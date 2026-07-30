#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { parseAllDocuments, stringify } from "yaml";
import { loadArgocdValues } from "./load-argocd-values.mjs";
import {
  assertKubeconfigBinding,
  sha256,
  verifyPlatformHandoff,
} from "./platform-handoff.mjs";

const args = parseArguments(process.argv.slice(2));
const handoff = verifyPlatformHandoff(args.handoff, args.publicKey);
const spec = handoff.spec;
if (spec.gitops.revision !== args.revision) {
  throw new Error(
    `Requested revision ${args.revision} does not match signed handoff revision ${spec.gitops.revision}.`,
  );
}
const workingDirectory = mkdtempSync(
  path.join(tmpdir(), "platform-argocd-activation-"),
);
const chartValues = loadArgocdValues(workingDirectory);
const chartArchive = path.join(
  workingDirectory,
  `argo-cd-${chartValues.ARGOCD_CHART_VERSION}.tgz`,
);
const mainValuesPath = path.join(workingDirectory, "argocd-values.yaml");
const databaseValuesPath = path.join(
  workingDirectory,
  "argocd-database-values.yaml",
);

try {
  const mainValues = chartValues.argocdHelmValues({
    clusterRole: spec.cluster.role,
    argocdHostname: required("--hostname", args.hostname),
    oidcIssuer: required("--oidc-issuer", args.oidcIssuer),
    oidcClientId: required("--oidc-client-id", args.oidcClientId),
    oidcClientSecretRef: required(
      "--oidc-client-secret-ref",
      args.oidcClientSecretRef,
    ),
    oidcAdminGroup: required("--oidc-admin-group", args.oidcAdminGroup),
  });
  writeFileSync(mainValuesPath, stringify(mainValues), { mode: 0o600 });
  if (spec.cluster.role === "platform") {
    writeFileSync(
      databaseValuesPath,
      stringify(chartValues.databaseArgocdHelmValues()),
      { mode: 0o600 },
    );
  }
  const plan = activationPlan(
    spec,
    args.kubeconfig,
    mainValuesPath,
    databaseValuesPath,
  );
  if (!args.execute) {
    process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
    process.exit(0);
  }

  assertCheckout(spec.gitops.revision);
  assertKubeconfig(spec, args.kubeconfig);
  run("helm", [
    "pull",
    "argo-cd",
    "--repo",
    chartValues.ARGOCD_CHART_REPOSITORY,
    "--version",
    chartValues.ARGOCD_CHART_VERSION,
    "--destination",
    workingDirectory,
  ]);
  if (sha256(readFileSync(chartArchive)) !== chartValues.ARGOCD_CHART_DIGEST) {
    throw new Error("Pinned Argo CD chart digest verification failed.");
  }
  for (const command of plan.helm) run(command.command, command.arguments);
  const rendered = run("kubectl", [
    "--kubeconfig",
    args.kubeconfig,
    "kustomize",
    spec.gitops.bootstrapEntrypoint,
  ]).stdout;
  const documents = parseAllDocuments(rendered)
    .map((document) => {
      if (document.errors.length > 0) {
        throw new Error(document.errors.join(", "));
      }
      return document.toJSON();
    })
    .filter(Boolean);
  bindGitSources(documents, spec.gitops.repository, spec.gitops.revision);
  run(
    "kubectl",
    ["--kubeconfig", args.kubeconfig, "apply", "-f", "-"],
    documents.map((document) => stringify(document)).join("---\n"),
  );
  process.stdout.write(
    `Activated Argo CD for ${spec.cluster.name}; reconciliation is owned by ${spec.gitops.repository}@${spec.gitops.revision}.\n`,
  );
} finally {
  rmSync(workingDirectory, { recursive: true, force: true });
}

function activationPlan(specification, kubeconfig, mainValues, databaseValues) {
  const helm = [
    {
      command: "helm",
      arguments: [
        "--kubeconfig",
        kubeconfig,
        "upgrade",
        "--install",
        "argocd",
        chartArchive,
        "--namespace",
        "argocd",
        "--create-namespace",
        "--values",
        mainValues,
        "--wait",
        "--timeout",
        "8m",
      ],
    },
  ];
  if (specification.cluster.role === "platform") {
    helm.push({
      command: "helm",
      arguments: [
        "--kubeconfig",
        kubeconfig,
        "upgrade",
        "--install",
        "argocd-database",
        chartArchive,
        "--namespace",
        "argocd-database",
        "--create-namespace",
        "--values",
        databaseValues,
        "--wait",
        "--timeout",
        "8m",
      ],
    });
  }
  return {
    cluster: specification.cluster.name,
    role: specification.cluster.role,
    handoffDigest: handoff.specDigest,
    helm,
    gitHandoff: {
      command: "kubectl",
      arguments: ["--kubeconfig", kubeconfig, "apply", "-f", "-"],
      repository: specification.gitops.repository,
      revision: specification.gitops.revision,
      entrypoint: specification.gitops.bootstrapEntrypoint,
    },
  };
}

function bindGitSources(documents, repository, revision) {
  const applications = documents.filter(
    (document) => document.kind === "Application",
  );
  for (const application of applications) {
    if (
      application.spec?.source?.repoURL ===
        "https://github.com/codefly-dev/secure-saas-platform.git" ||
      /^gitops\//.test(application.spec?.source?.path ?? "")
    ) {
      application.spec.source.repoURL = repository;
      application.spec.source.targetRevision = revision;
    }
  }
  for (const project of documents.filter(
    (document) => document.kind === "AppProject",
  )) {
    project.spec.sourceRepos = project.spec.sourceRepos.map((source) =>
      source === "https://github.com/codefly-dev/secure-saas-platform.git"
        ? repository
        : source,
    );
  }
}

function assertCheckout(revision) {
  const expected = run("git", [
    "rev-parse",
    "--verify",
    `${revision}^{commit}`,
  ]).stdout.trim();
  const actual = run("git", ["rev-parse", "HEAD"]).stdout.trim();
  if (expected !== actual) {
    throw new Error(
      `Activation checkout ${actual} does not match reviewed revision ${revision}.`,
    );
  }
}

function assertKubeconfig(specification, kubeconfig) {
  const config = JSON.parse(
    run("kubectl", [
      "--kubeconfig",
      kubeconfig,
      "config",
      "view",
      "--raw",
      "--minify",
      "-o",
      "json",
    ]).stdout,
  );
  assertKubeconfigBinding(specification, config);
}

function run(command, commandArguments, input) {
  const result = spawnSync(command, commandArguments, {
    cwd: process.cwd(),
    encoding: "utf8",
    input,
    stdio: ["pipe", "pipe", "pipe"],
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `${command} ${commandArguments.join(" ")} failed: ${
        result.error?.message ?? `${result.stdout}\n${result.stderr}`
      }`,
    );
  }
  return result;
}

function required(flag, value) {
  if (!value) throw new Error(`${flag} is required.`);
  return value;
}

function parseArguments(values) {
  const parsed = { execute: false };
  const keys = new Map([
    ["--handoff", "handoff"],
    ["--public-key", "publicKey"],
    ["--kubeconfig", "kubeconfig"],
    ["--revision", "revision"],
    ["--hostname", "hostname"],
    ["--oidc-issuer", "oidcIssuer"],
    ["--oidc-client-id", "oidcClientId"],
    ["--oidc-client-secret-ref", "oidcClientSecretRef"],
    ["--oidc-admin-group", "oidcAdminGroup"],
  ]);
  for (let index = 0; index < values.length; index += 1) {
    if (values[index] === "--execute") {
      if (parsed.execute) usage();
      parsed.execute = true;
      continue;
    }
    const key = keys.get(values[index]);
    const value = values[index + 1];
    if (!key || !value || parsed[key]) usage();
    parsed[key] = value;
    index += 1;
  }
  for (const key of keys.values()) required(`--${key}`, parsed[key]);
  return parsed;
}

function usage() {
  process.stderr.write(
    "Usage: npm run activate -- --handoff <file> --public-key <file> --kubeconfig <file> --revision <sha-or-tag> --hostname <name> --oidc-issuer <url> --oidc-client-id <id> --oidc-client-secret-ref <reference> --oidc-admin-group <group> [--execute]\n",
  );
  process.exit(2);
}
