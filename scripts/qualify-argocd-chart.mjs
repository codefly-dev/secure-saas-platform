#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { parseAllDocuments, stringify } from "yaml";
import { loadArgocdValues } from "./load-argocd-values.mjs";

const workingDirectory = mkdtempSync(
  path.join(tmpdir(), "argocd-chart-qualification-"),
);
const {
  ARGOCD_CHART_DIGEST: CHART_DIGEST,
  ARGOCD_CHART_REPOSITORY: CHART_REPOSITORY,
  ARGOCD_CHART_VERSION: CHART_VERSION,
  argocdHelmValues,
  databaseArgocdHelmValues,
} = loadArgocdValues(workingDirectory);

try {
  const chart = path.join(workingDirectory, `argo-cd-${CHART_VERSION}.tgz`);
  run("helm", [
    "pull",
    "argo-cd",
    "--repo",
    CHART_REPOSITORY,
    "--version",
    CHART_VERSION,
    "--destination",
    workingDirectory,
  ]);
  if (sha256(chart) !== CHART_DIGEST) {
    throw new Error("Argo CD chart digest does not match the reviewed pin.");
  }

  const controllerConfig = (clusterRole) => ({
    clusterRole,
    argocdHostname: `argocd-${clusterRole}.qualification.invalid`,
    oidcIssuer: "https://identity.qualification.invalid",
    oidcClientId: `argocd-${clusterRole}`,
    oidcClientSecretRef: "$oidc.organization.clientSecret",
    oidcAdminGroup: "deus:infra:admins",
  });
  for (const profile of [
    ...["platform", "execution"].map((clusterRole) => ({
      name: `argocd-${clusterRole}`,
      namespace: "argocd",
      values: argocdHelmValues(controllerConfig(clusterRole)),
      clusterRole,
    })),
    {
      name: "argocd-database",
      namespace: "argocd-database",
      values: databaseArgocdHelmValues(),
    },
  ]) {
    const valuesPath = path.join(workingDirectory, `${profile.name}.yaml`);
    writeFileSync(valuesPath, stringify(profile.values), { mode: 0o600 });
    run("helm", [
      "lint",
      chart,
      "--namespace",
      profile.namespace,
      "--values",
      valuesPath,
    ]);
    const rendered = run("helm", [
      "template",
      profile.name,
      chart,
      "--namespace",
      profile.namespace,
      "--kube-version",
      "1.33.9",
      "--values",
      valuesPath,
    ]).stdout;
    const documents = parseAllDocuments(rendered)
      .map((document) => {
        if (document.errors.length > 0) {
          throw new Error(document.errors.join(", "));
        }
        return document.toJSON();
      })
      .filter(Boolean);
    if (
      !documents.some(
        (document) =>
          document.kind === "Deployment" || document.kind === "StatefulSet",
      ) ||
      !documents.some(
        (document) =>
          document.kind === "Service" && document.spec?.type === "ClusterIP",
      )
    ) {
      throw new Error(`${profile.name} rendered an incomplete chart.`);
    }
    if (
      documents.some((document) => document.kind === "ServiceMonitor") ||
      profile.values.configs.cm["resource.respectRBAC"] !== "strict"
    ) {
      throw new Error(
        `${profile.name} is not installable before monitoring CRDs or does not enforce strict resource RBAC.`,
      );
    }
    if (profile.clusterRole) {
      const rules = profile.values.controller.clusterRoleRules.rules;
      const serializedRules = JSON.stringify(rules);
      if (
        !serializedRules.includes("validatingadmissionpolicies") ||
        !serializedRules.includes("clusterpolicies") ||
        (profile.clusterRole === "platform") !==
          serializedRules.includes("connectors")
      ) {
        throw new Error(
          `${profile.name} does not carry its production role-specific controller rules.`,
        );
      }
    } else {
      const serializedRules = JSON.stringify(
        profile.values.controller.clusterRoleRules.rules,
      );
      if (
        !serializedRules.includes("applicationnetworkpolicies") ||
        serializedRules.includes('"delete"')
      ) {
        throw new Error(
          "argocd-database does not carry its production infrastructure controller rules.",
        );
      }
    }
  }

  process.stdout.write(
    `Argo CD chart ${CHART_VERSION} qualified at ${CHART_DIGEST}.\n`,
  );
} finally {
  rmSync(workingDirectory, { recursive: true, force: true });
}

function sha256(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function run(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed: ${result.error?.message ?? `${result.stdout}\n${result.stderr}`}`,
    );
  }
  return result;
}
