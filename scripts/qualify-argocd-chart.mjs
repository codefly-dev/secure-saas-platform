#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { parseAllDocuments, stringify } from "yaml";

const CHART_VERSION = "10.2.1";
const CHART_DIGEST =
  "27e930e366d22c999002008ad5ec7961bda00410a84287210d0fffbee8150885";
const CHART_REPOSITORY = "https://argoproj.github.io/argo-helm";
const workingDirectory = mkdtempSync(
  path.join(tmpdir(), "argocd-chart-qualification-"),
);

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

  for (const profile of [
    {
      name: "argocd",
      namespace: "argocd",
      values: {
        fullnameOverride: "argocd",
        crds: { install: true },
        configs: {
          params: {
            "server.insecure": false,
            "server.repo.server.timeout.seconds": 180,
          },
          cm: {
            "admin.enabled": false,
            "exec.enabled": false,
            "resource.respectRBAC": "strict",
            "users.anonymous.enabled": false,
          },
        },
        controller: {
          replicas: 1,
          clusterRoleRules: {
            enabled: true,
            rules: [
              {
                apiGroups: [""],
                resources: ["configmaps", "namespaces"],
                verbs: ["get", "list", "watch"],
              },
            ],
          },
        },
        server: {
          replicas: 1,
          service: { type: "ClusterIP" },
          extraArgs: ["--insecure=false"],
        },
        repoServer: { replicas: 1 },
        applicationSet: { replicas: 1 },
        notifications: { enabled: false },
        dex: { enabled: false },
      },
    },
    {
      name: "argocd-database",
      namespace: "argocd-database",
      values: {
        fullnameOverride: "argocd-database",
        crds: { install: false },
        configs: {
          cm: {
            "admin.enabled": false,
            "exec.enabled": false,
            "resource.respectRBAC": "strict",
            "users.anonymous.enabled": false,
          },
        },
        controller: {
          replicas: 1,
          serviceAccount: {
            create: true,
            name: "database-infrastructure-application-controller",
          },
        },
        server: { replicas: 1, service: { type: "ClusterIP" } },
        repoServer: { replicas: 1 },
        applicationSet: { enabled: false },
        notifications: { enabled: false },
        dex: { enabled: false },
      },
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
