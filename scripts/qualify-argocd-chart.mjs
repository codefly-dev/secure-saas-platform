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
  qualifyMonitoringIntegration(controllerConfig);

  process.stdout.write(
    `Argo CD chart ${CHART_VERSION} qualified at ${CHART_DIGEST}.\n`,
  );
} finally {
  rmSync(workingDirectory, { recursive: true, force: true });
}

function sha256(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function qualifyMonitoringIntegration(controllerConfig) {
  const application = parseAllDocuments(
    readFileSync(
      "gitops/bootstrap/argocd/base/apps/kube-prometheus-stack.application.yaml",
      "utf8",
    ),
  )[0].toJSON();
  const source = application.spec.source;
  const monitoringChart = path.join(
    workingDirectory,
    `${source.chart}-${source.targetRevision}.tgz`,
  );
  const monitoringValues = path.join(
    workingDirectory,
    "kube-prometheus-stack-values.yaml",
  );
  writeFileSync(monitoringValues, stringify(source.helm.valuesObject), {
    mode: 0o600,
  });
  run("helm", [
    "pull",
    source.chart,
    "--repo",
    source.repoURL,
    "--version",
    source.targetRevision,
    "--destination",
    workingDirectory,
  ]);
  const rendered = run("helm", [
    "template",
    "kube-prometheus-stack",
    monitoringChart,
    "--namespace",
    application.spec.destination.namespace,
    "--kube-version",
    "1.33.9",
    "--values",
    monitoringValues,
  ]).stdout;
  const resources = parseAllDocuments(rendered)
    .map((document) => document.toJSON())
    .filter(Boolean)
    .flatMap((document) =>
      document.kind === "List" ? document.items : [document],
    );
  const resourceNames = new Map([
    ["Alertmanager", "alertmanagers"],
    ["PodMonitor", "podmonitors"],
    ["Prometheus", "prometheuses"],
    ["PrometheusRule", "prometheusrules"],
    ["ServiceMonitor", "servicemonitors"],
  ]);
  const renderedMonitoringKinds = [
    ...new Set(
      resources
        .filter((resource) =>
          String(resource.apiVersion).startsWith("monitoring.coreos.com/"),
        )
        .map((resource) => resource.kind),
    ),
  ].sort();
  const expectedMonitoringKinds = [
    "Alertmanager",
    "Prometheus",
    "PrometheusRule",
    "ServiceMonitor",
  ];
  if (
    JSON.stringify(renderedMonitoringKinds) !==
    JSON.stringify(expectedMonitoringKinds)
  ) {
    throw new Error(
      "The pinned monitoring chart rendered an unexpected monitoring resource inventory.",
    );
  }
  const project = parseAllDocuments(
    run("kubectl", [
      "kustomize",
      "gitops/bootstrap/argocd/overlays/dev/platform",
    ]).stdout,
  )
    .map((document) => document.toJSON())
    .find(
      (document) =>
        document.kind === "AppProject" &&
        document.metadata?.name === "platform-operators",
    );
  const allowedKinds = new Set(
    project.spec.namespaceResourceWhitelist.map(
      (resource) => `${resource.group}/${resource.kind}`,
    ),
  );
  for (const kind of renderedMonitoringKinds) {
    if (!allowedKinds.has(`monitoring.coreos.com/${kind}`)) {
      throw new Error(
        `platform-operators cannot reconcile monitoring.coreos.com/${kind}.`,
      );
    }
  }
  for (const clusterRole of ["platform", "execution"]) {
    const rules = argocdHelmValues(controllerConfig(clusterRole)).controller
      .clusterRoleRules.rules;
    for (const kind of renderedMonitoringKinds) {
      if (
        !rules.some(
          (rule) =>
            rule.apiGroups.includes("monitoring.coreos.com") &&
            rule.resources.includes(resourceNames.get(kind)),
        )
      ) {
        throw new Error(
          `${clusterRole} Argo CD cannot reconcile monitoring.coreos.com/${kind}.`,
        );
      }
    }
  }
  const argocdMonitors = resources
    .filter(
      (resource) =>
        resource.kind === "ServiceMonitor" &&
        resource.metadata?.name?.startsWith("argocd-"),
    )
    .map((resource) => resource.metadata.name)
    .sort();
  if (
    JSON.stringify(argocdMonitors) !==
    JSON.stringify([
      "argocd-application-controller",
      "argocd-applicationset-controller",
      "argocd-repo-server",
      "argocd-server",
    ])
  ) {
    throw new Error(
      "The monitoring stack does not render the exact Argo CD ServiceMonitor inventory.",
    );
  }
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
