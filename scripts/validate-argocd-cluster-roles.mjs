#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { parseAllDocuments, stringify } from "yaml";

const K3S_IMAGE =
  "rancher/k3s@sha256:f17e43023cce2b9c613e198f26e73637bf734b5156d37c9f44819d97bac4d655";
const CHART_VERSION = "10.2.1";
const CHART_DIGEST =
  "27e930e366d22c999002008ad5ec7961bda00410a84287210d0fffbee8150885";
const CHART_REPOSITORY = "https://argoproj.github.io/argo-helm";
const roles = ["platform", "execution"];
const runId = `argocd-role-${process.pid}-${randomBytes(4).toString("hex")}`;
const workingDirectory = mkdtempSync(path.join(tmpdir(), `${runId}-`));
const sourceDirectory = path.join(workingDirectory, "source");
const chart = path.join(workingDirectory, `argo-cd-${CHART_VERSION}.tgz`);
const clusters = new Map();
let gitDaemon;
let failure;
let cleaned = false;

for (const [signal, code] of [
  ["SIGINT", 130],
  ["SIGTERM", 143],
]) {
  process.once(signal, () => {
    cleanup();
    process.exit(code);
  });
}

try {
  validatePrerequisites();
  const revision = createDisposableRepository();
  const port = await availablePort();
  gitDaemon = spawn(
    "git",
    [
      "daemon",
      "--reuseaddr",
      "--export-all",
      `--base-path=${workingDirectory}`,
      "--listen=0.0.0",
      `--port=${port}`,
      workingDirectory,
    ],
    { stdio: "ignore" },
  );
  await new Promise((resolve) => setTimeout(resolve, 500));
  if (gitDaemon.exitCode !== null) {
    throw new Error("Disposable Git daemon did not start.");
  }

  pullChart();
  for (const role of roles) {
    clusters.set(role, startCluster(role));
  }
  const repository = `git://host.docker.internal:${port}/source`;

  for (const role of roles) {
    installArgocd(clusters.get(role));
    reconcileRole(clusters.get(role), role, repository, revision);
  }
  for (const role of roles) {
    assertRoleIsolation(clusters.get(role), role);
  }
} catch (error) {
  failure = error;
} finally {
  cleanup();
}

if (failure) {
  throw failure;
}

process.stdout.write(
  `Argo CD ${CHART_VERSION} reconciled isolated platform and execution resources across two disposable clusters.\n`,
);

function validatePrerequisites() {
  for (const [command, args] of [
    ["docker", ["version", "--format", "{{.Server.Version}}"]],
    ["git", ["--version"]],
    ["helm", ["version", "--short"]],
    ["kubectl", ["version", "--client", "-o", "json"]],
  ]) {
    run(command, args);
  }
  const context = run("docker", ["context", "show"]).stdout.trim();
  const endpoint = JSON.parse(
    run("docker", [
      "context",
      "inspect",
      context,
      "--format",
      "{{json .Endpoints.docker.Host}}",
    ]).stdout,
  );
  if (
    typeof endpoint !== "string" ||
    !endpoint.startsWith("unix://") ||
    (process.env.DOCKER_HOST && !process.env.DOCKER_HOST.startsWith("unix://"))
  ) {
    throw new Error("Qualification requires a local Unix Docker endpoint.");
  }
  const image = JSON.parse(
    run("docker", [
      "image",
      "inspect",
      K3S_IMAGE,
      "--format",
      "{{json .RepoDigests}}",
    ]).stdout,
  );
  if (!image.includes(K3S_IMAGE)) {
    throw new Error("Local K3s image does not match the reviewed digest.");
  }
}

function createDisposableRepository() {
  for (const role of roles) {
    const directory = path.join(
      sourceDirectory,
      "gitops",
      "overlays",
      "dev",
      role,
    );
    mkdirSync(directory, { recursive: true });
    writeFileSync(
      path.join(directory, "kustomization.yaml"),
      stringify({
        apiVersion: "kustomize.config.k8s.io/v1beta1",
        kind: "Kustomization",
        resources: ["role-proof.configmap.yaml"],
      }),
    );
    writeFileSync(
      path.join(directory, "role-proof.configmap.yaml"),
      stringify({
        apiVersion: "v1",
        kind: "ConfigMap",
        metadata: { name: "role-proof", namespace: role },
        data: { role },
      }),
    );
  }
  run("git", ["init", "-q"], undefined, sourceDirectory);
  run("git", ["add", "."], undefined, sourceDirectory);
  run(
    "git",
    [
      "-c",
      "user.name=Argo CD qualification",
      "-c",
      "user.email=argocd-qualification@example.invalid",
      "commit",
      "-qm",
      "role fixtures",
    ],
    undefined,
    sourceDirectory,
  );
  return run(
    "git",
    ["rev-parse", "HEAD"],
    undefined,
    sourceDirectory,
  ).stdout.trim();
}

function pullChart() {
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
}

function startCluster(role) {
  const name = `${runId}-${role}`;
  const kubeconfig = path.join(workingDirectory, `${role}.kubeconfig`);
  run("docker", [
    "run",
    "-d",
    "--privileged",
    "--name",
    name,
    "--label",
    "security.deus.dev/owner=argocd-role-qualification",
    "--tmpfs",
    "/run",
    "--tmpfs",
    "/var/run",
    "-p",
    "127.0.0.1::6443",
    K3S_IMAGE,
    "server",
    "--disable",
    "traefik",
    "--disable",
    "servicelb",
    "--disable",
    "metrics-server",
    "--write-kubeconfig-mode=644",
  ]);
  poll(`${role} K3s API`, 120, () => {
    const result = runOptional("docker", [
      "exec",
      name,
      "kubectl",
      "--kubeconfig",
      "/etc/rancher/k3s/k3s.yaml",
      "get",
      "nodes",
      "-o",
      "name",
    ]);
    return result.status === 0 && result.stdout.trim().length > 0;
  });
  run("docker", ["cp", `${name}:/etc/rancher/k3s/k3s.yaml`, kubeconfig]);
  const port = run("docker", ["port", name, "6443/tcp"])
    .stdout.trim()
    .match(/:(\d+)$/)?.[1];
  if (!port) throw new Error(`Cannot resolve ${role} K3s API port.`);
  writeFileSync(
    kubeconfig,
    readFileSync(kubeconfig, "utf8").replace(
      "https://127.0.0.1:6443",
      `https://127.0.0.1:${port}`,
    ),
    { mode: 0o600 },
  );
  kubectl({ kubeconfig }, [
    "wait",
    "--for=condition=Ready",
    "node",
    "--all",
    "--timeout=120s",
  ]);
  return { name, kubeconfig };
}

function installArgocd(cluster) {
  const values = path.join(workingDirectory, "argocd-values.yaml");
  if (!existsSync(values)) {
    writeFileSync(
      values,
      stringify({
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
                resources: [
                  "configmaps",
                  "endpoints",
                  "events",
                  "limitranges",
                  "namespaces",
                  "persistentvolumeclaims",
                  "resourcequotas",
                  "secrets",
                  "serviceaccounts",
                  "services",
                ],
                verbs: [
                  "get",
                  "list",
                  "watch",
                  "create",
                  "update",
                  "patch",
                  "delete",
                ],
              },
              {
                apiGroups: [
                  "admissionregistration.k8s.io",
                  "apiextensions.k8s.io",
                  "apiregistration.k8s.io",
                  "apps",
                  "argoproj.io",
                  "autoscaling",
                  "batch",
                  "gateway.networking.k8s.io",
                  "monitoring.coreos.com",
                  "networking.k8s.io",
                  "node.k8s.io",
                  "policy",
                  "rbac.authorization.k8s.io",
                  "security.istio.io",
                  "tailscale.com",
                  "telemetry.istio.io",
                ],
                resources: [
                  "applications",
                  "applicationsets",
                  "appprojects",
                  "authorizationpolicies",
                  "clusterroles",
                  "clusterrolebindings",
                  "cronjobs",
                  "customresourcedefinitions",
                  "daemonsets",
                  "deployments",
                  "gateways",
                  "horizontalpodautoscalers",
                  "httproutes",
                  "jobs",
                  "mutatingwebhookconfigurations",
                  "networkpolicies",
                  "peerauthentications",
                  "poddisruptionbudgets",
                  "podmonitors",
                  "prometheusrules",
                  "roles",
                  "rolebindings",
                  "runtimeclasses",
                  "servicemonitors",
                  "statefulsets",
                  "telemetries",
                  "validatingwebhookconfigurations",
                ],
                verbs: [
                  "get",
                  "list",
                  "watch",
                  "create",
                  "update",
                  "patch",
                  "delete",
                ],
              },
              {
                apiGroups: ["authorization.k8s.io"],
                resources: ["selfsubjectaccessreviews"],
                verbs: ["create"],
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
        applicationSet: { enabled: false },
        notifications: { enabled: false },
        dex: { enabled: false },
      }),
      { mode: 0o600 },
    );
  }
  run("helm", [
    "--kubeconfig",
    cluster.kubeconfig,
    "install",
    "argocd",
    chart,
    "--namespace",
    "argocd",
    "--create-namespace",
    "--values",
    values,
    "--wait",
    "--timeout",
    "8m",
  ]);
}

function reconcileRole(cluster, role, repository, revision) {
  const rendered = parseAllDocuments(
    run("kubectl", [
      "kustomize",
      `gitops/bootstrap/argocd/overlays/dev/${role}`,
    ]).stdout,
  )
    .map((document) => document.toJSON())
    .filter(Boolean);
  const baselines = rendered.filter(
    (document) =>
      document.kind === "Application" &&
      /-cluster-baseline$/.test(document.metadata?.name ?? ""),
  );
  if (
    baselines.length !== 1 ||
    baselines[0].metadata.name !== `${role}-cluster-baseline`
  ) {
    throw new Error(`${role} entrypoint did not select exactly one role.`);
  }
  const application = structuredClone(baselines[0]);
  application.spec.source.repoURL = repository;
  application.spec.source.targetRevision = revision;
  const project = {
    apiVersion: "argoproj.io/v1alpha1",
    kind: "AppProject",
    metadata: { name: "bootstrap", namespace: "argocd" },
    spec: {
      sourceRepos: [repository],
      destinations: [
        { server: "https://kubernetes.default.svc", namespace: role },
      ],
      clusterResourceWhitelist: [{ group: "", kind: "Namespace" }],
      namespaceResourceWhitelist: [{ group: "", kind: "ConfigMap" }],
    },
  };
  kubectl(
    cluster,
    ["apply", "-f", "-"],
    `${stringify(project)}---\n${stringify(application)}`,
  );
  poll(`${role} Argo reconciliation`, 300, () => {
    const result = kubectlOptional(cluster, [
      "get",
      "application",
      `${role}-cluster-baseline`,
      "-n",
      "argocd",
      "-o",
      "json",
    ]);
    if (result.status !== 0) return false;
    const status = JSON.parse(result.stdout).status ?? {};
    return (
      status.sync?.status === "Synced" && status.health?.status === "Healthy"
    );
  });
}

function assertRoleIsolation(cluster, role) {
  const marker = JSON.parse(
    kubectl(cluster, [
      "get",
      "configmap",
      "role-proof",
      "-n",
      role,
      "-o",
      "json",
    ]).stdout,
  );
  if (marker.data?.role !== role) {
    throw new Error(`${role} cluster reconciled the wrong role marker.`);
  }
  const otherRole = opposite(role);
  const forbiddenMarker = kubectl(cluster, [
    "get",
    "configmap",
    "role-proof",
    "-n",
    otherRole,
    "--ignore-not-found",
    "-o",
    "name",
  ]).stdout.trim();
  const forbiddenApplication = kubectl(cluster, [
    "get",
    "application",
    `${otherRole}-cluster-baseline`,
    "-n",
    "argocd",
    "--ignore-not-found",
    "-o",
    "name",
  ]).stdout.trim();
  if (forbiddenMarker || forbiddenApplication) {
    throw new Error(`${otherRole} ownership crossed into the ${role} cluster.`);
  }
}

function kubectl(cluster, args, input) {
  return run("kubectl", ["--kubeconfig", cluster.kubeconfig, ...args], input);
}

function kubectlOptional(cluster, args, input) {
  return runOptional(
    "kubectl",
    ["--kubeconfig", cluster.kubeconfig, ...args],
    input,
  );
}

function poll(label, attempts, predicate) {
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    if (predicate()) return;
    if (attempt < attempts) run("sleep", ["1"]);
  }
  throw new Error(`${label} did not become ready.`);
}

function run(command, args, input, cwd = process.cwd()) {
  const result = runOptional(command, args, input, cwd);
  if (result.error || result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed: ${result.error?.message ?? `${result.stdout}\n${result.stderr}`}`,
    );
  }
  return result;
}

function runOptional(command, args, input, cwd = process.cwd()) {
  return spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    input,
    stdio: ["pipe", "pipe", "pipe"],
    maxBuffer: 32 * 1024 * 1024,
  });
}

function sha256(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function opposite(role) {
  return role === "platform" ? "execution" : "platform";
}

function cleanup() {
  if (cleaned) return;
  cleaned = true;
  gitDaemon?.kill("SIGTERM");
  for (const role of roles) {
    runOptional("docker", ["rm", "-f", `${runId}-${role}`]);
  }
  rmSync(workingDirectory, { recursive: true, force: true });
}

async function availablePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "0.0.0.0", resolve);
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  if (!port) throw new Error("Cannot allocate a disposable Git port.");
  return port;
}
