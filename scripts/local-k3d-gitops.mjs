#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { createServer } from "node:net";
import { stringify } from "yaml";
import { loadArgocdValues } from "./load-argocd-values.mjs";

const repositoryRoot = realpathSync(
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."),
);
const command = process.argv[2] ?? "help";
const clusterName = option("--cluster") ?? "codefly-local";
const waitTimeout = option("--timeout") ?? "8m";
const contextName = `k3d-${clusterName}`;
const stateRoot = path.join(repositoryRoot, ".local", "k3d");
const stateDirectory = path.join(stateRoot, clusterName);
const ownerMarkerPath = path.join(stateDirectory, "owner.json");
const kubeconfigPath = path.join(stateDirectory, "kubeconfig.yaml");
const gitContainerName = `codefly-${clusterName}-git`;
const expectedRegistryName = `k3d-${clusterName}-registry`;
const gitRepositoryUrl =
  "http://codefly-local-git.argocd.svc.cluster.local/gitops.git";
const k3sImage =
  "rancher/k3s@sha256:f17e43023cce2b9c613e198f26e73637bf734b5156d37c9f44819d97bac4d655";
const gitServerImage =
  "nginx@sha256:1eff5a5f3fcf8431a0abb7eddf5471fec24e5e1905a2581aeacdb07a4479b92b";
const ownerLabel = "codefly.local-gitops.owner";
const ownerValue = "secure-saas-platform";
const childEnvironment = sanitizedEnvironment();

try {
  assertArguments(process.argv.slice(3));
  assertClusterName(clusterName);
  assertTimeout(waitTimeout);
  assertWithin(stateRoot, stateDirectory);
  switch (command) {
    case "up":
      await up();
      break;
    case "down":
      down();
      break;
    case "status":
      status();
      break;
    case "doctor":
      doctor();
      break;
    case "render":
      render();
      break;
    case "help":
    case "--help":
    case "-h":
      help();
      break;
    default:
      throw new Error(`unknown command '${command}'`);
  }
} catch (error) {
  process.stderr.write(`local-k3d-gitops: ${error.message}\n`);
  if (command === "up") {
    process.stderr.write(
      `State was preserved for diagnosis. Clean owned resources with './scripts/local-k3d-down --cluster ${clusterName}'.\n`,
    );
  }
  process.exit(1);
}

async function up() {
  requireTools();
  assertLocalDocker();
  render();
  if (clusterRecord()) {
    throw new Error(
      `cluster '${clusterName}' already exists; use status or down first`,
    );
  }
  if (containerExists(gitContainerName)) {
    throw new Error(
      `Git container '${gitContainerName}' already exists; use down first`,
    );
  }
  if (existsSync(stateDirectory)) {
    throw new Error(
      `state directory '${relative(stateDirectory)}' already exists; use down first`,
    );
  }

  createOwnedState();
  const source = snapshotGitops();
  const chart = prepareChartAndValues();
  const apiPort = await availablePort();
  const registry = registryRecord();
  if (registry) assertReusableRegistry(registry, false);

  process.stdout.write(`Creating isolated k3d cluster '${clusterName}'...\n`);
  const clusterArguments = [
    "cluster",
    "create",
    clusterName,
    "--image",
    k3sImage,
    "--servers",
    "1",
    "--agents",
    "1",
    "--api-port",
    `127.0.0.1:${apiPort}`,
    "--wait",
    "--timeout",
    "4m",
    "--no-lb",
    "--kubeconfig-update-default=false",
    "--kubeconfig-switch-context=false",
    ...(registry ? ["--registry-use", registry.name] : []),
    "--runtime-label",
    `${ownerLabel}=${ownerValue}@server:*`,
    "--runtime-label",
    `${ownerLabel}=${ownerValue}@agent:*`,
    "--k3s-arg",
    "--disable=traefik@server:*",
    "--k3s-arg",
    "--disable=servicelb@server:*",
    "--k3s-arg",
    "--disable=metrics-server@server:*",
  ];
  run("k3d", clusterArguments);
  assertOwnedCluster(clusterRecord());
  if (registry) assertReusableRegistry(registryRecord(), true);
  const kubeconfig = capture("k3d", ["kubeconfig", "get", clusterName]);
  if (!/server:\s+https:\/\/127\.0\.0\.1:\d+/.test(kubeconfig)) {
    throw new Error("k3d API endpoint is not bound to loopback");
  }
  writeFileSync(kubeconfigPath, kubeconfig, { mode: 0o600 });
  chmodSync(kubeconfigPath, 0o600);

  process.stdout.write("Starting the isolated read-only Git remote...\n");
  run("docker", [
    "run",
    "--detach",
    "--name",
    gitContainerName,
    "--network",
    `k3d-${clusterName}`,
    "--label",
    `${ownerLabel}=${ownerValue}`,
    "--label",
    `codefly.local-gitops.cluster=${clusterName}`,
    "--mount",
    `type=bind,source=${source.bareRepository},target=/usr/share/nginx/html/gitops.git,readonly`,
    gitServerImage,
  ]);
  const gitServerAddress = capture("docker", [
    "inspect",
    "--format",
    `{{(index .NetworkSettings.Networks "k3d-${clusterName}").IPAddress}}`,
    gitContainerName,
  ]).trim();
  if (!isIpv4(gitServerAddress)) {
    throw new Error("could not resolve the disposable Git server address");
  }

  process.stdout.write(
    `Installing reviewed Argo CD chart ${chart.version} without public exposure...\n`,
  );
  run("helm", [
    "upgrade",
    "--install",
    "argocd",
    chart.path,
    "--namespace",
    "argocd",
    "--create-namespace",
    "--kubeconfig",
    kubeconfigPath,
    "--values",
    chart.values,
    "--wait",
    helmRollbackFlag(),
    "--timeout",
    waitTimeout,
  ]);

  apply(gitServiceManifest(gitServerAddress));
  runKubectl([
    "wait",
    "--for=condition=Established",
    "crd/applications.argoproj.io",
    `--timeout=${waitTimeout}`,
  ]);
  waitForGitRemote(source.snapshotRevision);

  const bootstrap = renderKustomize(
    path.join(repositoryRoot, "gitops/bootstrap/argocd/overlays/local"),
  );
  const occurrences = bootstrap.split("LOCAL_GIT_REVISION").length - 1;
  if (occurrences !== 1) {
    throw new Error(
      `local bootstrap must contain exactly one revision placeholder, found ${occurrences}`,
    );
  }
  apply(bootstrap.replace("LOCAL_GIT_REVISION", source.snapshotRevision));
  runKubectl([
    "annotate",
    "--namespace",
    "argocd",
    "application/codefly-local-baseline",
    "argocd.argoproj.io/refresh=hard",
    "--overwrite",
  ]);

  process.stdout.write("Waiting for exact Argo CD reconciliation...\n");
  for (const [field, value] of [
    [".status.sync.status", "Synced"],
    [".status.health.status", "Healthy"],
  ]) {
    runKubectl([
      "wait",
      "--namespace",
      "argocd",
      "application/codefly-local-baseline",
      `--for=jsonpath={${field}}=${value}`,
      `--timeout=${waitTimeout}`,
    ]);
  }
  const application = JSON.parse(
    captureKubectl([
      "get",
      "--namespace",
      "argocd",
      "application/codefly-local-baseline",
      "--output=json",
    ]),
  );
  if (application.status?.sync?.revision !== source.snapshotRevision) {
    throw new Error(
      "Argo CD reported a revision different from the local Git snapshot",
    );
  }
  const report = {
    apiVersion: "evidence.codefly.dev/local-k3d-gitops/v1",
    createdAt: new Date().toISOString(),
    scope: {
      mode: "single-combined-developer-cluster",
      excludes: [
        "aws-runtime",
        "microvm-runtime",
        "production-platform-execution-isolation",
        "production-tailscale-identity",
        "production-vault-storage",
      ],
    },
    cluster: {
      name: clusterName,
      context: contextName,
      apiExposure: "loopback-only",
      k3sImage,
      registry: registry
        ? {
            name: registry.name,
            hostEndpoint: registryHostEndpoint(registry),
            lifecycle: "preserved-external-resource",
          }
        : null,
    },
    git: {
      repositoryUrl: gitRepositoryUrl,
      gitServerImage,
      sourceHead: source.sourceHead,
      sourceDirty: source.sourceDirty,
      gitopsDirty: source.gitopsDirty,
      snapshotFileCount: source.snapshotFileCount,
      snapshotRevision: source.snapshotRevision,
    },
    argocd: {
      chartRepository: chart.repository,
      chartVersion: chart.version,
      chartDigest: chart.digest,
      valuesProfile: "production-platform-derived/local-sized",
      application: application.metadata?.name,
      sync: application.status?.sync?.status,
      health: application.status?.health?.status,
      reconciledRevision: application.status?.sync?.revision,
    },
  };
  writeFileSync(
    path.join(stateDirectory, "report.json"),
    `${JSON.stringify(report, null, 2)}\n`,
    { mode: 0o600 },
  );
  process.stdout.write(
    `Local GitOps is ready: ${application.status.sync.status}/${application.status.health.status} at ${source.snapshotRevision}.\n`,
  );
  process.stdout.write(
    `Kubeconfig: ${relative(kubeconfigPath)}\nEvidence: ${relative(path.join(stateDirectory, "report.json"))}\n`,
  );
}

function down() {
  requireCommand("docker");
  requireCommand("k3d");
  assertLocalDocker();
  const gitContainerPresent = containerExists(gitContainerName);
  const cluster = clusterRecord();
  const statePresent = existsSync(stateDirectory);
  const registry = registryRecord();
  const clusterNetwork = `k3d-${clusterName}`;
  const registryAttached =
    registry?.Networks?.includes(clusterNetwork) ?? false;
  if (gitContainerPresent) assertOwnedGitContainer();
  if (cluster) assertOwnedCluster(cluster);
  if (statePresent) assertOwnedState();
  if (registryAttached) assertReusableRegistry(registry, true);

  let removed = false;
  if (gitContainerPresent) {
    run("docker", ["rm", "--force", gitContainerName]);
    removed = true;
  }
  if (cluster && registryAttached) {
    run("docker", [
      "network",
      "disconnect",
      clusterNetwork,
      expectedRegistryName,
    ]);
  }
  if (cluster) {
    run("k3d", ["cluster", "delete", clusterName]);
    removed = true;
  }
  if (statePresent) {
    assertWithin(stateRoot, stateDirectory);
    rmSync(stateDirectory, { recursive: true, force: true });
    removed = true;
  }
  process.stdout.write(
    removed
      ? `Removed owned local cluster '${clusterName}', Git container, and ignored state; any validated registry was preserved.\n`
      : `No owned local GitOps resources exist for '${clusterName}'.\n`,
  );
}

function status() {
  requireCommand("k3d");
  const cluster = clusterRecord();
  if (!cluster) {
    process.stdout.write(`Local cluster '${clusterName}' does not exist.\n`);
    return;
  }
  assertOwnedCluster(cluster);
  assertOwnedState();
  const registry = registryRecord();
  if (registry) {
    assertReusableRegistry(registry, true);
    process.stdout.write(
      `Registry: ${registry.name} (${registryHostEndpoint(registry)}, preserved)\n`,
    );
  }
  runKubectl(["get", "nodes", "--output=wide"]);
  runKubectl([
    "get",
    "applications.argoproj.io",
    "--namespace",
    "argocd",
    "--output=wide",
  ]);
  const reportPath = path.join(stateDirectory, "report.json");
  if (existsSync(reportPath)) {
    process.stdout.write(`Evidence: ${relative(reportPath)}\n`);
  }
}

function doctor() {
  requireTools();
  assertLocalDocker();
  render();
  process.stdout.write(
    `Local k3d GitOps prerequisites and manifests are ready for '${clusterName}'.\n`,
  );
}

function render() {
  for (const directory of [
    "gitops/overlays/local",
    "gitops/bootstrap/argocd/overlays/local",
  ]) {
    const rendered = renderKustomize(path.join(repositoryRoot, directory));
    if (rendered.trim().length === 0) {
      throw new Error(`'${directory}' rendered an empty manifest`);
    }
  }
  process.stdout.write("Local workload and Argo CD overlays render.\n");
}

function createOwnedState() {
  for (const directory of [path.dirname(stateRoot), stateRoot]) {
    if (existsSync(directory)) {
      const stat = lstatSync(directory);
      if (!stat.isDirectory() || stat.isSymbolicLink()) {
        throw new Error(
          `local state parent '${relative(directory)}' is unsafe`,
        );
      }
    } else {
      mkdirSync(directory, { mode: 0o700 });
    }
  }
  mkdirSync(stateDirectory, { mode: 0o700 });
  writeFileSync(
    ownerMarkerPath,
    `${JSON.stringify(
      {
        apiVersion: "internal.codefly.dev/local-k3d-owner/v1",
        owner: ownerValue,
        cluster: clusterName,
      },
      null,
      2,
    )}\n`,
    { mode: 0o600 },
  );
}

function assertOwnedState() {
  const stat = lstatSync(stateDirectory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`refusing unsafe state path '${relative(stateDirectory)}'`);
  }
  let marker;
  try {
    marker = JSON.parse(readFileSync(ownerMarkerPath, "utf8"));
  } catch {
    throw new Error("refusing state without a valid ownership marker");
  }
  if (
    marker.apiVersion !== "internal.codefly.dev/local-k3d-owner/v1" ||
    marker.owner !== ownerValue ||
    marker.cluster !== clusterName
  ) {
    throw new Error("refusing state with a different ownership marker");
  }
}

function snapshotGitops() {
  const sourceHead = capture("git", [
    "-C",
    repositoryRoot,
    "rev-parse",
    "HEAD",
  ]).trim();
  if (!/^[a-f0-9]{40}$/.test(sourceHead)) {
    throw new Error("Git did not return a full source revision");
  }
  const sourceStatus = capture("git", [
    "-C",
    repositoryRoot,
    "status",
    "--porcelain",
    "--untracked-files=all",
  ]).trim();
  const gitopsStatus = capture("git", [
    "-C",
    repositoryRoot,
    "status",
    "--porcelain",
    "--untracked-files=all",
    "--",
    "gitops",
  ]).trim();
  const snapshotDirectory = path.join(stateDirectory, "snapshot");
  const sourceDirectory = path.join(snapshotDirectory, "source");
  const bareRepository = path.join(snapshotDirectory, "gitops.git");
  mkdirSync(sourceDirectory, { recursive: true, mode: 0o700 });
  const snapshotFiles = capture("git", [
    "-C",
    repositoryRoot,
    "ls-files",
    "--cached",
    "--others",
    "--exclude-standard",
    "-z",
    "--",
    "gitops",
  ])
    .split("\0")
    .filter(Boolean);
  if (snapshotFiles.length === 0) {
    throw new Error("the GitOps snapshot inventory is empty");
  }
  for (const entry of snapshotFiles) {
    if (
      path.isAbsolute(entry) ||
      !entry.startsWith("gitops/") ||
      entry.split("/").includes("..")
    ) {
      throw new Error(`unsafe GitOps snapshot path '${entry}'`);
    }
    const source = path.resolve(repositoryRoot, entry);
    const destination = path.resolve(sourceDirectory, entry);
    assertWithin(repositoryRoot, source);
    assertWithin(sourceDirectory, destination);
    const stat = lstatSync(source);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error(
        `GitOps snapshot entry '${entry}' must be a regular non-symlink file`,
      );
    }
    mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
    cpSync(source, destination, {
      dereference: false,
      errorOnExist: true,
    });
  }
  run("git", ["init", "--initial-branch=local", sourceDirectory]);
  run("git", ["-C", sourceDirectory, "add", "--", "gitops"]);
  run(
    "git",
    [
      "-C",
      sourceDirectory,
      "-c",
      "user.name=Codefly Local GitOps",
      "-c",
      "user.email=local-gitops@invalid",
      "-c",
      "commit.gpgsign=false",
      "commit",
      "--message",
      `Local GitOps snapshot from ${sourceHead}`,
    ],
    { quiet: true },
  );
  const snapshotRevision = capture("git", [
    "-C",
    sourceDirectory,
    "rev-parse",
    "HEAD",
  ]).trim();
  run("git", ["clone", "--bare", sourceDirectory, bareRepository], {
    quiet: true,
  });
  run("git", ["-C", bareRepository, "update-server-info"]);
  return {
    bareRepository,
    sourceHead,
    sourceDirty: sourceStatus.length > 0,
    gitopsDirty: gitopsStatus.length > 0,
    snapshotFileCount: snapshotFiles.length,
    snapshotRevision,
  };
}

function prepareChartAndValues() {
  const {
    ARGOCD_CHART_DIGEST: digest,
    ARGOCD_CHART_REPOSITORY: repository,
    ARGOCD_CHART_VERSION: version,
    argocdHelmValues,
  } = loadArgocdValues(stateDirectory);
  run("helm", [
    "pull",
    "argo-cd",
    "--repo",
    repository,
    "--version",
    version,
    "--destination",
    stateDirectory,
  ]);
  const chartPath = path.join(stateDirectory, `argo-cd-${version}.tgz`);
  if (sha256(chartPath) !== digest) {
    throw new Error("Argo CD chart digest does not match the reviewed pin");
  }
  const values = argocdHelmValues({
    clusterRole: "platform",
    argocdHostname: "argocd.local.invalid",
    oidcIssuer: "https://identity.local.invalid",
    oidcClientId: "argocd-local",
    oidcClientSecretRef: "$oidc.organization.clientSecret",
    oidcAdminGroup: "deus:local:admins",
  });
  values.controller.replicas = 1;
  values.controller.resources = {
    requests: { cpu: "100m", memory: "256Mi" },
    limits: { cpu: "1", memory: "1Gi" },
  };
  values.server.replicas = 1;
  values.repoServer.replicas = 1;
  values.applicationSet = { enabled: false };
  const valuesPath = path.join(stateDirectory, "argocd-local-values.yaml");
  writeFileSync(valuesPath, stringify(values), { mode: 0o600 });
  return {
    digest,
    repository,
    version,
    path: chartPath,
    values: valuesPath,
  };
}

function gitServiceManifest(address) {
  return `apiVersion: v1
kind: Service
metadata:
  name: codefly-local-git
  namespace: argocd
spec:
  ports:
    - name: http
      port: 80
      protocol: TCP
      targetPort: 80
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: codefly-local-git
  namespace: argocd
  labels:
    kubernetes.io/service-name: codefly-local-git
addressType: IPv4
ports:
  - name: http
    protocol: TCP
    port: 80
endpoints:
  - addresses:
      - ${address}
    conditions:
      ready: true
`;
}

function waitForGitRemote(revision) {
  for (let attempt = 1; attempt <= 30; attempt += 1) {
    const result = spawnSync(
      "kubectl",
      [
        "--kubeconfig",
        kubeconfigPath,
        "exec",
        "--namespace",
        "argocd",
        "deployment/argocd-repo-server",
        "--",
        "git",
        "ls-remote",
        gitRepositoryUrl,
      ],
      {
        cwd: repositoryRoot,
        encoding: "utf8",
        env: childEnvironment,
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    if (
      result.status === 0 &&
      result.stdout
        .split(/\r?\n/)
        .some((line) => line.startsWith(`${revision}\t`))
    ) {
      return;
    }
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1000);
  }
  throw new Error(
    "the Argo CD repo server could not read the disposable exact-snapshot Git remote",
  );
}

function apply(manifest) {
  run("kubectl", ["--kubeconfig", kubeconfigPath, "apply", "--filename=-"], {
    input: manifest,
  });
}

function runKubectl(args) {
  run("kubectl", ["--kubeconfig", kubeconfigPath, ...args]);
}

function captureKubectl(args) {
  return capture("kubectl", ["--kubeconfig", kubeconfigPath, ...args]);
}

function renderKustomize(directory) {
  const standalone = spawnSync("kustomize", ["version"], {
    cwd: repositoryRoot,
    env: childEnvironment,
    stdio: "ignore",
  });
  return standalone.status === 0
    ? capture("kustomize", ["build", directory])
    : capture("kubectl", ["kustomize", directory]);
}

function clusterRecord() {
  const result = spawnSync("k3d", ["cluster", "list", "--output", "json"], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: childEnvironment,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || "could not list k3d clusters");
  }
  return JSON.parse(result.stdout).find(
    (cluster) => cluster.name === clusterName,
  );
}

function registryRecord() {
  const result = spawnSync("k3d", ["registry", "list", "--output", "json"], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: childEnvironment,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || "could not list k3d registries");
  }
  return JSON.parse(result.stdout).find(
    (registry) => registry.name === expectedRegistryName,
  );
}

function assertReusableRegistry(registry, requireAttached) {
  const bindings = Object.values(registry?.portMappings ?? {}).flat();
  if (
    registry?.name !== expectedRegistryName ||
    registry?.role !== "registry" ||
    registry?.runtimeLabels?.["k3d.role"] !== "registry" ||
    bindings.length === 0 ||
    bindings.some((binding) => binding.HostIp !== "127.0.0.1") ||
    (requireAttached && !registry.Networks?.includes(`k3d-${clusterName}`))
  ) {
    throw new Error(
      `refusing registry '${expectedRegistryName}' unless it is an exact loopback-only k3d registry${requireAttached ? " attached to the owned cluster network" : ""}`,
    );
  }
  const role = capture("docker", [
    "inspect",
    "--format",
    '{{index .Config.Labels "k3d.role"}}',
    registry.name,
  ]).trim();
  if (role !== "registry") {
    throw new Error(
      `refusing registry '${expectedRegistryName}' without the exact runtime role`,
    );
  }
}

function registryHostEndpoint(registry) {
  const binding = Object.values(registry.portMappings).flat()[0];
  return `${binding.HostIp}:${binding.HostPort}`;
}

function assertOwnedCluster(cluster) {
  if (!cluster || !Array.isArray(cluster.nodes) || cluster.nodes.length === 0) {
    throw new Error(
      `refusing cluster '${clusterName}' without exact '${ownerLabel}=${ownerValue}' node ownership`,
    );
  }
  for (const node of cluster.nodes) {
    const owner = capture("docker", [
      "inspect",
      "--format",
      `{{index .Config.Labels "${ownerLabel}"}}`,
      node.name,
    ]).trim();
    if (owner !== ownerValue) {
      throw new Error(
        `refusing cluster '${clusterName}' without exact '${ownerLabel}=${ownerValue}' node ownership`,
      );
    }
  }
}

function containerExists(name) {
  return (
    spawnSync("docker", ["inspect", name], {
      cwd: repositoryRoot,
      env: childEnvironment,
      stdio: "ignore",
    }).status === 0
  );
}

function assertOwnedGitContainer() {
  const owner = capture("docker", [
    "inspect",
    "--format",
    `{{index .Config.Labels "${ownerLabel}"}}`,
    gitContainerName,
  ]).trim();
  const cluster = capture("docker", [
    "inspect",
    "--format",
    '{{index .Config.Labels "codefly.local-gitops.cluster"}}',
    gitContainerName,
  ]).trim();
  if (owner !== ownerValue || cluster !== clusterName) {
    throw new Error(
      `refusing to remove container '${gitContainerName}' without exact ownership labels`,
    );
  }
}

function requireTools() {
  for (const tool of ["docker", "git", "helm", "k3d", "kubectl"]) {
    requireCommand(tool);
  }
  if (
    spawnSync("kustomize", ["version"], {
      cwd: repositoryRoot,
      env: childEnvironment,
      stdio: "ignore",
    }).status !== 0
  ) {
    requireCommand("kubectl");
  }
}

function assertLocalDocker() {
  const context = capture("docker", ["context", "show"]).trim();
  const endpoint = JSON.parse(
    capture("docker", [
      "context",
      "inspect",
      context,
      "--format",
      "{{json .Endpoints.docker.Host}}",
    ]),
  );
  if (
    typeof endpoint !== "string" ||
    !endpoint.startsWith("unix://") ||
    (process.env.DOCKER_HOST && !process.env.DOCKER_HOST.startsWith("unix://"))
  ) {
    throw new Error(
      `local GitOps requires a local Unix Docker endpoint; resolved '${String(endpoint)}'`,
    );
  }
  capture("docker", ["info", "--format", "{{json .ServerVersion}}"]);
}

function helmRollbackFlag() {
  const version = capture("helm", [
    "version",
    "--template",
    "{{.Version}}",
  ]).trim();
  const match = /^v?(\d+)\./.exec(version);
  if (!match) {
    throw new Error(`could not parse Helm version '${version}'`);
  }
  return Number(match[1]) >= 4 ? "--rollback-on-failure" : "--atomic";
}

function requireCommand(name) {
  const result = spawnSync(name, ["--version"], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: childEnvironment,
    stdio: "ignore",
  });
  if (result.error?.code === "ENOENT") {
    throw new Error(
      `required command '${name}' is missing${name === "k3d" ? " (macOS: brew install k3d)" : ""}`,
    );
  }
}

function run(executable, args, options = {}) {
  const result = spawnSync(executable, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: childEnvironment,
    input: options.input,
    stdio: options.quiet
      ? ["ignore", "pipe", "pipe"]
      : options.input === undefined
        ? "inherit"
        : ["pipe", "inherit", "inherit"],
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const detail = options.quiet
      ? `${result.stdout ?? ""}${result.stderr ?? ""}`.trim()
      : "";
    throw new Error(
      `'${executable} ${args.join(" ")}' failed${detail ? `: ${detail}` : ""}`,
    );
  }
}

function capture(executable, args) {
  const result = spawnSync(executable, args, {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: childEnvironment,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      `'${executable} ${args.join(" ")}' failed: ${result.stderr.trim()}`,
    );
  }
  return result.stdout;
}

function sanitizedEnvironment() {
  return Object.fromEntries(
    Object.entries(process.env).filter(
      ([key]) =>
        key !== "KUBECONFIG" &&
        !/^(?:AWS|PULUMI|GOOGLE|AZURE|ARM|GH|GITHUB)_/.test(key),
    ),
  );
}

function option(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) return undefined;
  return process.argv[index + 1];
}

function assertArguments(args) {
  const seen = new Set();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    if (!["--cluster", "--timeout"].includes(name)) {
      throw new Error(`unknown option '${name}'`);
    }
    if (seen.has(name)) {
      throw new Error(`option '${name}' may be provided only once`);
    }
    const value = args[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`${name} requires a value`);
    }
    seen.add(name);
  }
}

function assertClusterName(value) {
  if (!/^[a-z0-9](?:[-a-z0-9]{0,38}[a-z0-9])?$/.test(value)) {
    throw new Error(
      "cluster name must be 1-40 lowercase alphanumeric or hyphen characters",
    );
  }
}

function assertTimeout(value) {
  if (!/^(?:[1-9]\d?m|[1-9]\d{0,2}s)$/.test(value)) {
    throw new Error("timeout must be 1-99 minutes or 1-999 seconds");
  }
}

function assertWithin(parent, candidate) {
  const relativePath = path.relative(parent, candidate);
  if (
    relativePath === "" ||
    relativePath.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relativePath)
  ) {
    throw new Error(`unsafe local state path '${candidate}'`);
  }
}

function isIpv4(value) {
  const octets = value.split(".");
  return (
    octets.length === 4 &&
    octets.every((octet) => {
      if (!/^\d{1,3}$/.test(octet)) return false;
      const number = Number(octet);
      return number >= 0 && number <= 255;
    })
  );
}

function availablePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port =
        address && typeof address === "object" ? address.port : undefined;
      server.close((error) => {
        if (error) reject(error);
        else if (!port)
          reject(new Error("could not allocate a local API port"));
        else resolve(port);
      });
    });
  });
}

function sha256(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function relative(value) {
  return path.relative(repositoryRoot, value);
}

function help() {
  process.stdout
    .write(`Usage: node scripts/local-k3d-gitops.mjs <command> [options]

Commands:
  up       Create owned k3d, isolated Git, and exact Argo CD reconciliation
  status   Show nodes, Argo CD reconciliation, and evidence path
  down     Delete only exactly named and ownership-labelled local resources
  doctor   Check prerequisites, local Docker, and both local overlays
  render   Render the local workload and Argo CD overlays

Options:
  --cluster <name>   Cluster name (default: codefly-local)
  --timeout <value>  Helm and reconciliation timeout (default: 8m)
`);
}
