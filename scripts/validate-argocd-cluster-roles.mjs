#!/usr/bin/env node

import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  cpSync,
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
import { loadArgocdValues } from "./load-argocd-values.mjs";

const K3S_IMAGE =
  "rancher/k3s@sha256:f17e43023cce2b9c613e198f26e73637bf734b5156d37c9f44819d97bac4d655";
const roles = ["platform", "execution"];
const runId = `argocd-role-${process.pid}-${randomBytes(4).toString("hex")}`;
const workingDirectory = mkdtempSync(path.join(tmpdir(), `${runId}-`));
const sourceDirectory = path.join(workingDirectory, "source");
const {
  ARGOCD_CHART_DIGEST: CHART_DIGEST,
  ARGOCD_CHART_REPOSITORY: CHART_REPOSITORY,
  ARGOCD_CHART_VERSION: CHART_VERSION,
  argocdHelmValues,
  databaseArgocdHelmValues,
} = loadArgocdValues(workingDirectory);
const chart = path.join(workingDirectory, `argo-cd-${CHART_VERSION}.tgz`);
const clusters = new Map();
const inventories = new Map(
  roles.map((role) => [role, renderRoleInventory(role)]),
);
const entrypointInventories = new Map(
  roles.map((role) => [role, renderEntrypointInventory(role)]),
);
const qualificationOperatorResources = new Map(
  roles.map((role) => [
    role,
    entrypointInventories
      .get(role)
      .filter(isAutomatedOperatorApplication)
      .map(qualificationOperatorResource),
  ]),
);
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
    installQualificationCrds(clusters.get(role), inventories.get(role));
    installArgocd(clusters.get(role), role);
    reconcileRole(clusters.get(role), role, repository, revision);
  }
  for (const role of roles) {
    assertRoleIsolation(
      clusters.get(role),
      role,
      inventories,
      entrypointInventories,
      qualificationOperatorResources,
    );
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
  cpSync("gitops", path.join(sourceDirectory, "gitops"), { recursive: true });
  for (const resource of uniqueOperatorResources()) {
    const directory = path.join(
      sourceDirectory,
      qualificationOperatorPath(resource.data.application),
    );
    mkdirSync(directory, { recursive: true });
    writeFileSync(
      path.join(directory, "kustomization.yaml"),
      stringify({
        apiVersion: "kustomize.config.k8s.io/v1beta1",
        kind: "Kustomization",
        resources: ["resource.yaml"],
      }),
    );
    writeFileSync(path.join(directory, "resource.yaml"), stringify(resource));
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
      "-c",
      "commit.gpgsign=false",
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
    "--add-host",
    "host.docker.internal:host-gateway",
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

function installArgocd(cluster, role) {
  const values = path.join(workingDirectory, `argocd-${role}-values.yaml`);
  writeFileSync(
    values,
    stringify(
      argocdHelmValues({
        clusterRole: role,
        argocdHostname: `argocd-${role}.qualification.invalid`,
        oidcIssuer: "https://identity.qualification.invalid",
        oidcClientId: `argocd-${role}`,
        oidcClientSecretRef: "$oidc.organization.clientSecret",
        oidcAdminGroup: "deus:infra:admins",
      }),
    ),
    { mode: 0o600 },
  );
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
  if (role === "platform") {
    const databaseValues = path.join(
      workingDirectory,
      "argocd-database-values.yaml",
    );
    writeFileSync(databaseValues, stringify(databaseArgocdHelmValues()), {
      mode: 0o600,
    });
    run("helm", [
      "--kubeconfig",
      cluster.kubeconfig,
      "install",
      "argocd-database",
      chart,
      "--namespace",
      "argocd-database",
      "--create-namespace",
      "--values",
      databaseValues,
      "--wait",
      "--timeout",
      "8m",
    ]);
  }
}

function reconcileRole(cluster, role, repository, revision) {
  const rendered = structuredClone(entrypointInventories.get(role));
  const applications = rendered.filter(
    (document) => document.kind === "Application",
  );
  const baselines = applications.filter((document) =>
    /-cluster-baseline$/.test(document.metadata?.name ?? ""),
  );
  if (
    baselines.length !== 1 ||
    baselines[0].metadata.name !== `${role}-cluster-baseline`
  ) {
    throw new Error(`${role} entrypoint did not select exactly one role.`);
  }
  for (const application of applications) {
    if (isAutomatedOperatorApplication(application)) {
      application.spec.source = {
        repoURL: repository,
        targetRevision: revision,
        path: qualificationOperatorPath(application.metadata.name),
      };
    } else if (
      application.spec.source?.repoURL ===
      "https://github.com/codefly-dev/secure-saas-infra.git"
    ) {
      application.spec.source.repoURL = repository;
      application.spec.source.targetRevision = revision;
    }
    if (application.spec.syncPolicy?.automated) {
      application.spec.syncPolicy.syncOptions = [
        ...(application.spec.syncPolicy.syncOptions ?? []).filter(
          (option) => !option.startsWith("CreateNamespace="),
        ),
        "CreateNamespace=false",
      ];
    }
  }
  for (const project of rendered.filter(
    (document) => document.kind === "AppProject",
  )) {
    if (
      applications.some(
        (application) => application.spec.project === project.metadata.name,
      )
    ) {
      project.spec.sourceRepos = [repository];
    }
  }
  const namespaces = [
    ...new Set(
      applications
        .filter((application) => application.spec.syncPolicy?.automated)
        .map((application) => application.spec.destination.namespace)
        .filter((namespace) => namespace !== "default"),
    ),
  ].map((namespace) => ({
    apiVersion: "v1",
    kind: "Namespace",
    metadata: { name: namespace },
  }));
  if (namespaces.length > 0) {
    kubectl(cluster, ["apply", "-f", "-"], joinDocuments(namespaces));
  }
  kubectl(cluster, ["apply", "-f", "-"], joinDocuments(rendered));
  for (const application of applications.filter(
    (candidate) => candidate.spec.syncPolicy?.automated,
  )) {
    poll(`${role} ${application.metadata.name} reconciliation`, 300, () => {
      const result = kubectlOptional(cluster, [
        "get",
        "application",
        application.metadata.name,
        "-n",
        application.metadata.namespace,
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
}

function assertRoleIsolation(
  cluster,
  role,
  roleInventories,
  entrypointResources,
  operatorResources,
) {
  const owned = roleInventories.get(role);
  const ownedOutput = kubectl(
    cluster,
    ["get", "-f", "-", "-o", "name"],
    stringifyResourceReferences(owned),
  )
    .stdout.trim()
    .split("\n")
    .filter(Boolean);
  if (ownedOutput.length !== owned.length) {
    throw new Error(
      `${role} cluster did not reconcile its exact baseline inventory.`,
    );
  }
  const otherRole = opposite(role);
  const ownedKeys = new Set(owned.map(resourceIdentity));
  const forbidden = roleInventories
    .get(otherRole)
    .filter((resource) => !ownedKeys.has(resourceIdentity(resource)));
  const forbiddenResources = findExistingResources(cluster, forbidden);
  const ownedOperators = operatorResources.get(role);
  const ownedOperatorOutput = kubectl(
    cluster,
    ["get", "-f", "-", "-o", "name"],
    stringifyResourceReferences(ownedOperators),
  )
    .stdout.trim()
    .split("\n")
    .filter(Boolean);
  const otherOperatorResources = operatorResources
    .get(otherRole)
    .filter(
      (resource) =>
        !ownedOperators.some(
          (ownedResource) =>
            resourceIdentity(ownedResource) === resourceIdentity(resource),
        ),
    );
  const forbiddenOperatorResources =
    otherOperatorResources.length === 0
      ? ""
      : findExistingResources(cluster, otherOperatorResources);
  const expectedApplications = entrypointResources
    .get(role)
    .filter((resource) => resource.kind === "Application")
    .map(
      (application) =>
        `${application.metadata.namespace}/${application.metadata.name}`,
    )
    .sort();
  const actualApplications = JSON.parse(
    kubectl(cluster, ["get", "applications.argoproj.io", "-A", "-o", "json"])
      .stdout,
  )
    .items.map(
      (application) =>
        `${application.metadata.namespace}/${application.metadata.name}`,
    )
    .sort();
  const forbiddenApplication =
    JSON.stringify(actualApplications) !== JSON.stringify(expectedApplications);
  const databaseNamespace = kubectl(cluster, [
    "get",
    "namespace",
    "argocd-database",
    "--ignore-not-found",
    "-o",
    "name",
  ]).stdout.trim();
  if (
    forbiddenResources ||
    forbiddenApplication ||
    forbiddenOperatorResources ||
    ownedOperatorOutput.length !== ownedOperators.length ||
    (role === "platform") !== Boolean(databaseNamespace)
  ) {
    throw new Error(`${otherRole} ownership crossed into the ${role} cluster.`);
  }
}

function renderRoleInventory(role) {
  return parseAllDocuments(
    run("kubectl", ["kustomize", `gitops/overlays/dev/${role}`]).stdout,
  )
    .map((document) => document.toJSON())
    .filter(Boolean);
}

function renderEntrypointInventory(role) {
  return parseAllDocuments(
    run("kubectl", [
      "kustomize",
      `gitops/bootstrap/argocd/overlays/dev/${role}`,
    ]).stdout,
  )
    .map((document) => document.toJSON())
    .filter(Boolean);
}

function isAutomatedOperatorApplication(resource) {
  return (
    resource.kind === "Application" &&
    resource.spec?.syncPolicy?.automated &&
    !/-cluster-baseline$/.test(resource.metadata?.name ?? "")
  );
}

function qualificationOperatorResource(application) {
  return {
    apiVersion: "v1",
    kind: "ConfigMap",
    metadata: {
      name: `argocd-qualification-${application.metadata.name}`,
      namespace: application.spec.destination.namespace,
    },
    data: {
      application: application.metadata.name,
    },
  };
}

function qualificationOperatorPath(applicationName) {
  return `gitops/qualification/operators/${applicationName}`;
}

function uniqueOperatorResources() {
  return [
    ...new Map(
      roles
        .flatMap((role) => qualificationOperatorResources.get(role))
        .map((resource) => [resourceIdentity(resource), resource]),
    ).values(),
  ];
}

function installQualificationCrds(cluster, resources) {
  const definitions = [
    ["kyverno.io", "v1", "ClusterPolicy", "clusterpolicies", "Cluster"],
    [
      "security.istio.io",
      "v1",
      "AuthorizationPolicy",
      "authorizationpolicies",
      "Namespaced",
    ],
    [
      "security.istio.io",
      "v1",
      "PeerAuthentication",
      "peerauthentications",
      "Namespaced",
    ],
    ["telemetry.istio.io", "v1", "Telemetry", "telemetries", "Namespaced"],
    ["tailscale.com", "v1alpha1", "Connector", "connectors", "Namespaced"],
  ].filter(([group, version, kind]) =>
    resources.some(
      (resource) =>
        resource.apiVersion === `${group}/${version}` && resource.kind === kind,
    ),
  );
  if (definitions.length === 0) return;
  const manifests = definitions.map(
    ([group, version, kind, plural, scope]) => ({
      apiVersion: "apiextensions.k8s.io/v1",
      kind: "CustomResourceDefinition",
      metadata: { name: `${plural}.${group}` },
      spec: {
        group,
        names: { kind, plural, singular: plural.replace(/s$/, "") },
        scope,
        versions: [
          {
            name: version,
            served: true,
            storage: true,
            schema: {
              openAPIV3Schema: {
                type: "object",
                "x-kubernetes-preserve-unknown-fields": true,
              },
            },
          },
        ],
      },
    }),
  );
  kubectl(cluster, ["apply", "-f", "-"], joinDocuments(manifests));
  kubectl(cluster, [
    "wait",
    "--for=condition=Established",
    "customresourcedefinition",
    "--all",
    "--timeout=60s",
  ]);
}

function stringifyResourceReferences(resources) {
  return joinDocuments(
    resources.map((resource) => ({
      apiVersion: resource.apiVersion,
      kind: resource.kind,
      metadata: {
        name: resource.metadata.name,
        ...(resource.metadata.namespace
          ? { namespace: resource.metadata.namespace }
          : {}),
      },
    })),
  );
}

function findExistingResources(cluster, resources) {
  return resources
    .flatMap((resource) => {
      const result = kubectlOptional(
        cluster,
        ["get", "-f", "-", "--ignore-not-found", "-o", "name"],
        stringifyResourceReferences([resource]),
      );
      if (result.status === 0) {
        return result.stdout.trim() ? [result.stdout.trim()] : [];
      }
      if (result.stderr.includes("no matches for kind")) return [];
      throw new Error(
        `Cannot verify isolation for ${resourceIdentity(resource)}: ${result.stderr}`,
      );
    })
    .join("\n");
}

function joinDocuments(documents) {
  return documents.map((document) => stringify(document)).join("---\n");
}

function resourceIdentity(resource) {
  return [
    resource.apiVersion,
    resource.kind,
    resource.metadata?.namespace ?? "<cluster>",
    resource.metadata?.name,
  ].join("|");
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
