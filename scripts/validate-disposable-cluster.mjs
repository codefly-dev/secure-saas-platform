#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { parse as parseYaml, stringify } from "yaml";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

let databaseAccessCompiler;

const K3S_DIGEST =
  "rancher/k3s@sha256:f17e43023cce2b9c613e198f26e73637bf734b5156d37c9f44819d97bac4d655";
const KYVERNO_CHART_VERSION = "3.7.0";
const KYVERNO_CHART_DIGEST =
  "7a94960c75c8faa9a2bbf7a2c39f6deeb7ff0b8814a8c17cee9a0816f8f69874";
const FIXTURE_IMAGE_DIGEST =
  "alpine@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40";
const OWNER_LABEL = "security.deus.dev/owner";
const RUN_LABEL = "security.deus.dev/run-id";
const RESTRICTED_NAMESPACES = Object.freeze([
  "agent-broker",
  "agent-egress",
  "execution",
  "platform",
  "security",
  "workloads",
]);
const EXPECTED_KYVERNO_IMAGES = Object.freeze([
  {
    component: "admission-controller",
    container: "kyverno",
    image: "reg.kyverno.io/kyverno/kyverno:v1.17.0",
    imageId:
      "reg.kyverno.io/kyverno/kyverno@sha256:ff2ca78b0703c1bcce7f22576f4e3e90d1dd17e710475dc88f3b7f10fc9f019d",
  },
  {
    component: "admission-controller",
    container: "kyverno-pre",
    image: "reg.kyverno.io/kyverno/kyvernopre:v1.17.0",
    imageId:
      "reg.kyverno.io/kyverno/kyvernopre@sha256:0b21526834219a8d7d0123632ab4308106444049cee4be7a46cbf209c21e11bb",
  },
  {
    component: "background-controller",
    container: "controller",
    image: "reg.kyverno.io/kyverno/background-controller:v1.17.0",
    imageId:
      "reg.kyverno.io/kyverno/background-controller@sha256:a38173ad69f0ad02779a6b20d40253a35608aac922d7d3ac39ac8d26f8382ca4",
  },
  {
    component: "cleanup-controller",
    container: "controller",
    image: "reg.kyverno.io/kyverno/cleanup-controller:v1.17.0",
    imageId:
      "reg.kyverno.io/kyverno/cleanup-controller@sha256:01af176e0af8f1b1f3388a8223ba3e6e19ed02517444df20b5e1e27e6ffa7c66",
  },
  {
    component: "reports-controller",
    container: "controller",
    image: "reg.kyverno.io/kyverno/reports-controller:v1.17.0",
    imageId:
      "reg.kyverno.io/kyverno/reports-controller@sha256:d5d0358e658b9d1b90954bf666f457bd6af5db36209e9ba792c182f212a11c0b",
  },
]);

const startedAt = Date.now();
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const runId = `secure-saas-infra-g5-${process.pid}-${randomBytes(4).toString("hex")}`;
const fixtureRuntimeImage = `docker.io/library/secure-saas-infra-g5:${runId}`;
const reportPath = safeOutputPath(
  parseArguments(process.argv.slice(2)).output ??
    "artifacts/disposable-cluster-validation.json",
);
const diagnosticsPath = path.resolve(
  `artifacts/disposable-cluster-diagnostics.${runId}.txt`,
);
const workingDirectory = mkdtempSync(path.join(tmpdir(), `${runId}-`));
const kubeconfig = path.join(workingDirectory, "kubeconfig");
const containerName = runId;
const report = {
  apiVersion: "security.deus.dev/disposable-cluster-validation/v1alpha1",
  kind: "DisposableClusterValidationReport",
  generatedAt: new Date(startedAt).toISOString(),
  completedAt: new Date(startedAt).toISOString(),
  durationMs: 0,
  pass: false,
  runId,
  scope: {
    environment: "local-k3s",
    proves: [
      "database-access-admission-shape",
      "database-controller-actor-authorization",
      "database-node-pool-reservation",
      "eks-shaped-token-manifest-admission",
      "kyverno-admission-enforcement",
      "kyverno-failure-policy-configured",
      "protected-admission-denied-during-kyverno-outage",
      "service-account-token-policy",
    ],
    excludes: [
      "application-network-policy-enforcement",
      "aws-sts-role-assumption",
      "eks-auto-mode-nodeclass-admission",
      "eks-pod-identity-agent-runtime",
      "pod-security-group-enforcement",
      "rds-iam-proxy-connectivity",
    ],
  },
  source: {},
  tools: {},
  cluster: {},
  inputs: {},
  checks: [],
  controllerImages: [],
  cleanup: {
    containerRemoved: false,
    temporaryDirectoryRemoved: false,
  },
};
let failure;
let kubeconfigReady = false;
let finalized = false;
let signalExitCode;

rmSync(reportPath, { force: true });

for (const [signal, code] of [
  ["SIGINT", 130],
  ["SIGTERM", 143],
]) {
  process.on(signal, () => {
    if (finalized) return;
    signalExitCode = code;
    failure =
      failure ?? new Error(`G5_SIGNAL_DENIED interrupted by ${signal}.`);
    finalize();
    process.exit(code);
  });
}

try {
  report.source = sourceState();
  validatePrerequisites();
  recordInputs();
  startCluster();
  installKyverno();
  importFixtureImage();
  validateServiceAccountTokenPolicy();
  validateDatabaseAccessAdmission();
  validateDatabaseControllerAuthorization();
  validateAdmissionFailurePolicy();
} catch (error) {
  failure = error;
} finally {
  finalize();
}

if (failure) {
  console.error(`G5 disposable-cluster validation failed: ${report.failure}`);
  if (existsSync(diagnosticsPath))
    console.error(`Diagnostics: ${diagnosticsPath}`);
  process.exit(signalExitCode ?? 1);
}

console.log(
  `Local K3s token/admission validation passed (${report.checks.length} checks; cleanup confirmed; AWS runtime excluded).`,
);

function validatePrerequisites() {
  for (const command of ["docker", "kubectl", "helm"]) {
    const versionArgs =
      command === "docker"
        ? ["version", "--format", "{{.Server.Version}}"]
        : command === "kubectl"
          ? ["version", "--client", "-o", "json"]
          : ["version", "--short"];
    report.tools[command] = run(command, versionArgs).stdout.trim();
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
    throw new Error(
      `G5_DOCKER_ENDPOINT_DENIED G5 requires a local Unix Docker endpoint; resolved '${String(endpoint)}'.`,
    );
  }
  report.tools.dockerContext = context;
  report.tools.dockerEndpoint = endpoint;
  pass("local-docker-endpoint");

  assertLocalImage(K3S_DIGEST, "K3s");
  assertLocalImage(FIXTURE_IMAGE_DIGEST, "fixture");
  pass("pinned-local-images");
}

function assertLocalImage(digest, label) {
  const repoDigests = JSON.parse(
    run("docker", [
      "image",
      "inspect",
      digest,
      "--format",
      "{{json .RepoDigests}}",
    ]).stdout,
  );
  if (!repoDigests.includes(digest)) {
    throw new Error(
      `G5_IMAGE_DENIED local ${label} image does not match ${digest}.`,
    );
  }
}

function recordInputs() {
  for (const file of [
    "gitops/base/kyverno/deny-service-account-tokens.yaml",
    "gitops/base/kyverno/authorize-database-infrastructure-controller.yaml",
    "gitops/base/kyverno/database-controller-native-admission.yaml",
    "gitops/base/kyverno/database-native-admission.yaml",
    "gitops/base/kyverno/workload-native-admission.yaml",
    "gitops/base/namespaces/restricted-default-serviceaccounts.yaml",
    "src/databaseAccess.ts",
    "dist/databaseAccess.js",
    "scripts/validate-disposable-cluster.mjs",
    "scripts/verify-disposable-cluster-report.mjs",
    "schemas/disposable-cluster-validation-v1.schema.json",
  ]) {
    report.inputs[file] = fileDigest(file);
  }
  report.inputs.k3sImage = K3S_DIGEST;
  report.inputs.kyvernoChart = {
    version: KYVERNO_CHART_VERSION,
    digest: KYVERNO_CHART_DIGEST,
  };
  report.inputs.fixtureImage = FIXTURE_IMAGE_DIGEST;
}

function startCluster() {
  run("docker", [
    "run",
    "-d",
    "--privileged",
    "--name",
    containerName,
    "--label",
    `${OWNER_LABEL}=secure-saas-infra-g5`,
    "--label",
    `${RUN_LABEL}=${runId}`,
    "--tmpfs",
    "/run",
    "--tmpfs",
    "/var/run",
    "-p",
    "127.0.0.1::6443",
    K3S_DIGEST,
    "server",
    "--disable",
    "traefik",
    "--disable",
    "servicelb",
    "--disable",
    "metrics-server",
    "--disable",
    "local-storage",
    "--write-kubeconfig-mode=644",
  ]);
  poll("K3s API", 120, () => {
    const result = runOptional("docker", [
      "exec",
      containerName,
      "kubectl",
      "--kubeconfig",
      "/etc/rancher/k3s/k3s.yaml",
      "get",
      "nodes",
      "-o",
      "json",
    ]);
    if (result.status !== 0) return false;
    try {
      return JSON.parse(result.stdout).items.length === 1;
    } catch {
      return false;
    }
  });
  run("docker", [
    "cp",
    `${containerName}:/etc/rancher/k3s/k3s.yaml`,
    kubeconfig,
  ]);
  const portOutput = run("docker", [
    "port",
    containerName,
    "6443/tcp",
  ]).stdout.trim();
  const port = portOutput.match(/:(\d+)$/)?.[1];
  if (!port) throw new Error("G5_CLUSTER_DENIED cannot resolve K3s API port.");
  const server = `https://127.0.0.1:${port}`;
  const body = readFileSync(kubeconfig, "utf8").replace(
    "https://127.0.0.1:6443",
    server,
  );
  writeFileSync(kubeconfig, body, { mode: 0o600 });
  kubeconfigReady = true;
  kubectl(["wait", "--for=condition=Ready", "node", "--all", "--timeout=120s"]);
  const node = JSON.parse(kubectl(["get", "nodes", "-o", "json"]).stdout);
  if (node.items.length !== 1) {
    throw new Error(
      `G5_CLUSTER_DENIED expected one node; found ${node.items.length}.`,
    );
  }
  const config = parseYaml(body);
  const caData = config?.clusters?.[0]?.cluster?.["certificate-authority-data"];
  if (typeof caData !== "string" || caData.length === 0) {
    throw new Error("G5_CLUSTER_DENIED kubeconfig lacks embedded CA data.");
  }
  const kubeSystem = JSON.parse(
    kubectl(["get", "namespace", "kube-system", "-o", "json"]).stdout,
  );
  report.tools.kubernetes = node.items[0].status.nodeInfo.kubeletVersion;
  report.cluster = {
    namespaceUid: kubeSystem.metadata.uid,
    apiServer: server,
    caSha256: sha256(Buffer.from(caData, "base64")),
  };
  pass("unique-ready-cluster");
}

function installKyverno() {
  const chart = path.join(
    workingDirectory,
    `kyverno-${KYVERNO_CHART_VERSION}.tgz`,
  );
  run("helm", [
    "pull",
    "kyverno",
    "--repo",
    "https://kyverno.github.io/kyverno/",
    "--version",
    KYVERNO_CHART_VERSION,
    "--destination",
    workingDirectory,
  ]);
  if (fileDigest(chart) !== KYVERNO_CHART_DIGEST) {
    throw new Error("G5_CHART_DENIED Kyverno chart digest does not match pin.");
  }
  helm([
    "install",
    "kyverno",
    chart,
    "--namespace",
    "kyverno",
    "--create-namespace",
    "--wait",
    "--timeout",
    "5m",
  ]);
  const pods = JSON.parse(
    kubectl(["get", "pods", "-n", "kyverno", "-o", "json"]).stdout,
  );
  const observed = [];
  for (const pod of pods.items) {
    const component = pod.metadata.labels?.["app.kubernetes.io/component"];
    for (const status of [
      ...(pod.status.containerStatuses ?? []),
      ...(pod.status.initContainerStatuses ?? []),
    ]) {
      observed.push({
        component,
        container: status.name,
        image: status.image,
        imageId: String(status.imageID ?? "").replace(
          /^docker-pullable:\/\//,
          "",
        ),
      });
    }
  }
  observed.sort(controllerImageOrder);
  const expected = structuredClone(EXPECTED_KYVERNO_IMAGES).sort(
    controllerImageOrder,
  );
  if (canonicalJson(observed) !== canonicalJson(expected)) {
    throw new Error(
      `G5_CONTROLLER_IMAGE_DENIED exact Kyverno image inventory mismatch: ${JSON.stringify(observed)}.`,
    );
  }
  report.controllerImages = observed;
  const versions = new Set(
    observed.map((entry) => entry.image.match(/:(v\d+\.\d+\.\d+)$/)?.[1]),
  );
  if (versions.size !== 1 || versions.has(undefined)) {
    throw new Error(
      "G5_CONTROLLER_IMAGE_DENIED Kyverno controllers do not share one observed version.",
    );
  }
  report.tools.kyverno = [...versions][0];
  pass("pinned-real-kyverno");
}

function controllerImageOrder(left, right) {
  return `${left.component}/${left.container}`.localeCompare(
    `${right.component}/${right.container}`,
  );
}

function importFixtureImage() {
  const archive = path.join(workingDirectory, "fixture-image.tar");
  run("docker", ["save", "--output", archive, FIXTURE_IMAGE_DIGEST]);
  run("docker", ["cp", archive, `${containerName}:/tmp/fixture-image.tar`]);
  run("docker", [
    "exec",
    containerName,
    "ctr",
    "-n",
    "k8s.io",
    "images",
    "import",
    "--index-name",
    fixtureRuntimeImage,
    "/tmp/fixture-image.tar",
  ]);
  const checkedImage = run("docker", [
    "exec",
    containerName,
    "ctr",
    "-n",
    "k8s.io",
    "images",
    "check",
    "--quiet",
    `name==${fixtureRuntimeImage}`,
  ]).stdout.trim();
  if (checkedImage !== fixtureRuntimeImage) {
    throw new Error(
      `G5_IMAGE_DENIED imported fixture did not resolve to the run-scoped local image; received '${checkedImage}'.`,
    );
  }
  run("docker", ["exec", containerName, "rm", "/tmp/fixture-image.tar"]);
  pass("local-fixture-image-imported");
}

function validateServiceAccountTokenPolicy() {
  for (const namespace of RESTRICTED_NAMESPACES) {
    apply(restrictedNamespace(namespace));
  }
  applyFile("gitops/base/namespaces/restricted-default-serviceaccounts.yaml");
  applyFile("gitops/base/kyverno/workload-native-admission.yaml");
  for (const namespace of RESTRICTED_NAMESPACES) {
    const serviceAccount = JSON.parse(
      kubectl([
        "get",
        "serviceaccount",
        "default",
        "-n",
        namespace,
        "-o",
        "json",
      ]).stdout,
    );
    if (serviceAccount.automountServiceAccountToken !== false) {
      throw new Error(
        `SEC_TOKEN_AUTOMOUNT_DENIED ${namespace}/default was not hardened by the real GitOps artifact.`,
      );
    }
  }
  pass("restricted-default-serviceaccounts-applied");

  applyFile("gitops/base/kyverno/deny-service-account-tokens.yaml");
  kubectl([
    "wait",
    "--for=condition=Ready",
    "clusterpolicy/deny-application-service-account-tokens",
    "--timeout=60s",
  ]);
  apply({
    apiVersion: "v1",
    kind: "ServiceAccount",
    metadata: { name: "safe-runtime", namespace: "workloads" },
    automountServiceAccountToken: false,
  });
  expectDenied(
    "service-account-automount",
    {
      apiVersion: "v1",
      kind: "ServiceAccount",
      metadata: { name: "unsafe-runtime", namespace: "workloads" },
      automountServiceAccountToken: true,
    },
    "SEC_TOKEN_AUTOMOUNT_DENIED",
    "serviceaccount-automount-must-be-false",
  );
  expectDenied(
    "pod-automount-omitted",
    fixturePod("unsafe-omitted", {}, { namespace: "workloads" }),
    "SEC_TOKEN_AUTOMOUNT_DENIED",
    "pod-automount-must-be-false",
  );
  expectDenied(
    "kubernetes-api-token-projection",
    fixturePod(
      "unsafe-kubernetes-token",
      {
        automountServiceAccountToken: false,
        volumes: [projectedTokenVolume("https://kubernetes.default.svc", 600)],
      },
      { namespace: "workloads" },
    ),
    "SEC_TOKEN_PROJECTION_DENIED",
    "kubernetes-api-token-projection-forbidden",
  );

  const bindingDigest = "b".repeat(64);
  const audience = "cloud.identity.example";
  const identityAnnotations = {
    "security.deus.dev/workload-identity-binding-digest": bindingDigest,
    "security.deus.dev/workload-identity-audience": audience,
  };
  apply({
    apiVersion: "v1",
    kind: "ServiceAccount",
    metadata: {
      name: "cloud-runtime",
      namespace: "workloads",
      annotations: identityAnnotations,
    },
    automountServiceAccountToken: false,
  });
  const cloudPod = fixturePod(
    "cloud-token-exact",
    {
      serviceAccountName: "cloud-runtime",
      automountServiceAccountToken: false,
      volumes: [projectedTokenVolume(audience, 600)],
    },
    { namespace: "workloads", annotations: identityAnnotations },
  );
  expectAllowed("cloud-token-binding-positive", cloudPod);

  const wrongAudience = structuredClone(cloudPod);
  wrongAudience.metadata.name = "cloud-token-wrong-audience";
  wrongAudience.spec.volumes[0].projected.sources[0].serviceAccountToken.audience =
    "attacker.invalid";
  expectDenied(
    "cloud-token-audience-substitution",
    wrongAudience,
    "SEC_CLOUD_TOKEN_BINDING_DENIED",
    "projected-cloud-token-must-match-infrastructure-owned-identity",
  );
  const wrongDigest = structuredClone(cloudPod);
  wrongDigest.metadata.name = "cloud-token-wrong-digest";
  wrongDigest.metadata.annotations[
    "security.deus.dev/workload-identity-binding-digest"
  ] = "c".repeat(64);
  expectDenied(
    "cloud-token-digest-substitution",
    wrongDigest,
    "SEC_CLOUD_TOKEN_BINDING_DENIED",
    "projected-cloud-token-must-match-infrastructure-owned-identity",
  );

  const eksAudience = "pods.eks.amazonaws.com";
  const eksBindingDigest = "e".repeat(64);
  const eksIdentityAnnotations = {
    "security.deus.dev/workload-identity-binding-digest": eksBindingDigest,
    "security.deus.dev/workload-identity-audience": eksAudience,
    "security.deus.dev/workload-identity-mode": "eks-pod-identity",
  };
  apply({
    apiVersion: "v1",
    kind: "ServiceAccount",
    metadata: {
      name: "eks-runtime",
      namespace: "workloads",
      annotations: eksIdentityAnnotations,
    },
    automountServiceAccountToken: false,
  });
  const eksPod = fixturePod(
    "eks-pod-identity-exact",
    {
      serviceAccountName: "eks-runtime",
      automountServiceAccountToken: false,
      volumes: [
        projectedTokenVolume(eksAudience, 86400, "eks-pod-identity-token"),
      ],
    },
    { namespace: "workloads", annotations: eksIdentityAnnotations },
  );
  expectAllowed("eks-pod-identity-token-positive", eksPod);

  const wrongEksExpiration = structuredClone(eksPod);
  wrongEksExpiration.metadata.name = "eks-token-wrong-expiration";
  wrongEksExpiration.spec.volumes[0].projected.sources[0].serviceAccountToken.expirationSeconds = 3600;
  expectDenied(
    "eks-pod-identity-expiration-substitution",
    wrongEksExpiration,
    "SEC_EKS_POD_IDENTITY_DENIED",
    "eks-pod-identity-token-must-match-association",
  );
  const wrongEksPath = structuredClone(eksPod);
  wrongEksPath.metadata.name = "eks-token-wrong-path";
  wrongEksPath.spec.volumes[0].projected.sources[0].serviceAccountToken.path =
    "token";
  expectDenied(
    "eks-pod-identity-path-substitution",
    wrongEksPath,
    "SEC_EKS_POD_IDENTITY_DENIED",
    "eks-pod-identity-token-must-match-association",
  );
  const wrongEksMode = structuredClone(eksPod);
  wrongEksMode.metadata.name = "eks-token-wrong-mode";
  wrongEksMode.spec.serviceAccountName = "eks-runtime-wrong-mode";
  apply({
    apiVersion: "v1",
    kind: "ServiceAccount",
    metadata: {
      name: "eks-runtime-wrong-mode",
      namespace: "workloads",
      annotations: {
        ...eksIdentityAnnotations,
        "security.deus.dev/workload-identity-mode": "irsa",
      },
    },
    automountServiceAccountToken: false,
  });
  expectDenied(
    "eks-pod-identity-mode-substitution",
    wrongEksMode,
    "SEC_EKS_POD_IDENTITY_DENIED",
    "eks-pod-identity-token-must-match-association",
  );
  const wrongEksDigest = structuredClone(eksPod);
  wrongEksDigest.metadata.name = "eks-token-wrong-digest";
  wrongEksDigest.metadata.annotations[
    "security.deus.dev/workload-identity-binding-digest"
  ] = "f".repeat(64);
  expectDenied(
    "eks-pod-identity-digest-substitution",
    wrongEksDigest,
    "SEC_EKS_POD_IDENTITY_DENIED",
    "eks-pod-identity-token-must-match-association",
  );

  expectDenied(
    "secret-volume",
    fixturePod(
      "unsafe-secret-volume",
      {
        automountServiceAccountToken: false,
        volumes: [{ name: "secret", secret: { secretName: "forbidden" } }],
      },
      { namespace: "workloads" },
    ),
    "SEC_SECRET_VOLUME_DENIED",
    "secret-volumes-forbidden",
  );

  apply(
    fixturePod(
      "safe-runtime",
      { automountServiceAccountToken: false },
      { namespace: "workloads" },
    ),
  );
  kubectl([
    "wait",
    "--for=condition=Ready",
    "pod/safe-runtime",
    "-n",
    "workloads",
    "--timeout=120s",
  ]);
  kubectl([
    "exec",
    "-n",
    "workloads",
    "safe-runtime",
    "--",
    "sh",
    "-c",
    "test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token",
  ]);
  const apiAttempt = kubectlOptional([
    "exec",
    "-n",
    "workloads",
    "safe-runtime",
    "--",
    "sh",
    "-c",
    "wget -S -O /dev/null --timeout=3 --no-check-certificate https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT_HTTPS}/api",
  ]);
  const apiOutput = `${apiAttempt.stdout}\n${apiAttempt.stderr}`;
  if (
    apiAttempt.status === 0 ||
    !/401 Unauthorized|403 Forbidden/.test(apiOutput)
  ) {
    throw new Error(
      `SEC_TOKEN_RUNTIME_DENIED expected unauthenticated API denial; received ${apiOutput.trim()}.`,
    );
  }
  pass("token-policy-denial-matrix");
  pass("runtime-token-absent-and-api-authentication-denied");
}

function validateDatabaseAccessAdmission() {
  applyFile("gitops/base/kyverno/database-native-admission.yaml");
  apply({
    apiVersion: "rbac.authorization.k8s.io/v1",
    kind: "ClusterRole",
    metadata: { name: "g5-database-child-controller" },
    rules: [
      {
        apiGroups: [""],
        resources: ["pods"],
        verbs: ["create"],
      },
      {
        apiGroups: ["apps"],
        resources: ["replicasets"],
        verbs: ["create"],
      },
    ],
  });
  apply({
    apiVersion: "rbac.authorization.k8s.io/v1",
    kind: "ClusterRoleBinding",
    metadata: { name: "g5-database-child-controller" },
    roleRef: {
      apiGroup: "rbac.authorization.k8s.io",
      kind: "ClusterRole",
      name: "g5-database-child-controller",
    },
    subjects: [
      { kind: "User", name: "system:kube-controller-manager" },
      {
        kind: "User",
        name: "system:serviceaccount:kube-system:replicaset-controller",
      },
      {
        kind: "User",
        name: "system:serviceaccount:kube-system:job-controller",
      },
    ],
  });
  databaseAccessCompiler ??= createRequire(import.meta.url)(
    "../dist/databaseAccess.js",
  );
  const { awsDatabaseAccessReservationKey, compileAwsDatabaseAdmissionPolicy } =
    databaseAccessCompiler;
  const bindingId = "k3s-postgres";
  const fixtures = ["runtime", "migration", "bootstrap"].map((accessClass) => {
    const namespace = `database-${accessClass}`;
    const serviceAccount = `database-${accessClass}`;
    const nodePoolName = `${bindingId}-${accessClass}-database-access`;
    const bindingDigest = sha256(`database-${accessClass}-binding`);
    const bindingLabels = {
      "security.deus.dev/workload-identity-binding": serviceAccount,
    };
    const reservationKey = awsDatabaseAccessReservationKey(
      bindingId,
      accessClass,
    );
    const requiredPodAnnotations = {
      "security.deus.dev/workload-identity-mode": "eks-pod-identity",
      "security.deus.dev/workload-identity-audience": "pods.eks.amazonaws.com",
      "security.deus.dev/workload-identity-binding-digest": bindingDigest,
    };
    const requiredPodScheduling = {
      nodeSelector: {
        [reservationKey]: nodePoolName,
      },
      tolerations: [
        {
          key: reservationKey,
          operator: "Equal",
          value: nodePoolName,
          effect: "NoSchedule",
        },
      ],
    };
    const fixture = {
      accessClass,
      namespace,
      serviceAccount,
      bindingLabels,
      requiredPodAnnotations,
      requiredPodScheduling,
      policy: compileAwsDatabaseAdmissionPolicy({
        bindingId,
        accessClass,
        namespace,
        serviceAccount,
        bindingLabels,
        requiredPodAnnotations,
        requiredPodScheduling,
      }),
    };
    apply(restrictedNamespace(namespace));
    apply({
      apiVersion: "v1",
      kind: "ServiceAccount",
      metadata: { name: "default", namespace },
      automountServiceAccountToken: false,
    });
    apply(databaseServiceAccount(fixture, namespace));
    apply(databaseServiceAccount(fixture, "workloads"));
    apply(fixture.policy);
    kubectl([
      "wait",
      "--for=condition=Ready",
      `clusterpolicy/${fixture.policy.metadata.name}`,
      "--timeout=60s",
    ]);
    return fixture;
  });

  for (const fixture of fixtures) {
    expectDenied(
      `database-${fixture.accessClass}-cross-namespace-nodepool-denied`,
      databasePod(
        fixture,
        `${fixture.accessClass}-cross-namespace`,
        "workloads",
        fixture.accessClass === "runtime" ? "ReplicaSet" : "Job",
      ),
      "SEC_DATABASE_NODE_POOL_RESERVED",
      "reserve-database-node-pool",
    );
    const tolerationOnly = databasePod(
      fixture,
      `${fixture.accessClass}-cross-namespace-toleration`,
      "workloads",
      fixture.accessClass === "runtime" ? "ReplicaSet" : "Job",
    );
    delete tolerationOnly.spec.nodeSelector;
    expectDenied(
      `database-${fixture.accessClass}-cross-namespace-toleration-denied`,
      tolerationOnly,
      "SEC_DATABASE_NODE_POOL_RESERVED",
      "reserve-database-node-pool",
    );
    const affinityOnly = databasePod(
      fixture,
      `${fixture.accessClass}-cross-namespace-affinity`,
      "workloads",
      fixture.accessClass === "runtime" ? "ReplicaSet" : "Job",
    );
    delete affinityOnly.spec.nodeSelector;
    delete affinityOnly.spec.tolerations;
    affinityOnly.spec.affinity = {
      nodeAffinity: {
        requiredDuringSchedulingIgnoredDuringExecution: {
          nodeSelectorTerms: [
            {
              matchExpressions: [
                {
                  key: Object.keys(
                    fixture.requiredPodScheduling.nodeSelector,
                  )[0],
                  operator: "In",
                  values: [
                    Object.values(
                      fixture.requiredPodScheduling.nodeSelector,
                    )[0],
                  ],
                },
              ],
            },
          ],
        },
      },
    };
    expectDenied(
      `database-${fixture.accessClass}-cross-namespace-affinity-denied`,
      affinityOnly,
      "SEC_DATABASE_NODE_POOL_RESERVED",
      "reserve-database-node-pool",
    );
    expectDenied(
      `database-${fixture.accessClass}-ownerless-pod-denied`,
      databasePod(
        fixture,
        `${fixture.accessClass}-direct-pod`,
        fixture.namespace,
      ),
      "SEC_DATABASE_POD_OWNER_DENIED",
      "require-database-pod-controller-owner",
    );
    expectAllowed(
      `database-${fixture.accessClass}-controller-owner-shape-positive`,
      databasePod(
        fixture,
        `${fixture.accessClass}-controller-owned`,
        fixture.namespace,
        fixture.accessClass === "runtime" ? "ReplicaSet" : "Job",
      ),
      "system:kube-controller-manager",
    );
    expectAllowed(
      `database-${fixture.accessClass}-parent-admission-positive`,
      databaseWorkload(
        fixture,
        fixture.accessClass === "runtime" ? "Deployment" : "Job",
      ),
    );
  }

  const runtime = fixtures.find((fixture) => fixture.accessClass === "runtime");
  const migration = fixtures.find(
    (fixture) => fixture.accessClass === "migration",
  );
  const bootstrap = fixtures.find(
    (fixture) => fixture.accessClass === "bootstrap",
  );
  poll("Kyverno database child-controller webhook", 60, () => {
    const configurations = JSON.parse(
      kubectl(["get", "validatingwebhookconfigurations", "-o", "json"]).stdout,
    );
    return configurations.items
      .flatMap((configuration) => configuration.webhooks ?? [])
      .filter(
        (webhook) => webhook.clientConfig?.service?.namespace === "kyverno",
      )
      .flatMap((webhook) => webhook.rules ?? [])
      .some((rule) =>
        (rule.resources ?? []).some(
          (resource) => resource === "*" || resource === "replicasets",
        ),
      );
  });
  const directNodeBinding = databasePod(
    runtime,
    "runtime-direct-node-binding",
    runtime.namespace,
    "ReplicaSet",
  );
  directNodeBinding.spec.nodeName = "forged-database-node";
  expectDenied(
    "database-runtime-direct-node-binding-denied",
    directNodeBinding,
    "SEC_DATABASE_NODE_NAME_DENIED",
    "deny-direct-node-binding",
  );
  expectDenied(
    "database-runtime-wrong-owner-denied",
    databasePod(runtime, "runtime-wrong-owner", runtime.namespace, "Job"),
    "SEC_DATABASE_POD_OWNER_DENIED",
    "require-database-pod-controller-owner",
  );
  expectDenied(
    "database-runtime-wrong-kind-denied",
    databaseWorkload(runtime, "Job"),
    "SEC_DATABASE_WORKLOAD_KIND_DENIED",
    "restrict-database-workload-kind",
  );
  expectDenied(
    "database-runtime-native-statefulset-denied",
    databaseWorkload(runtime, "StatefulSet"),
    "SEC_DATABASE_WORKLOAD_KIND_DENIED",
    "database-workload-native-boundary",
  );
  expectDenied(
    "database-migration-wrong-kind-denied",
    databaseWorkload(migration, "Deployment"),
    "SEC_DATABASE_WORKLOAD_KIND_DENIED",
    "restrict-database-workload-kind",
  );
  expectDenied(
    "database-bootstrap-wrong-kind-denied",
    databaseWorkload(bootstrap, "Deployment"),
    "SEC_DATABASE_WORKLOAD_KIND_DENIED",
    "restrict-database-workload-kind",
  );
  expectDenied(
    "database-runtime-direct-replicaset-denied",
    databaseWorkload(runtime, "ReplicaSet"),
    "SEC_DATABASE_CHILD_ACTOR_DENIED",
    "require-database-replicaset-controller-identity",
  );
  expectDenied(
    "database-runtime-forged-owner-actor-denied",
    databasePod(
      runtime,
      "runtime-forged-owner-actor",
      runtime.namespace,
      "ReplicaSet",
    ),
    "SEC_DATABASE_POD_ACTOR_DENIED",
    "require-database-pod-controller-identity",
  );
  const customScheduler = databasePod(
    runtime,
    "runtime-custom-scheduler",
    runtime.namespace,
    "ReplicaSet",
  );
  customScheduler.spec.schedulerName = "attacker-scheduler";
  expectDenied(
    "database-runtime-custom-scheduler-denied",
    customScheduler,
    "SEC_DATABASE_CUSTOM_SCHEDULER_DENIED",
    "database-pods-default-scheduler-only",
    "system:kube-controller-manager",
  );
}

function validateDatabaseControllerAuthorization() {
  const actor =
    "system:serviceaccount:argocd-database:database-infrastructure-application-controller";
  const attacker = "system:serviceaccount:default:database-controller-attacker";
  const roleName = "database-infrastructure-application-controller";
  const exactNamespace = "codefly-db-runtime-warden-saas-postgres-development";

  apply({
    apiVersion: "v1",
    kind: "Namespace",
    metadata: { name: "argocd-database" },
  });
  apply({
    apiVersion: "v1",
    kind: "ServiceAccount",
    metadata: {
      name: "database-infrastructure-application-controller",
      namespace: "argocd-database",
    },
    automountServiceAccountToken: true,
  });
  apply({
    apiVersion: "v1",
    kind: "ServiceAccount",
    metadata: { name: "database-controller-attacker", namespace: "default" },
    automountServiceAccountToken: false,
  });
  apply({
    apiVersion: "rbac.authorization.k8s.io/v1",
    kind: "ClusterRole",
    metadata: { name: roleName },
    rules: [
      {
        apiGroups: [""],
        resources: ["namespaces", "serviceaccounts"],
        verbs: ["get", "list", "watch", "create", "update", "patch"],
      },
      {
        apiGroups: ["authorization.k8s.io"],
        resources: ["selfsubjectaccessreviews"],
        verbs: ["create"],
      },
    ],
  });
  for (const [name, namespace, serviceAccount] of [
    [
      "database-infrastructure-controller",
      "argocd-database",
      "database-infrastructure-application-controller",
    ],
    [
      "database-infrastructure-attacker",
      "default",
      "database-controller-attacker",
    ],
  ]) {
    apply({
      apiVersion: "rbac.authorization.k8s.io/v1",
      kind: "ClusterRoleBinding",
      metadata: { name },
      roleRef: {
        apiGroup: "rbac.authorization.k8s.io",
        kind: "ClusterRole",
        name: roleName,
      },
      subjects: [{ kind: "ServiceAccount", name: serviceAccount, namespace }],
    });
  }

  applyFile(
    "gitops/base/kyverno/authorize-database-infrastructure-controller.yaml",
  );
  applyFile("gitops/base/kyverno/database-controller-native-admission.yaml");
  kubectl([
    "wait",
    "--for=condition=Ready",
    "clusterpolicy/authorize-database-infrastructure-controller",
    "--timeout=60s",
  ]);

  for (const [verb, resource, namespace] of [
    ["create", "namespaces", undefined],
    ["create", "serviceaccounts", exactNamespace],
    ["patch", "serviceaccounts", exactNamespace],
  ]) {
    assertCanI(actor, verb, resource, namespace, true);
  }
  pass("database-controller-rbac-positive");
  assertCanI(actor, "delete", "namespaces", undefined, false);
  assertCanI(actor, "delete", "serviceaccounts", exactNamespace, false);
  pass("database-controller-delete-rbac-denied");
  for (const [resource, namespace] of [
    ["pods", exactNamespace],
    ["pods/binding", exactNamespace],
    ["deployments.apps", exactNamespace],
    ["jobs.batch", exactNamespace],
    ["secrets", exactNamespace],
    ["roles.rbac.authorization.k8s.io", exactNamespace],
    ["clusterpolicies.kyverno.io", undefined],
    ["nodes", undefined],
  ]) {
    assertCanI(actor, "create", resource, namespace, false);
  }
  pass("database-controller-rbac-negative");
  pass("database-controller-policy-mutation-rbac-denied");

  kubectl(
    ["create", "--as", actor, "-f", "-"],
    stringify({
      apiVersion: "v1",
      kind: "Namespace",
      metadata: { name: exactNamespace },
    }),
  );
  pass("database-controller-namespace-create-positive");

  apply({
    apiVersion: "v1",
    kind: "Namespace",
    metadata: { name: "database-controller-native-delete-victim" },
  });
  apply({
    apiVersion: "rbac.authorization.k8s.io/v1",
    kind: "ClusterRole",
    metadata: { name: "database-controller-adversarial-delete" },
    rules: [
      {
        apiGroups: [""],
        resources: ["namespaces", "serviceaccounts"],
        verbs: ["delete"],
      },
    ],
  });
  apply({
    apiVersion: "rbac.authorization.k8s.io/v1",
    kind: "ClusterRoleBinding",
    metadata: { name: "database-controller-adversarial-delete" },
    roleRef: {
      apiGroup: "rbac.authorization.k8s.io",
      kind: "ClusterRole",
      name: "database-controller-adversarial-delete",
    },
    subjects: [
      {
        kind: "ServiceAccount",
        name: "database-infrastructure-application-controller",
        namespace: "argocd-database",
      },
    ],
  });
  assertCanI(actor, "delete", "namespaces", undefined, true);
  expectDeleteDenied(
    "database-controller-native-exact-delete-denied",
    "namespace",
    exactNamespace,
    undefined,
    "SEC_DATABASE_CONTROLLER_DELETE_DENIED",
    "database-controller-native-scope",
    actor,
  );
  expectDeleteDenied(
    "database-controller-native-out-of-scope-delete-denied",
    "namespace",
    "database-controller-native-delete-victim",
    undefined,
    "SEC_DATABASE_CONTROLLER_DELETE_DENIED",
    "database-controller-native-scope",
    actor,
  );
  expectDenied(
    "database-controller-wrong-actor-denied",
    {
      apiVersion: "v1",
      kind: "Namespace",
      metadata: {
        name: "codefly-db-migration-mind-users-postgres-development",
      },
    },
    "SEC_DATABASE_CONTROLLER_IDENTITY_DENIED",
    "database-controller-native-ownership",
    attacker,
  );
  expectDenied(
    "database-controller-namespace-scope-denied",
    {
      apiVersion: "v1",
      kind: "Namespace",
      metadata: { name: "codefly-db-runtime-attacker-development" },
    },
    "SEC_DATABASE_CONTROLLER_SCOPE_DENIED",
    "database-controller-native-scope",
    actor,
  );
  expectAllowed(
    "database-controller-serviceaccount-positive",
    {
      apiVersion: "v1",
      kind: "ServiceAccount",
      metadata: { name: "warden-saas-service", namespace: exactNamespace },
      automountServiceAccountToken: false,
    },
    actor,
  );
  expectDenied(
    "database-controller-serviceaccount-scope-denied",
    {
      apiVersion: "v1",
      kind: "ServiceAccount",
      metadata: { name: "forbidden", namespace: "workloads" },
      automountServiceAccountToken: false,
    },
    "SEC_DATABASE_CONTROLLER_SCOPE_DENIED",
    "database-controller-native-scope",
    actor,
  );

  apply({
    apiVersion: "rbac.authorization.k8s.io/v1",
    kind: "ClusterRole",
    metadata: { name: "database-controller-adversarial-workload-create" },
    rules: [
      {
        apiGroups: ["apps"],
        resources: ["deployments"],
        verbs: ["create"],
      },
    ],
  });
  apply({
    apiVersion: "rbac.authorization.k8s.io/v1",
    kind: "ClusterRoleBinding",
    metadata: { name: "database-controller-adversarial-workload-create" },
    roleRef: {
      apiGroup: "rbac.authorization.k8s.io",
      kind: "ClusterRole",
      name: "database-controller-adversarial-workload-create",
    },
    subjects: [
      {
        kind: "ServiceAccount",
        name: "database-infrastructure-application-controller",
        namespace: "argocd-database",
      },
    ],
  });
  expectDenied(
    "database-controller-forbidden-kind-denied",
    {
      apiVersion: "apps/v1",
      kind: "Deployment",
      metadata: { name: "forbidden", namespace: exactNamespace },
      spec: {
        replicas: 1,
        selector: { matchLabels: { app: "forbidden" } },
        template: {
          metadata: {
            labels: { app: "forbidden" },
            annotations: {
              "security.deus.dev/workload-identity-binding-digest": "0".repeat(
                64,
              ),
            },
          },
          spec: {
            automountServiceAccountToken: false,
            containers: [{ name: "fixture", image: fixtureRuntimeImage }],
          },
        },
      },
    },
    "SEC_DATABASE_CONTROLLER_KIND_DENIED",
    "database-controller-forbidden-kinds",
    actor,
  );
}

function databaseServiceAccount(fixture, namespace) {
  return {
    apiVersion: "v1",
    kind: "ServiceAccount",
    metadata: {
      name: fixture.serviceAccount,
      namespace,
      labels: fixture.bindingLabels,
      annotations: fixture.requiredPodAnnotations,
    },
    automountServiceAccountToken: false,
  };
}

function databasePod(fixture, name, namespace, ownerKind) {
  const pod = fixturePod(
    name,
    {
      serviceAccountName: fixture.serviceAccount,
      automountServiceAccountToken: false,
      nodeSelector: fixture.requiredPodScheduling.nodeSelector,
      tolerations: fixture.requiredPodScheduling.tolerations,
      volumes: [
        projectedTokenVolume(
          "pods.eks.amazonaws.com",
          86400,
          "eks-pod-identity-token",
        ),
      ],
    },
    { namespace, annotations: fixture.requiredPodAnnotations },
  );
  pod.metadata.labels = fixture.bindingLabels;
  if (ownerKind) {
    pod.metadata.ownerReferences = [
      {
        apiVersion: ownerKind === "Job" ? "batch/v1" : "apps/v1",
        kind: ownerKind,
        name: `${name}-owner`,
        uid: `${name}-owner-uid`,
        controller: true,
        blockOwnerDeletion: false,
      },
    ];
  }
  return pod;
}

function databaseWorkload(fixture, kind) {
  const pod = databasePod(
    fixture,
    `${fixture.accessClass}-${kind.toLowerCase()}-template`,
    fixture.namespace,
    kind === "Job" ? "Job" : "ReplicaSet",
  );
  delete pod.metadata.name;
  delete pod.metadata.namespace;
  delete pod.metadata.ownerReferences;
  const template = { metadata: pod.metadata, spec: pod.spec };
  if (kind === "Job") {
    return {
      apiVersion: "batch/v1",
      kind,
      metadata: {
        name: `${fixture.accessClass}-forbidden-job`,
        namespace: fixture.namespace,
      },
      spec: { template },
    };
  }
  pod.spec.restartPolicy = "Always";
  return {
    apiVersion: "apps/v1",
    kind,
    metadata: {
      name: `${fixture.accessClass}-forbidden-${kind.toLowerCase()}`,
      namespace: fixture.namespace,
    },
    spec: {
      replicas: 1,
      ...(kind === "StatefulSet"
        ? { serviceName: `${fixture.accessClass}-statefulset` }
        : {}),
      selector: { matchLabels: fixture.bindingLabels },
      template,
    },
  };
}

function restrictedNamespace(name) {
  return {
    apiVersion: "v1",
    kind: "Namespace",
    metadata: {
      name,
      labels: {
        "security.deus.dev/service-account-token-policy": "restricted",
      },
    },
  };
}

function projectedTokenVolume(
  audience,
  expirationSeconds,
  tokenPath = "token",
) {
  return {
    name: "cloud-token",
    projected: {
      sources: [
        {
          serviceAccountToken: {
            audience,
            expirationSeconds,
            path: tokenPath,
          },
        },
      ],
    },
  };
}

function validateAdmissionFailurePolicy() {
  assertKyvernoFailClosedWebhook();
  pass("kyverno-failure-policy-webhook-configured");
  kubectl([
    "scale",
    "deployment",
    "kyverno-admission-controller",
    "-n",
    "kyverno",
    "--replicas=0",
  ]);
  poll("Kyverno admission controller shutdown", 60, () => {
    const pods = JSON.parse(
      kubectl([
        "get",
        "pods",
        "-n",
        "kyverno",
        "-l",
        "app.kubernetes.io/component=admission-controller",
        "-o",
        "json",
      ]).stdout,
    );
    return pods.items.length === 0;
  });
  poll("Kyverno admission endpoint removal", 60, () => {
    const endpoints = JSON.parse(
      kubectl([
        "get",
        "endpoints",
        "kyverno-svc",
        "-n",
        "kyverno",
        "-o",
        "json",
      ]).stdout,
    );
    return (endpoints.subsets ?? []).every(
      (subset) => (subset.addresses ?? []).length === 0,
    );
  });
  poll("Kyverno admission EndpointSlice removal", 60, () => {
    const endpointSlices = JSON.parse(
      kubectl([
        "get",
        "endpointslices.discovery.k8s.io",
        "-n",
        "kyverno",
        "-l",
        "kubernetes.io/service-name=kyverno-svc",
        "-o",
        "json",
      ]).stdout,
    );
    return endpointSlices.items.every((slice) =>
      (slice.endpoints ?? []).every(
        (endpoint) =>
          endpoint.conditions?.ready !== true &&
          endpoint.conditions?.serving !== true,
      ),
    );
  });
  const outageFixtures = [
    {
      apiVersion: "v1",
      kind: "Pod",
      metadata: { name: "pod-during-outage", namespace: "workloads" },
      spec: {
        automountServiceAccountToken: false,
        containers: [{ name: "fixture", image: fixtureRuntimeImage }],
      },
    },
    {
      apiVersion: "apps/v1",
      kind: "Deployment",
      metadata: {
        name: "deployment-during-outage",
        namespace: "codefly-db-runtime-warden-saas-postgres-development",
      },
      spec: {
        selector: { matchLabels: { app: "outage" } },
        template: {
          metadata: { labels: { app: "outage" } },
          spec: {
            automountServiceAccountToken: false,
            containers: [{ name: "fixture", image: fixtureRuntimeImage }],
          },
        },
      },
    },
    {
      apiVersion: "batch/v1",
      kind: "Job",
      metadata: {
        name: "job-during-outage",
        namespace: "codefly-db-runtime-warden-saas-postgres-development",
      },
      spec: {
        template: {
          spec: {
            restartPolicy: "Never",
            automountServiceAccountToken: false,
            containers: [{ name: "fixture", image: fixtureRuntimeImage }],
          },
        },
      },
    },
  ];
  let firstOutageOutput = "";
  poll("Kyverno protected-resource outage denial", 60, () => {
    const result = attemptOutageAdmission(outageFixtures[0]);
    firstOutageOutput = result.output;
    return result.failedClosed;
  });
  for (const fixture of outageFixtures.slice(1)) {
    const result = attemptOutageAdmission(fixture);
    if (!result.failedClosed) {
      throw new Error(
        `G5_FAILURE_POLICY_DENIED protected ${fixture.kind} admission did not fail closed during controller outage; received ${result.output.trim()}.`,
      );
    }
  }
  if (!firstOutageOutput) {
    throw new Error(
      "G5_FAILURE_POLICY_DENIED protected Pod outage denial produced no API-server evidence.",
    );
  }
  pass("protected-admission-denied-during-kyverno-outage");
}

function assertKyvernoFailClosedWebhook() {
  const configurations = JSON.parse(
    kubectl(["get", "validatingwebhookconfigurations", "-o", "json"]).stdout,
  );
  const installed = configurations.items
    .flatMap((configuration) => configuration.webhooks ?? [])
    .filter(
      (webhook) =>
        webhook.name === "validate.kyverno.svc-fail" &&
        webhook.clientConfig?.service?.name === "kyverno-svc" &&
        webhook.clientConfig?.service?.namespace === "kyverno",
    );
  const coveredResources = new Set(
    installed.flatMap((webhook) =>
      (webhook.rules ?? []).flatMap((rule) => rule.resources ?? []),
    ),
  );
  if (
    installed.length === 0 ||
    installed.some(
      (webhook) =>
        webhook.failurePolicy !== "Fail" || !webhook.clientConfig?.caBundle,
    ) ||
    !["pods", "deployments", "jobs"].every(
      (resource) => coveredResources.has("*") || coveredResources.has(resource),
    )
  ) {
    throw new Error(
      "G5_FAILURE_POLICY_DENIED Kyverno must retain a CA-bound failurePolicy=Fail webhook covering Pods, Deployments, and Jobs.",
    );
  }
}

function attemptOutageAdmission(fixture) {
  const attempt = kubectlOptional(
    ["create", "--dry-run=server", "-f", "-"],
    stringify(fixture),
  );
  const output = `${attempt.stdout}\n${attempt.stderr}`;
  const webhookUnavailable =
    /failed calling webhook|no endpoints available|connection refused/i.test(
      output,
    );
  const nativeBackstop =
    /SEC_NATIVE_RUN_AS_NON_ROOT_DENIED|SEC_NATIVE_SECCOMP_DENIED|SEC_DATABASE_BINDING_DIGEST_DENIED|SEC_DATABASE_WORKLOAD_KIND_DENIED/i.test(
      output,
    );
  return {
    output,
    webhookUnavailable,
    nativeBackstop,
    failedClosed:
      attempt.status !== 0 && (webhookUnavailable || nativeBackstop),
  };
}

function fixturePod(name, specPatch, options = {}) {
  return {
    apiVersion: "v1",
    kind: "Pod",
    metadata: {
      name,
      namespace: options.namespace ?? "workloads",
      ...(options.annotations ? { annotations: options.annotations } : {}),
    },
    spec: {
      serviceAccountName: "safe-runtime",
      restartPolicy: "Never",
      enableServiceLinks: true,
      securityContext: {
        runAsNonRoot: true,
        runAsUser: 65532,
        seccompProfile: { type: "RuntimeDefault" },
      },
      containers: [
        {
          name: "fixture",
          image: fixtureRuntimeImage,
          imagePullPolicy: "Never",
          command: ["sleep", "600"],
          securityContext: {
            allowPrivilegeEscalation: false,
            readOnlyRootFilesystem: true,
            capabilities: { drop: ["ALL"] },
          },
          resources: {
            requests: { cpu: "5m", memory: "8Mi" },
            limits: { cpu: "100m", memory: "32Mi" },
          },
        },
      ],
      ...specPatch,
    },
  };
}

function expectAllowed(label, resource, username) {
  const args = ["create", "--dry-run=server", "-f", "-"];
  if (username) args.unshift("--as", username);
  const result = kubectlOptional(args, stringify(resource));
  if (result.status !== 0) {
    throw new Error(
      `G5_ALLOW_ASSERTION_FAILED ${label}: ${result.stderr.trim() || result.stdout.trim()}.`,
    );
  }
  pass(label);
}

function expectDenied(
  label,
  resource,
  code,
  rule,
  username,
  impersonationGroups = [],
) {
  const args = ["create", "--dry-run=server", "-f", "-"];
  for (const group of impersonationGroups) args.unshift("--as-group", group);
  if (username) args.unshift("--as", username);
  const result = kubectlOptional(args, stringify(resource));
  const output = `${result.stdout}\n${result.stderr}`;
  if (result.status === 0 || !output.includes(code) || !output.includes(rule)) {
    throw new Error(
      `G5_DENIAL_ASSERTION_FAILED ${label} expected ${code}/${rule}; received ${output.trim()}.`,
    );
  }
  pass(label, { denialCode: code, rule });
}

function expectDeleteDenied(
  label,
  resource,
  name,
  namespace,
  code,
  rule,
  username,
) {
  const args = ["delete", resource, name, "--dry-run=server"];
  if (namespace) args.push("-n", namespace);
  if (username) args.push("--as", username);
  const result = kubectlOptional(args);
  const output = `${result.stdout}\n${result.stderr}`;
  if (result.status === 0 || !output.includes(code) || !output.includes(rule)) {
    throw new Error(
      `G5_DENIAL_ASSERTION_FAILED ${label} expected ${code}/${rule}; received ${output.trim()}.`,
    );
  }
  pass(label, { denialCode: code, rule });
}

function assertCanI(username, verb, resource, namespace, expected) {
  const args = ["auth", "can-i", verb, resource, "--as", username];
  if (namespace) args.push("-n", namespace);
  const command = kubectlOptional(args);
  if (![0, 1].includes(command.status)) {
    throw new Error(
      `G5_RBAC_ASSERTION_FAILED kubectl auth can-i errored: ${command.stderr.trim()}.`,
    );
  }
  const allowed = command.stdout.trim() === "yes";
  if (allowed !== expected) {
    throw new Error(
      `G5_RBAC_ASSERTION_FAILED ${username} ${verb} ${resource} expected ${expected}; received ${allowed}.`,
    );
  }
}

function apply(resource) {
  kubectl(["apply", "-f", "-"], stringify(resource));
}

function applyFile(file) {
  kubectl(["apply", "-f", file]);
}

function kubectl(args, input) {
  return run("kubectl", args, input, { KUBECONFIG: kubeconfig });
}

function kubectlOptional(args, input) {
  return runOptional("kubectl", args, input, { KUBECONFIG: kubeconfig });
}

function helm(args) {
  return run("helm", args, undefined, { KUBECONFIG: kubeconfig });
}

function poll(label, attempts, predicate) {
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    if (predicate()) return;
    if (attempt < attempts) run("sleep", ["1"]);
  }
  throw new Error(`G5_TIMEOUT ${label} did not become ready.`);
}

function collectDiagnostics() {
  const sections = [];
  if (kubeconfigReady) {
    for (const args of [
      ["get", "all", "-A", "-o", "wide"],
      ["get", "events", "-A", "--sort-by=.lastTimestamp"],
      ["get", "clusterpolicies", "-o", "yaml"],
      [
        "logs",
        "-n",
        "kyverno",
        "-l",
        "app.kubernetes.io/component=admission-controller",
        "--tail=300",
      ],
    ]) {
      const result = kubectlOptional(args);
      sections.push(
        `$ kubectl ${args.join(" ")}\n${result.stdout}\n${result.stderr}`,
      );
    }
  }
  const logs = runOptional("docker", ["logs", "--tail", "400", containerName]);
  sections.push(
    `$ docker logs --tail 400 ${containerName}\n${logs.stdout}\n${logs.stderr}`,
  );
  writeFileSync(diagnosticsPath, `${sections.join("\n\n")}\n`, { mode: 0o600 });
}

function cleanup() {
  const failures = [];
  const remove = runOptional("docker", ["rm", "-f", containerName]);
  if (remove.error) failures.push(String(remove.error.message ?? remove.error));
  const inspect = runOptional("docker", ["inspect", containerName]);
  if (
    inspect.status !== 0 &&
    !/^error: no such object:|^error response from daemon: no such container:/im.test(
      inspect.stderr,
    )
  ) {
    failures.push(
      `container absence could not be established: ${inspect.stderr.trim() || inspect.stdout.trim()}`,
    );
  }
  report.cleanup.containerRemoved =
    inspect.status !== 0 && failures.length === 0;
  try {
    rmSync(workingDirectory, { recursive: true, force: true });
  } catch (error) {
    failures.push(String(error instanceof Error ? error.message : error));
  }
  report.cleanup.temporaryDirectoryRemoved = !existsSync(workingDirectory);
  return failures;
}

function finalize() {
  if (finalized) return;
  finalized = true;
  if (failure) {
    try {
      collectDiagnostics();
    } catch (diagnosticError) {
      failure = new Error(
        `${message(failure)}; diagnostics failed: ${message(diagnosticError)}`,
      );
    }
  }
  const cleanupFailures = cleanup();
  if (cleanupFailures.length > 0) {
    failure = new Error(
      `${failure ? `${message(failure)}; ` : ""}G5_CLEANUP_DENIED ${cleanupFailures.join("; ")}`,
    );
  }
  report.pass = !failure;
  if (failure) report.failure = message(failure).slice(0, 8192);
  report.completedAt = new Date().toISOString();
  report.durationMs = Date.now() - startedAt;
  if (report.pass) rmSync(diagnosticsPath, { force: true });
  try {
    writeReport(report.pass);
  } catch (error) {
    failure = error;
    report.pass = false;
    report.failure = message(error).slice(0, 8192);
    try {
      writeReport(false);
    } catch {
      // The original evidence-write failure is reported on stderr below.
    }
  }
}

function writeReport(validate) {
  const parent = path.dirname(reportPath);
  if (!existsSync(parent)) {
    throw new Error(
      `G5_OUTPUT_DENIED output directory '${parent}' is missing.`,
    );
  }
  assertSafeOutputPath(reportPath);
  report.checks.sort((left, right) => left.id.localeCompare(right.id));
  report.controllerImages.sort(controllerImageOrder);
  const withoutDigest = structuredClone(report);
  delete withoutDigest.reportDigest;
  report.reportDigest = sha256(canonicalJson(withoutDigest));
  if (validate) validateReport(report);
  const temporaryReport = `${reportPath}.${runId}.tmp`;
  writeFileSync(temporaryReport, `${JSON.stringify(report, null, 2)}\n`, {
    mode: 0o600,
    flag: "wx",
  });
  try {
    renameSync(temporaryReport, reportPath);
  } finally {
    rmSync(temporaryReport, { force: true });
  }
}

function safeOutputPath(value) {
  const candidate = path.resolve(root, value);
  const relative = path.relative(root, candidate);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error(
      `G5_OUTPUT_DENIED output path escapes the repository: '${candidate}'.`,
    );
  }
  assertSafeOutputPath(candidate);
  return candidate;
}

function assertSafeOutputPath(candidate) {
  const parent = path.dirname(candidate);
  const relativeParent = path.relative(root, parent);
  let current = root;
  for (const segment of relativeParent.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    if (!existsSync(current)) break;
    const stat = lstatSync(current);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error(
        `G5_OUTPUT_DENIED output parent must be a real directory: '${current}'.`,
      );
    }
  }
  if (existsSync(candidate)) {
    const stat = lstatSync(candidate);
    if (stat.isSymbolicLink() || !stat.isFile()) {
      throw new Error(
        `G5_OUTPUT_DENIED output must be a regular non-symlink file: '${candidate}'.`,
      );
    }
  }
}

function validateReport(value) {
  const schema = fixture(
    "schemas/disposable-cluster-validation-v1.schema.json",
  );
  const ajv = new Ajv2020({
    allErrors: true,
    allowUnionTypes: false,
    strict: true,
    validateFormats: true,
  });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  if (!validate(value)) {
    throw new Error(
      `G5_EVIDENCE_SCHEMA_DENIED ${JSON.stringify(validate.errors)}`,
    );
  }
}

function pass(id, detail = {}) {
  if (report.checks.some((entry) => entry.id === id)) {
    throw new Error(`G5_CHECK_DENIED duplicate check '${id}'.`);
  }
  report.checks.push({ id, pass: true, ...detail });
}

function run(command, args, input, extraEnv = {}) {
  const result = runOptional(command, args, input, extraEnv);
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      `G5_COMMAND_FAILED ${command} ${args.join(" ")} (${result.status}): ${result.stderr.trim() || result.stdout.trim()}`,
    );
  }
  return result;
}

function runOptional(command, args, input, extraEnv = {}) {
  return spawnSync(command, args, {
    cwd: process.cwd(),
    encoding: "utf8",
    input,
    maxBuffer: 16 * 1024 * 1024,
    timeout: 6 * 60 * 1000,
    env: { ...process.env, ...extraEnv },
  });
}

function fixture(file) {
  return JSON.parse(readFileSync(file, "utf8"));
}

function fileDigest(file) {
  return sha256(readFileSync(file));
}

function sourceState() {
  const revision = run("git", ["rev-parse", "HEAD"]).stdout.trim();
  if (!/^[a-f0-9]{40}$/.test(revision)) {
    throw new Error("G5_SOURCE_DENIED Git did not return a full revision.");
  }
  const dirty =
    run("git", ["status", "--porcelain", "--untracked-files=all"]).stdout.trim()
      .length > 0;
  return { revision, dirty };
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function parseArguments(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 1) {
    const flag = values[index];
    if (flag !== "--output")
      throw new Error(`G5_CLI_DENIED unknown '${flag}'.`);
    if (parsed.output !== undefined) {
      throw new Error("G5_CLI_DENIED duplicate --output.");
    }
    const value = values[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error("G5_CLI_DENIED --output requires a path.");
    }
    parsed.output = value;
    index += 1;
  }
  return parsed;
}

function message(error) {
  return String(error instanceof Error ? error.message : error);
}
