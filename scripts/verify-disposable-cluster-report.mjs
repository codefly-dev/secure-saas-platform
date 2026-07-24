#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const EXPECTED_CHECKS = Object.freeze(
  [
    "database-bootstrap-controller-owner-shape-positive",
    "database-bootstrap-cross-namespace-affinity-denied",
    "database-bootstrap-cross-namespace-nodepool-denied",
    "database-bootstrap-cross-namespace-toleration-denied",
    "database-bootstrap-ownerless-pod-denied",
    "database-bootstrap-parent-admission-positive",
    "database-bootstrap-wrong-kind-denied",
    "database-controller-forbidden-kind-denied",
    "database-controller-delete-rbac-denied",
    "database-controller-native-exact-delete-denied",
    "database-controller-native-out-of-scope-delete-denied",
    "database-controller-namespace-create-positive",
    "database-controller-namespace-scope-denied",
    "database-controller-policy-mutation-rbac-denied",
    "database-controller-rbac-negative",
    "database-controller-rbac-positive",
    "database-controller-serviceaccount-positive",
    "database-controller-serviceaccount-scope-denied",
    "database-controller-wrong-actor-denied",
    "database-migration-controller-owner-shape-positive",
    "database-migration-cross-namespace-affinity-denied",
    "database-migration-cross-namespace-nodepool-denied",
    "database-migration-cross-namespace-toleration-denied",
    "database-migration-ownerless-pod-denied",
    "database-migration-parent-admission-positive",
    "database-migration-wrong-kind-denied",
    "database-runtime-controller-owner-shape-positive",
    "database-runtime-custom-scheduler-denied",
    "database-runtime-direct-replicaset-denied",
    "database-runtime-forged-owner-actor-denied",
    "database-runtime-native-statefulset-denied",
    "database-runtime-cross-namespace-affinity-denied",
    "database-runtime-cross-namespace-nodepool-denied",
    "database-runtime-cross-namespace-toleration-denied",
    "database-runtime-direct-node-binding-denied",
    "database-runtime-ownerless-pod-denied",
    "database-runtime-parent-admission-positive",
    "database-runtime-wrong-kind-denied",
    "database-runtime-wrong-owner-denied",
    "cloud-token-audience-substitution",
    "cloud-token-binding-positive",
    "cloud-token-digest-substitution",
    "eks-pod-identity-digest-substitution",
    "eks-pod-identity-expiration-substitution",
    "eks-pod-identity-mode-substitution",
    "eks-pod-identity-path-substitution",
    "eks-pod-identity-token-positive",
    "kubernetes-api-token-projection",
    "kyverno-failure-policy-webhook-configured",
    "protected-admission-denied-during-kyverno-outage",
    "local-docker-endpoint",
    "local-fixture-image-imported",
    "pinned-local-images",
    "pinned-real-kyverno",
    "pod-automount-omitted",
    "restricted-default-serviceaccounts-applied",
    "runtime-token-absent-and-api-authentication-denied",
    "secret-volume",
    "service-account-automount",
    "token-policy-denial-matrix",
    "unique-ready-cluster",
  ].sort(),
);

const EXPECTED_DENIALS = Object.freeze([
  [
    "database-runtime-direct-replicaset-denied",
    "SEC_DATABASE_CHILD_ACTOR_DENIED",
    "require-database-replicaset-controller-identity",
  ],
  [
    "database-runtime-forged-owner-actor-denied",
    "SEC_DATABASE_POD_ACTOR_DENIED",
    "require-database-pod-controller-identity",
  ],
  [
    "database-runtime-custom-scheduler-denied",
    "SEC_DATABASE_CUSTOM_SCHEDULER_DENIED",
    "database-pods-default-scheduler-only",
  ],
  [
    "database-controller-wrong-actor-denied",
    "SEC_DATABASE_CONTROLLER_IDENTITY_DENIED",
    "database-controller-native-ownership",
  ],
  [
    "database-controller-namespace-scope-denied",
    "SEC_DATABASE_CONTROLLER_SCOPE_DENIED",
    "database-controller-native-scope",
  ],
  [
    "database-controller-serviceaccount-scope-denied",
    "SEC_DATABASE_CONTROLLER_SCOPE_DENIED",
    "database-controller-native-scope",
  ],
  [
    "database-controller-forbidden-kind-denied",
    "SEC_DATABASE_CONTROLLER_KIND_DENIED",
    "database-controller-forbidden-kinds",
  ],
  [
    "database-controller-native-exact-delete-denied",
    "SEC_DATABASE_CONTROLLER_DELETE_DENIED",
    "database-controller-native-scope",
  ],
  [
    "database-controller-native-out-of-scope-delete-denied",
    "SEC_DATABASE_CONTROLLER_DELETE_DENIED",
    "database-controller-native-scope",
  ],
  ...["runtime", "migration", "bootstrap"].flatMap((accessClass) => [
    [
      `database-${accessClass}-cross-namespace-nodepool-denied`,
      "SEC_DATABASE_NODE_POOL_RESERVED",
      "reserve-database-node-pool",
    ],
    [
      `database-${accessClass}-ownerless-pod-denied`,
      "SEC_DATABASE_POD_OWNER_DENIED",
      "require-database-pod-controller-owner",
    ],
    ...["affinity", "toleration"].map((route) => [
      `database-${accessClass}-cross-namespace-${route}-denied`,
      "SEC_DATABASE_NODE_POOL_RESERVED",
      "reserve-database-node-pool",
    ]),
  ]),
  [
    "database-runtime-native-statefulset-denied",
    "SEC_DATABASE_WORKLOAD_KIND_DENIED",
    "database-workload-native-boundary",
  ],
  [
    "database-runtime-direct-node-binding-denied",
    "SEC_DATABASE_NODE_NAME_DENIED",
    "deny-direct-node-binding",
  ],
  [
    "database-runtime-wrong-owner-denied",
    "SEC_DATABASE_POD_OWNER_DENIED",
    "require-database-pod-controller-owner",
  ],
  ...["runtime", "migration", "bootstrap"].map((accessClass) => [
    `database-${accessClass}-wrong-kind-denied`,
    "SEC_DATABASE_WORKLOAD_KIND_DENIED",
    "restrict-database-workload-kind",
  ]),
  [
    "service-account-automount",
    "SEC_TOKEN_AUTOMOUNT_DENIED",
    "serviceaccount-automount-must-be-false",
  ],
  [
    "pod-automount-omitted",
    "SEC_TOKEN_AUTOMOUNT_DENIED",
    "pod-automount-must-be-false",
  ],
  [
    "kubernetes-api-token-projection",
    "SEC_TOKEN_PROJECTION_DENIED",
    "kubernetes-api-token-projection-forbidden",
  ],
  [
    "cloud-token-audience-substitution",
    "SEC_CLOUD_TOKEN_BINDING_DENIED",
    "projected-cloud-token-must-match-infrastructure-owned-identity",
  ],
  [
    "cloud-token-digest-substitution",
    "SEC_CLOUD_TOKEN_BINDING_DENIED",
    "projected-cloud-token-must-match-infrastructure-owned-identity",
  ],
  [
    "eks-pod-identity-expiration-substitution",
    "SEC_EKS_POD_IDENTITY_DENIED",
    "eks-pod-identity-token-must-match-association",
  ],
  [
    "eks-pod-identity-path-substitution",
    "SEC_EKS_POD_IDENTITY_DENIED",
    "eks-pod-identity-token-must-match-association",
  ],
  [
    "eks-pod-identity-mode-substitution",
    "SEC_EKS_POD_IDENTITY_DENIED",
    "eks-pod-identity-token-must-match-association",
  ],
  [
    "eks-pod-identity-digest-substitution",
    "SEC_EKS_POD_IDENTITY_DENIED",
    "eks-pod-identity-token-must-match-association",
  ],
  ["secret-volume", "SEC_SECRET_VOLUME_DENIED", "secret-volumes-forbidden"],
]);

const EXPECTED_INPUT_PATHS = Object.freeze(
  [
    "gitops/base/kyverno/deny-service-account-tokens.yaml",
    "gitops/base/kyverno/authorize-database-infrastructure-controller.yaml",
    "gitops/base/kyverno/database-controller-native-admission.yaml",
    "gitops/base/kyverno/database-native-admission.yaml",
    "gitops/base/kyverno/workload-native-admission.yaml",
    "gitops/base/namespaces/restricted-default-serviceaccounts.yaml",
    "dist/databaseAccess.js",
    "schemas/disposable-cluster-validation-v1.schema.json",
    "scripts/validate-disposable-cluster.mjs",
    "scripts/verify-disposable-cluster-report.mjs",
    "src/databaseAccess.ts",
  ].sort(),
);

const EXPECTED_CONTROLLER_IMAGES = Object.freeze(
  [
    [
      "admission-controller",
      "kyverno",
      "reg.kyverno.io/kyverno/kyverno:v1.17.0",
      "reg.kyverno.io/kyverno/kyverno@sha256:ff2ca78b0703c1bcce7f22576f4e3e90d1dd17e710475dc88f3b7f10fc9f019d",
    ],
    [
      "admission-controller",
      "kyverno-pre",
      "reg.kyverno.io/kyverno/kyvernopre:v1.17.0",
      "reg.kyverno.io/kyverno/kyvernopre@sha256:0b21526834219a8d7d0123632ab4308106444049cee4be7a46cbf209c21e11bb",
    ],
    [
      "background-controller",
      "controller",
      "reg.kyverno.io/kyverno/background-controller:v1.17.0",
      "reg.kyverno.io/kyverno/background-controller@sha256:a38173ad69f0ad02779a6b20d40253a35608aac922d7d3ac39ac8d26f8382ca4",
    ],
    [
      "cleanup-controller",
      "controller",
      "reg.kyverno.io/kyverno/cleanup-controller:v1.17.0",
      "reg.kyverno.io/kyverno/cleanup-controller@sha256:01af176e0af8f1b1f3388a8223ba3e6e19ed02517444df20b5e1e27e6ffa7c66",
    ],
    [
      "reports-controller",
      "controller",
      "reg.kyverno.io/kyverno/reports-controller:v1.17.0",
      "reg.kyverno.io/kyverno/reports-controller@sha256:d5d0358e658b9d1b90954bf666f457bd6af5db36209e9ba792c182f212a11c0b",
    ],
  ].sort(tupleOrder),
);

const EXPECTED_K3S_IMAGE =
  "rancher/k3s@sha256:f17e43023cce2b9c613e198f26e73637bf734b5156d37c9f44819d97bac4d655";
const EXPECTED_FIXTURE_IMAGE =
  "alpine@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40";
const EXPECTED_CHART = Object.freeze({
  version: "3.7.0",
  digest: "7a94960c75c8faa9a2bbf7a2c39f6deeb7ff0b8814a8c17cee9a0816f8f69874",
});
const EXPECTED_SCOPE = Object.freeze({
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
});

const root = realpathSync(
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."),
);
const args = parseArguments(process.argv.slice(2));
if (args.printExpectations) {
  printExpectations();
  process.exit(0);
}
const reportPath = safeFile(
  args.report ?? "artifacts/disposable-cluster-validation.json",
  "disposable-cluster report",
);
const schemaPath = safeFile(
  "schemas/disposable-cluster-validation-v1.schema.json",
  "disposable-cluster schema",
);
const report = parseJson(readFileSync(reportPath, "utf8"), reportPath);
const schema = parseJson(readFileSync(schemaPath, "utf8"), schemaPath);

validateSchema(report, schema);
verifyDigest(report);
verifyTime(report, !args.boundByQualifiedCandidate);
verifySource(report, Boolean(args.requireClean));
verifyInputs(report);
verifyChecks(report);
verifyControllerImages(report);

process.stdout.write(
  `Verified disposable-cluster report ${path.relative(root, reportPath)} (${report.checks.length} exact checks).\n`,
);

function validateSchema(value, schemaValue) {
  const ajv = new Ajv2020({
    allErrors: true,
    allowUnionTypes: false,
    strict: true,
    validateFormats: true,
  });
  addFormats(ajv);
  const validate = ajv.compile(schemaValue);
  if (!validate(value)) {
    fail(
      `report schema validation failed:\n${(validate.errors ?? [])
        .map((error) => `- ${error.instancePath || "/"} ${error.message}`)
        .sort()
        .join("\n")}`,
    );
  }
}

function verifyDigest(value) {
  const { reportDigest, ...subject } = value;
  if (reportDigest !== sha256(canonicalJson(subject))) {
    fail("reportDigest does not bind the canonical report body.");
  }
}

function verifyTime(value, requireFresh) {
  const started = Date.parse(value.generatedAt);
  const completed = Date.parse(value.completedAt);
  const now = Date.now();
  if (completed < started) fail("completedAt precedes generatedAt.");
  if (Math.abs(completed - started - value.durationMs) > 5000) {
    fail("durationMs is inconsistent with generatedAt/completedAt.");
  }
  if (requireFresh && completed < now - 15 * 60 * 1000) {
    fail("disposable-cluster report is stale (maximum age is 15 minutes).");
  }
  if (completed > now + 60 * 1000) {
    fail("disposable-cluster report completion is in the future.");
  }
}

function verifySource(value, requireClean) {
  const revision = git(["rev-parse", "HEAD"]);
  const dirty =
    git(["status", "--porcelain", "--untracked-files=all"]).length > 0;
  if (value.source.revision !== revision || value.source.dirty !== dirty) {
    fail("report source revision/dirty state does not match this checkout.");
  }
  if (requireClean && dirty)
    fail("--require-clean was set on a dirty checkout.");
}

function verifyInputs(value) {
  const repositoryInputs = Object.entries(value.inputs)
    .filter(
      ([name, digest]) =>
        name.includes("/") &&
        typeof digest === "string" &&
        /^[a-f0-9]{64}$/.test(digest),
    )
    .map(([name]) => name)
    .sort();
  assertExact(repositoryInputs, EXPECTED_INPUT_PATHS, "repository input paths");
  for (const inputPath of EXPECTED_INPUT_PATHS) {
    const input = safeFile(inputPath, "bound repository input");
    if (value.inputs[inputPath] !== sha256(readFileSync(input))) {
      fail(`bound input digest does not match '${inputPath}'.`);
    }
  }
  if (
    value.inputs.k3sImage !== EXPECTED_K3S_IMAGE ||
    value.inputs.fixtureImage !== EXPECTED_FIXTURE_IMAGE ||
    canonicalJson(value.inputs.kyvernoChart) !== canonicalJson(EXPECTED_CHART)
  ) {
    fail("pinned K3s, fixture, or Kyverno chart input was substituted.");
  }
}

function verifyChecks(value) {
  const ids = value.checks.map((entry) => entry.id).sort();
  assertExact(ids, EXPECTED_CHECKS, "check inventory");
  const denials = new Map(
    value.checks
      .filter((entry) => entry.denialCode !== undefined)
      .map((entry) => [entry.id, entry]),
  );
  for (const [id, denialCode, rule] of EXPECTED_DENIALS) {
    const actual = denials.get(id);
    if (actual?.denialCode !== denialCode || actual?.rule !== rule) {
      fail(`denial '${id}' does not match ${denialCode}/${rule}.`);
    }
  }
  if (denials.size !== EXPECTED_DENIALS.length) {
    fail("denial inventory contains missing or unexpected entries.");
  }
}

function verifyControllerImages(value) {
  const actual = value.controllerImages
    .map((entry) => [
      entry.component,
      entry.container,
      entry.image,
      entry.imageId,
    ])
    .sort(tupleOrder);
  if (canonicalJson(actual) !== canonicalJson(EXPECTED_CONTROLLER_IMAGES)) {
    fail("observed Kyverno controller image inventory was substituted.");
  }
}

function printExpectations() {
  const denials = new Map(
    EXPECTED_DENIALS.map(([id, denialCode, rule]) => [
      id,
      { denialCode, rule },
    ]),
  );
  process.stdout.write(
    `${JSON.stringify(
      {
        scope: EXPECTED_SCOPE,
        checks: EXPECTED_CHECKS.map((id) => ({
          id,
          pass: true,
          ...(denials.get(id) ?? {}),
        })),
        inputPaths: EXPECTED_INPUT_PATHS,
        k3sImage: EXPECTED_K3S_IMAGE,
        fixtureImage: EXPECTED_FIXTURE_IMAGE,
        kyvernoChart: EXPECTED_CHART,
        controllerImages: EXPECTED_CONTROLLER_IMAGES.map(
          ([component, container, image, imageId]) => ({
            component,
            container,
            image,
            imageId,
          }),
        ),
      },
      null,
      2,
    )}\n`,
  );
}

function safeFile(value, label) {
  const candidate = path.resolve(root, value);
  const relative = path.relative(root, candidate);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    fail(`${label} escapes the repository: ${candidate}`);
  }
  const stat = lstatSync(candidate);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail(`${label} must be a regular non-symlink file: ${candidate}`);
  }
  return realpathSync(candidate);
}

function git(arguments_) {
  const result = spawnSync("git", arguments_, {
    cwd: root,
    encoding: "utf8",
  });
  if (result.status !== 0) fail(result.stderr || "git command failed.");
  return result.stdout.trim();
}

function parseJson(source, file) {
  try {
    return JSON.parse(source);
  } catch (error) {
    fail(`${file} is not valid JSON: ${error.message}`);
  }
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

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function assertExact(actual, expected, label) {
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail(`${label} does not match the required exact inventory.`);
  }
}

function tupleOrder(left, right) {
  return `${left[0]}/${left[1]}`.localeCompare(`${right[0]}/${right[1]}`);
}

function parseArguments(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 1) {
    const token = values[index];
    if (token === "--print-expectations") {
      if (parsed.printExpectations) fail("duplicate --print-expectations.");
      if (values.length !== 1)
        fail("--print-expectations cannot be combined with other arguments.");
      parsed.printExpectations = true;
      continue;
    }
    if (token === "--require-clean") {
      if (parsed.requireClean) fail("duplicate --require-clean.");
      parsed.requireClean = true;
      continue;
    }
    if (token === "--bound-by-qualified-candidate") {
      if (parsed.boundByQualifiedCandidate)
        fail("duplicate --bound-by-qualified-candidate.");
      parsed.boundByQualifiedCandidate = true;
      continue;
    }
    if (token !== "--report") fail(`unknown argument '${token}'.`);
    if (parsed.report !== undefined) fail("duplicate --report.");
    const value = values[index + 1];
    if (!value || value.startsWith("--")) fail("--report requires a path.");
    parsed.report = value;
    index += 1;
  }
  return parsed;
}

function fail(message) {
  process.stderr.write(`verify-disposable-cluster-report: ${message}\n`);
  process.exit(1);
}
