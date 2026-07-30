import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import Ajv2020 from "ajv/dist/2020.js";

const liveRoot = "gitops/generated/modules";
const fixtureRoot = "fixtures/manifest-bundles/valid";
const bundleRelative = "development/saas-starter/web";
const bundleDirectory = path.join(fixtureRoot, bundleRelative);

test("the live landing tree is empty and schema-valid before a real promotion", () => {
  const inventory = validateInventory(liveRoot);
  assert.deepEqual(inventory.bundles, []);
  assert.deepEqual(listRelativeFiles(liveRoot).sort(), [
    "README.md",
    "inventory.json",
  ]);
  const result = validateBundles(liveRoot);
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
});

test("a fixture bundle lands without reconciliation authority", () => {
  const inventory = validateInventory(fixtureRoot);
  assert.equal(inventory.bundles.length, 1);
  assert.equal(inventory.bundles[0].bundleDigest, digestOf(bundleDirectory));
  const result = validateBundles(fixtureRoot);
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const manifests = readdirSync(bundleDirectory)
    .map((file) => readFileSync(path.join(bundleDirectory, file), "utf8"))
    .join("\n");
  assert.doesNotMatch(manifests, /argoproj\.io/);
  assert.doesNotMatch(manifests, /repoURL|targetRevision|sourceRepos/);
});

test("one inventory supports multiple environments and producers", () => {
  withFixture((root) => {
    addBundle(root, {
      environment: "staging",
      module: "other-module",
      service: "api",
      producer: {
        identity: "codefly-dev/service-go",
        contractVersion: "manifest.codefly.dev/service-bundle/v2",
      },
      manifest:
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: other-api\n  namespace: workloads\n",
    });
    const result = validateBundles(root);
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /development, staging/);
  });
});

test("the landing contract rejects control-plane, credential, ownership, and provenance drift", () => {
  const cases: Array<[string, (root: string) => void, RegExp]> = [
    [
      "plugin-owned Argo Application",
      (root) =>
        writeBundleFile(
          root,
          "application.yaml",
          [
            "apiVersion: argoproj.io/v1alpha1",
            "kind: Application",
            "metadata:",
            "  name: saas-starter-web",
            "spec:",
            "  source:",
            "    repoURL: https://github.com/codefly-dev/secure-saas-platform.git",
            "    targetRevision: main",
            "",
          ].join("\n"),
        ),
      /owns argoproj\.io Application/,
    ],
    [
      "plugin-owned Flux source",
      (root) =>
        writeBundleFile(
          root,
          "source.yaml",
          "apiVersion: source.toolkit.fluxcd.io/v1\nkind: GitRepository\nmetadata:\n  name: rogue\n",
        ),
      /owns source\.toolkit\.fluxcd\.io GitRepository/,
    ],
    [
      "plugin-owned Git source binding",
      (root) =>
        appendToDeployment(
          root,
          "  repoURL: https://github.com/codefly-dev/secure-saas-platform.git\n",
        ),
      /declares Git source binding 'repoURL'/,
    ],
    [
      "plugin-owned repository credential Secret",
      (root) =>
        writeBundleFile(
          root,
          "repo-secret.yaml",
          [
            "apiVersion: v1",
            "kind: Secret",
            "metadata:",
            "  name: repo-credentials",
            "stringData:",
            "  password: hunter2",
            "",
          ].join("\n"),
        ),
      /owns a Secret/,
    ],
    [
      "credential-bearing ConfigMap key",
      (root) =>
        writeBundleFile(
          root,
          "credential.yaml",
          `apiVersion: v1
kind: ConfigMap
metadata:
  name: leaked
  namespace: workloads
data:
  AWS_SECRET_ACCESS_KEY: ${"AKIA"}${"1234567890123456"}
`,
        ),
      /credential-bearing key 'AWS_SECRET_ACCESS_KEY'/,
    ],
    [
      "URL credentials hidden in a value",
      (root) =>
        writeBundleFile(
          root,
          "credential-url.yaml",
          "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: leaked-url\n  namespace: workloads\ndata:\n  DATABASE_URL: https://user:password@example.invalid/database\n",
        ),
      /contains URL credentials/,
    ],
    [
      "stale inventory after a manifest change",
      (root) =>
        appendToDeployment(root, "  # drift beyond the recorded digest\n"),
      /digest does not match the landed manifests/,
    ],
    [
      "cross-path landing that overruns its identity",
      (root) => {
        const inventory = readInventory(root);
        inventory.bundles[0].path =
          "gitops/generated/modules/development/saas-starter/api";
        writeInventory(root, inventory);
      },
      /does not match its declared environment and module\/service identity/,
    ],
    [
      "undeclared cross-path write",
      (root) => {
        mkdirSync(path.join(root, "development/other-module/api"), {
          recursive: true,
        });
        writeFileSync(
          path.join(root, "development/other-module/api/rogue.yaml"),
          "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: rogue\n",
        );
      },
      /outside every inventoried bundle path/,
    ],
    [
      "duplicated landing path ownership",
      (root) => {
        const inventory = readInventory(root);
        inventory.bundles.push({
          ...inventory.bundles[0],
          sourceRevision: "a".repeat(40),
        });
        writeInventory(root, inventory);
      },
      /bundles overlap on landing path/,
    ],
    [
      "duplicated Kubernetes object ownership",
      (root) => {
        addBundle(root, {
          environment: "development",
          module: "other-module",
          service: "api",
          producer: {
            identity: "codefly-dev/service-go",
            contractVersion: "manifest.codefly.dev/service-bundle/v1",
          },
          manifest: readFileSync(
            path.join(root, bundleRelative, "deployment.yaml"),
            "utf8",
          ),
        });
      },
      /is owned by both/,
    ],
    [
      "mutable source revision",
      (root) => {
        const inventory = readInventory(root);
        inventory.bundles[0].sourceRevision = "main";
        writeInventory(root, inventory);
      },
      /inventory schema validation failed/,
    ],
    [
      "empty YAML document",
      (root) => writeBundleFile(root, "empty.yaml", "# no resource\n"),
      /contains no Kubernetes resources/,
    ],
  ];

  for (const [label, mutate, expected] of cases) {
    withFixture((root) => {
      mutate(root);
      const result = validateBundles(root);
      assert.notEqual(result.status, 0, label);
      assert.match(`${result.stdout}\n${result.stderr}`, expected, label);
    });
  }
});

function validateInventory(root: string): any {
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  const validate = ajv.compile(
    JSON.parse(
      readFileSync(
        "schemas/codefly-manifest-bundle-inventory-v1.schema.json",
        "utf8",
      ),
    ),
  );
  const inventory = readInventory(root);
  assert.equal(validate(inventory), true, JSON.stringify(validate.errors));
  return inventory;
}

function withFixture(action: (root: string) => void): void {
  const directory = mkdtempSync(path.join(os.tmpdir(), "manifest-bundle-"));
  const root = path.join(directory, "modules");
  try {
    cpSync(fixtureRoot, root, { recursive: true });
    action(root);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function addBundle(
  root: string,
  input: {
    environment: string;
    module: string;
    service: string;
    producer: { identity: string; contractVersion: string };
    manifest: string;
  },
): void {
  const relative = `${input.environment}/${input.module}/${input.service}`;
  const directory = path.join(root, relative);
  mkdirSync(directory, { recursive: true });
  writeFileSync(path.join(directory, "manifest.yaml"), input.manifest);
  const inventory = readInventory(root);
  inventory.bundles.push({
    environment: input.environment,
    module: input.module,
    service: input.service,
    path: `gitops/generated/modules/${relative}`,
    producer: input.producer,
    bundleDigest: digestOf(directory),
    sourceRevision: "b".repeat(40),
  });
  writeInventory(root, inventory);
}

function validateBundles(root: string) {
  return spawnSync(
    process.execPath,
    ["scripts/validate-manifest-bundles.mjs", "--modules-root", root],
    { cwd: process.cwd(), encoding: "utf8" },
  );
}

function writeBundleFile(root: string, name: string, contents: string): void {
  writeFileSync(path.join(root, bundleRelative, name), contents);
}

function appendToDeployment(root: string, addition: string): void {
  const file = path.join(root, bundleRelative, "deployment.yaml");
  writeFileSync(file, `${readFileSync(file, "utf8")}${addition}`);
}

function readInventory(root: string): any {
  return JSON.parse(readFileSync(path.join(root, "inventory.json"), "utf8"));
}

function writeInventory(root: string, inventory: any): void {
  writeFileSync(
    path.join(root, "inventory.json"),
    `${JSON.stringify(inventory, null, 2)}\n`,
  );
}

function digestOf(directory: string): string {
  const files = readdirSync(directory).sort();
  const manifest = files
    .map((file) => {
      const content = sha256(readFileSync(path.join(directory, file)));
      return `${file} ${content}`;
    })
    .join("\n");
  return sha256(manifest);
}

function listRelativeFiles(directory: string, prefix = ""): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const relative = path.join(prefix, entry.name);
    return entry.isDirectory()
      ? listRelativeFiles(path.join(directory, entry.name), relative)
      : [relative];
  });
}

function sha256(value: Buffer | string): string {
  return createHash("sha256").update(value).digest("hex");
}
