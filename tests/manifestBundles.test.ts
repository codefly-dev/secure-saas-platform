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
const bundleDirectory = path.join(liveRoot, "development/saas-starter/web");

test("the live landed inventory conforms to the bundle contract schema", () => {
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  const validate = ajv.compile(
    JSON.parse(
      readFileSync(
        "schemas/codefly-manifest-bundle-inventory-v1.schema.json",
        "utf8",
      ),
    ),
  );
  const inventory = JSON.parse(
    readFileSync(path.join(liveRoot, "inventory.json"), "utf8"),
  );
  assert.equal(validate(inventory), true, JSON.stringify(validate.errors));
  for (const bundle of inventory.bundles) {
    assert.equal(bundle.bundleDigest, digestOf(bundle.path));
  }
});

test("a validated bundle lands without any reconciliation authority", () => {
  const result = validateBundles(liveRoot);
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const manifests = readdirSync(bundleDirectory)
    .map((file) => readFileSync(path.join(bundleDirectory, file), "utf8"))
    .join("\n");
  assert.doesNotMatch(manifests, /argoproj\.io/);
  assert.doesNotMatch(manifests, /repoURL|targetRevision|sourceRepos/);
});

test("the landing contract rejects plugin-owned control-plane and provenance drift", () => {
  const cases: Array<[string, (root: string) => void, RegExp]> = [
    [
      "plugin-owned Argo Application",
      (root) =>
        writeFileSync(
          path.join(root, "development/saas-starter/web/application.yaml"),
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
      /owns Argo CD Application/,
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
        writeFileSync(
          path.join(root, "development/saas-starter/web/repo-secret.yaml"),
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
      "stale inventory after a manifest change",
      (root) =>
        appendToDeployment(root, "  # drift beyond the recorded digest\n"),
      /digest does not match the landed manifests/,
    ],
    [
      "cross-path landing that overruns its identity",
      (root) => {
        const inventoryPath = path.join(root, "inventory.json");
        const inventory = JSON.parse(readFileSync(inventoryPath, "utf8"));
        inventory.bundles[0].path =
          "gitops/generated/modules/development/saas-starter/api";
        writeFileSync(inventoryPath, `${JSON.stringify(inventory, null, 2)}\n`);
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
        const inventoryPath = path.join(root, "inventory.json");
        const inventory = JSON.parse(readFileSync(inventoryPath, "utf8"));
        inventory.bundles.push({
          ...inventory.bundles[0],
          sourceRevision: "a".repeat(40),
        });
        writeFileSync(inventoryPath, `${JSON.stringify(inventory, null, 2)}\n`);
      },
      /bundles overlap on landing path/,
    ],
    [
      "mutable source revision",
      (root) => {
        const inventoryPath = path.join(root, "inventory.json");
        const inventory = JSON.parse(readFileSync(inventoryPath, "utf8"));
        inventory.bundles[0].sourceRevision = "main";
        writeFileSync(inventoryPath, `${JSON.stringify(inventory, null, 2)}\n`);
      },
      /inventory schema validation failed/,
    ],
  ];

  for (const [label, mutate, expected] of cases) {
    const directory = mkdtempSync(path.join(os.tmpdir(), "manifest-bundle-"));
    const root = path.join(directory, "modules");
    try {
      cpSync(liveRoot, root, { recursive: true });
      mutate(root);
      const result = validateBundles(root);
      assert.notEqual(result.status, 0, label);
      assert.match(`${result.stdout}\n${result.stderr}`, expected, label);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
});

function validateBundles(root: string) {
  return spawnSync(
    process.execPath,
    ["scripts/validate-manifest-bundles.mjs", "--modules-root", root],
    { cwd: process.cwd(), encoding: "utf8" },
  );
}

function appendToDeployment(root: string, addition: string) {
  const file = path.join(root, "development/saas-starter/web/deployment.yaml");
  writeFileSync(file, `${readFileSync(file, "utf8")}${addition}`);
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

function sha256(value: Buffer | string): string {
  return createHash("sha256").update(value).digest("hex");
}
