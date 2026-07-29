#!/usr/bin/env node

import { lstatSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import { parseAllDocuments } from "yaml";
import { sha256 } from "./platform-handoff.mjs";

const forbiddenSourceKeys = [
  "repoURL",
  "targetRevision",
  "sourceRepos",
  "repositories",
];
const credentialKey =
  /(?:password|private.?key|client.?secret|access.?token|refresh.?token|credential)$/i;

const schemaPath = path.resolve(
  path.dirname(new URL(import.meta.url).pathname),
  "../schemas/codefly-manifest-bundle-inventory-v1.schema.json",
);

const modulesRoot = argument("--modules-root") ?? "gitops/generated/modules";
const inventoryPath = path.join(modulesRoot, "inventory.json");

const inventory = parseJson(read(inventoryPath), inventoryPath);
validateSchema(inventory);

const declared = new Map();
for (const bundle of inventory.bundles) {
  const expectedPath = `gitops/generated/modules/${inventory.environment}/${bundle.module}/${bundle.service}`;
  if (bundle.path !== expectedPath) {
    fail(
      `bundle ${bundle.module}/${bundle.service} landing path '${bundle.path}' does not match its declared environment and module/service identity.`,
    );
  }
  if (declared.has(bundle.path)) {
    fail(`bundles overlap on landing path '${bundle.path}'.`);
  }
  declared.set(bundle.path, bundle);
}

const ownedDirectories = new Map();
for (const bundle of declared.values()) {
  const directory = resolveWithin(
    modulesRoot,
    `${inventory.environment}/${bundle.module}/${bundle.service}`,
  );
  ownedDirectories.set(directory, bundle);
  const files = listFiles(directory).sort();
  if (files.length === 0) {
    fail(`bundle '${bundle.path}' landed no manifests.`);
  }
  for (const file of files) {
    assertPluginOwned(path.join(directory, file), bundle.path);
  }
  const digest = bundleDigest(directory, files);
  if (digest !== bundle.bundleDigest) {
    fail(
      `bundle '${bundle.path}' digest does not match the landed manifests; the inventory is stale or the tree was tampered with.`,
    );
  }
}

for (const file of listFiles(modulesRoot)) {
  if (file === "inventory.json" || file === "README.md") continue;
  const absolute = path.resolve(modulesRoot, file);
  const owned = [...ownedDirectories.keys()].some((directory) =>
    absolute.startsWith(`${directory}${path.sep}`),
  );
  if (!owned) {
    fail(
      `landed file 'gitops/generated/modules/${file}' is outside every inventoried bundle path (undeclared cross-path write).`,
    );
  }
}

console.log(
  `Manifest bundle landing contract satisfied for ${inventory.environment}: ${inventory.bundles.length} inventoried bundle(s).`,
);

function bundleDigest(directory, files) {
  const manifest = files
    .map((file) => {
      const content = sha256(readFileSync(path.join(directory, file)));
      return `${file} ${content}`;
    })
    .join("\n");
  return sha256(manifest);
}

function validateSchema(document) {
  const ajv = new Ajv2020({
    allErrors: true,
    allowUnionTypes: false,
    strict: true,
  });
  const validate = ajv.compile(parseJson(read(schemaPath), schemaPath));
  if (!validate(document)) {
    fail(
      `inventory schema validation failed:\n${(validate.errors ?? [])
        .map((error) => `- ${error.instancePath || "/"} ${error.message}`)
        .join("\n")}`,
    );
  }
}

function assertPluginOwned(file, landingPath) {
  if (!/\.ya?ml$/.test(file)) {
    fail(`bundle '${landingPath}' contains a non-manifest file '${file}'.`);
  }
  const documents = parseAllDocuments(read(file));
  for (const document of documents) {
    if (document.errors.length > 0) {
      fail(`bundle manifest '${file}' is invalid YAML.`);
    }
    const resource = document.toJSON();
    if (resource === null || typeof resource !== "object") continue;
    const group = String(resource.apiVersion ?? "").split("/")[0];
    if (group === "argoproj.io") {
      fail(
        `bundle '${landingPath}' owns Argo CD ${resource.kind ?? "object"}; reconciliation authority belongs to the platform layer.`,
      );
    }
    if (resource.kind === "Secret") {
      fail(
        `bundle '${landingPath}' owns a Secret; repository and cluster credentials belong to the platform layer.`,
      );
    }
    assertNoReconciliationAuthority(resource, file);
  }
}

function assertNoReconciliationAuthority(value, file) {
  if (Array.isArray(value)) {
    for (const entry of value) assertNoReconciliationAuthority(entry, file);
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, entry] of Object.entries(value)) {
    if (forbiddenSourceKeys.includes(key)) {
      fail(
        `bundle manifest '${file}' declares Git source binding '${key}'; only the platform layer controls Git sources.`,
      );
    }
    if (credentialKey.test(key)) {
      fail(
        `bundle manifest '${file}' contains credential-bearing key '${key}'.`,
      );
    }
    assertNoReconciliationAuthority(entry, file);
  }
}

function listFiles(directory, prefix = "") {
  const entries = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isSymbolicLink()) {
      fail(
        `symlink '${path.join(prefix, entry.name)}' is not allowed in bundles.`,
      );
    }
    const relative = path.join(prefix, entry.name);
    if (entry.isDirectory()) {
      entries.push(...listFiles(path.join(directory, entry.name), relative));
    } else if (entry.isFile()) {
      entries.push(relative);
    }
  }
  return entries;
}

function resolveWithin(root, relative) {
  const resolvedRoot = path.resolve(root);
  const candidate = path.resolve(resolvedRoot, relative);
  if (
    candidate !== resolvedRoot &&
    !candidate.startsWith(`${resolvedRoot}${path.sep}`)
  ) {
    fail(`bundle path '${relative}' escapes the modules root.`);
  }
  const stat = lstatSync(candidate);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    fail(`bundle directory '${relative}' must be a regular directory.`);
  }
  return candidate;
}

function read(file) {
  return readFileSync(file, "utf8");
}

function parseJson(source, file) {
  try {
    return JSON.parse(source);
  } catch (error) {
    fail(`${file} is not valid JSON: ${error.message}`);
  }
}

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0) return undefined;
  const value = process.argv[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${name} requires a value.`);
  }
  return value;
}

function fail(message) {
  console.error(`MANIFEST_BUNDLE_INVALID ${message}`);
  process.exit(1);
}
