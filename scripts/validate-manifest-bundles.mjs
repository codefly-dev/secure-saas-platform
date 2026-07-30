#!/usr/bin/env node

import { lstatSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import { parseAllDocuments } from "yaml";
import { sha256 } from "./platform-handoff.mjs";

const forbiddenSourceKeys = new Set([
  "repoURL",
  "repositoryURL",
  "targetRevision",
  "sourceRepos",
  "repositories",
]);
const forbiddenControlPlaneGroups = new Set([
  "argoproj.io",
  "helm.toolkit.fluxcd.io",
  "kustomize.toolkit.fluxcd.io",
  "notification.toolkit.fluxcd.io",
  "source.toolkit.fluxcd.io",
]);
const credentialKey =
  /(?:^|[._-])(?:password|passwd|private[._-]?key|client[._-]?secret|secret[._-]?access[._-]?key|access[._-]?token|refresh[._-]?token|api[._-]?key|credentials?)(?:$|[._-])/i;
const privateKeyMaterial = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/;
const accessKeyMaterial = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/;
const commonTokenMaterial =
  /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/;
const manifestPath = /^[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)*\.ya?ml$/;

const schemaPath = fileURLToPath(
  new URL(
    "../schemas/codefly-manifest-bundle-inventory-v1.schema.json",
    import.meta.url,
  ),
);

const modulesRoot = argument("--modules-root") ?? "gitops/generated/modules";
const inventoryPath = path.join(modulesRoot, "inventory.json");

const inventory = parseJson(read(inventoryPath), inventoryPath);
validateSchema(inventory);

const declared = new Map();
for (const bundle of inventory.bundles) {
  const expectedPath = `gitops/generated/modules/${bundle.environment}/${bundle.module}/${bundle.service}`;
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
const resourceOwners = new Map();
for (const bundle of declared.values()) {
  const directory = resolveWithin(
    modulesRoot,
    `${bundle.environment}/${bundle.module}/${bundle.service}`,
  );
  ownedDirectories.set(directory, bundle);
  const files = listFiles(directory).sort();
  if (files.length === 0) {
    fail(`bundle '${bundle.path}' landed no manifests.`);
  }
  for (const file of files) {
    if (!manifestPath.test(file)) {
      fail(
        `bundle '${bundle.path}' contains an unsafe manifest path '${file}'.`,
      );
    }
    for (const identity of validateManifest(
      path.join(directory, file),
      bundle.path,
    )) {
      const scopedIdentity = `${bundle.environment}:${identity}`;
      const existing = resourceOwners.get(scopedIdentity);
      if (existing) {
        fail(
          `Kubernetes resource '${identity}' in '${bundle.environment}' is owned by both '${existing}' and '${bundle.path}'.`,
        );
      }
      resourceOwners.set(scopedIdentity, bundle.path);
    }
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

const environments = [
  ...new Set(inventory.bundles.map((bundle) => bundle.environment)),
]
  .sort()
  .join(", ");
console.log(
  `Manifest bundle landing contract satisfied: ${inventory.bundles.length} inventoried bundle(s)${environments ? ` across ${environments}` : ""}.`,
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

function validateManifest(file, landingPath) {
  const documents = parseAllDocuments(read(file));
  const identities = [];
  for (const document of documents) {
    if (document.errors.length > 0) {
      fail(`bundle manifest '${file}' is invalid YAML.`);
    }
    const resource = document.toJSON();
    if (resource === null) continue;
    if (
      typeof resource !== "object" ||
      Array.isArray(resource) ||
      typeof resource.apiVersion !== "string" ||
      typeof resource.kind !== "string" ||
      typeof resource.metadata?.name !== "string" ||
      resource.metadata.name.length === 0
    ) {
      fail(
        `bundle manifest '${file}' must contain only named Kubernetes resource objects.`,
      );
    }
    const group = resource.apiVersion.includes("/")
      ? resource.apiVersion.split("/")[0]
      : "";
    if (forbiddenControlPlaneGroups.has(group)) {
      fail(
        `bundle '${landingPath}' owns ${group} ${resource.kind}; reconciliation authority belongs to the platform layer.`,
      );
    }
    if (resource.kind === "Secret") {
      fail(
        `bundle '${landingPath}' owns a Secret; repository and cluster credentials belong to the platform layer.`,
      );
    }
    assertNoReconciliationAuthority(resource, file);
    const namespace =
      typeof resource.metadata.namespace === "string"
        ? resource.metadata.namespace
        : "<cluster>";
    identities.push(
      `${resource.apiVersion}/${resource.kind}/${namespace}/${resource.metadata.name}`,
    );
  }
  if (identities.length === 0) {
    fail(`bundle manifest '${file}' contains no Kubernetes resources.`);
  }
  return identities;
}

function assertNoReconciliationAuthority(
  value,
  file,
  currentPath = "resource",
) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      assertNoReconciliationAuthority(entry, file, `${currentPath}[${index}]`),
    );
    return;
  }
  if (value === null || typeof value !== "object") {
    if (typeof value !== "string") return;
    if (privateKeyMaterial.test(value)) {
      fail(`bundle manifest '${file}' contains private key material.`);
    }
    if (accessKeyMaterial.test(value) || commonTokenMaterial.test(value)) {
      fail(
        `bundle manifest '${file}' contains recognizable access credentials.`,
      );
    }
    if (/^(?:https?|ssh|git\+https):\/\//.test(value)) {
      let url;
      try {
        url = new URL(value);
      } catch {
        return;
      }
      if (url.username || url.password) {
        fail(`bundle manifest '${file}' contains URL credentials.`);
      }
    }
    return;
  }
  for (const [key, entry] of Object.entries(value)) {
    if (forbiddenSourceKeys.has(key)) {
      fail(
        `bundle manifest '${file}' declares Git source binding '${key}'; only the platform layer controls Git sources.`,
      );
    }
    const normalizedKey = key.replace(/([a-z0-9])([A-Z])/g, "$1_$2");
    if (credentialKey.test(normalizedKey)) {
      fail(
        `bundle manifest '${file}' contains credential-bearing key '${key}' at '${currentPath}'.`,
      );
    }
    assertNoReconciliationAuthority(entry, file, `${currentPath}.${key}`);
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
      entries.push(relative.split(path.sep).join("/"));
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
