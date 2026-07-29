import { createHash, createPublicKey, verify } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schemaPath = path.resolve(
  path.dirname(new URL(import.meta.url).pathname),
  "../schemas/platform-iac-handoff-v1.schema.json",
);

export function verifyPlatformHandoff(handoffFile, publicKeyFile) {
  const handoffPath = regularFile(handoffFile, "handoff");
  const publicKeyPath = regularFile(publicKeyFile, "public key");
  const handoff = parseJson(readFileSync(handoffPath, "utf8"), handoffPath);
  const schema = parseJson(readFileSync(schemaPath, "utf8"), schemaPath);
  const ajv = new Ajv2020({
    allErrors: true,
    allowUnionTypes: false,
    strict: true,
    validateFormats: true,
  });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  if (!validate(handoff)) {
    fail(
      `schema validation failed:\n${(validate.errors ?? [])
        .map((error) => `- ${error.instancePath || "/"} ${error.message}`)
        .join("\n")}`,
    );
  }
  assertCredentialFree(handoff);
  assertBindings(handoff.spec);

  const canonicalSpec = canonicalJson(handoff.spec);
  const specDigest = sha256(canonicalSpec);
  if (handoff.specDigest !== specDigest) {
    fail("specDigest does not bind the canonical handoff spec.");
  }
  const publicKey = createPublicKey(readFileSync(publicKeyPath));
  if (
    publicKey.asymmetricKeyType !== "ec" ||
    publicKey.asymmetricKeyDetails?.namedCurve !== "prime256v1"
  ) {
    fail("handoff trust key must be ECDSA P-256.");
  }
  const keyId = sha256(publicKey.export({ type: "spki", format: "der" }));
  if (handoff.signature.keyId !== keyId) {
    fail("signature keyId does not match the reviewed public key.");
  }
  if (
    !verify(
      "sha256",
      Buffer.from(canonicalSpec),
      publicKey,
      Buffer.from(handoff.signature.value, "base64"),
    )
  ) {
    fail("handoff signature verification failed.");
  }
  return handoff;
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function assertBindings(spec) {
  const { role, name } = spec.cluster;
  if (!name.startsWith(`${role}-`)) {
    fail("cluster name does not match cluster role.");
  }
  const match =
    /^gitops\/bootstrap\/argocd\/overlays\/(dev|staging|production)\/(platform|execution)$/.exec(
      spec.gitops.bootstrapEntrypoint,
    );
  const expectedEnvironment = name.endsWith("-prod")
    ? "production"
    : name.split("-").at(-1);
  if (!match || match[1] !== expectedEnvironment || match[2] !== role) {
    fail("GitOps entrypoint does not match cluster environment and role.");
  }
  const endpoint = new URL(spec.cluster.endpoint);
  if (
    endpoint.protocol !== "https:" ||
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash ||
    endpoint.pathname !== "/"
  ) {
    fail("cluster endpoint must be one credential-free HTTPS origin.");
  }
  const { accountId, region, clusterArn, secretsEncryptionKeyArn } =
    spec.cloudResources;
  if (
    !clusterArn.startsWith(
      `arn:aws:eks:${region}:${accountId}:cluster/${name}`,
    ) ||
    !secretsEncryptionKeyArn.startsWith(
      `arn:aws:kms:${region}:${accountId}:key/`,
    ) ||
    !spec.bootstrapIdentity.principalArn.includes(`::${accountId}:role/`)
  ) {
    fail("cloud resource and bootstrap identity references cross boundaries.");
  }
}

function assertCredentialFree(value, currentPath = "handoff") {
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      assertCredentialFree(entry, `${currentPath}[${index}]`),
    );
    return;
  }
  if (value === null || typeof value !== "object") {
    if (
      typeof value === "string" &&
      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(value)
    ) {
      fail(`${currentPath} contains private key material.`);
    }
    if (typeof value === "string" && /^(?:https?|ssh):\/\//.test(value)) {
      const url = new URL(value);
      if (url.username || url.password) {
        fail(`${currentPath} contains URL credentials.`);
      }
    }
    return;
  }
  for (const [key, entry] of Object.entries(value)) {
    if (
      /(?:password|private.?key|client.?secret|access.?token|refresh.?token|credential)$/i.test(
        key,
      )
    ) {
      fail(`${currentPath}.${key} is credential-bearing.`);
    }
    assertCredentialFree(entry, `${currentPath}.${key}`);
  }
}

function regularFile(value, label) {
  const candidate = path.resolve(value);
  const stat = lstatSync(candidate);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail(`${label} must be a regular non-symlink file.`);
  }
  return realpathSync(candidate);
}

function parseJson(source, file) {
  try {
    return JSON.parse(source);
  } catch (error) {
    fail(`${file} is not valid JSON: ${error.message}`);
  }
}

function fail(message) {
  throw new Error(`PLATFORM_HANDOFF_INVALID ${message}`);
}
