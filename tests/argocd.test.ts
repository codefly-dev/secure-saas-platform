import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  argocdControllerRules,
  argocdHelmValues,
  databaseArgocdHelmValues,
} from "../src/argocdValues.js";

const handoff = "fixtures/platform-iac-handoff-v1.json";
const publicKey = "keys/qualification-platform-handoff-ecdsa-p256.pub";

test("signed credential-free IaC handoff verifies before activation", () => {
  const result = verify(handoff, publicKey);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Verified signed platform handoff/);
});

test("handoff verifier rejects spec, signature, key, and credential substitution", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "platform-handoff-"));
  try {
    const baseline = JSON.parse(readFileSync(handoff, "utf8"));
    for (const [name, mutate, error] of [
      [
        "spec",
        (value: any) => {
          value.spec.cluster.endpoint = "https://attacker.invalid";
        },
        /specDigest/,
      ],
      [
        "signature",
        (value: any) => {
          value.signature.value =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        },
        /signature verification/,
      ],
      [
        "credential",
        (value: any) => {
          value.spec.gitops.repository =
            "https://user:password@github.com/codefly-dev/secure-saas-platform.git";
        },
        /schema validation|credential/,
      ],
      [
        "credential-reference",
        (value: any) => {
          value.spec.bootstrapIdentity.accessEntryReference =
            "eks-access://user:password@platform-prod/bootstrap?token=secret";
        },
        /schema validation|credential/,
      ],
      [
        "mutable-key-reference",
        (value: any) => {
          value.signature.publicKeyReference = `${value.signature.publicKeyReference}?token=secret`;
        },
        /schema validation|credential/,
      ],
    ] as const) {
      const hostile = structuredClone(baseline);
      mutate(hostile);
      const file = path.join(directory, `${name}.json`);
      writeFileSync(file, `${JSON.stringify(hostile)}\n`);
      const result = verify(file, publicKey);
      assert.notEqual(result.status, 0, name);
      assert.match(result.stderr, error, name);
    }
    const wrongKey = path.join(directory, "wrong.pub");
    const { publicKey: unrelatedPublicKey } = generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    writeFileSync(
      wrongKey,
      unrelatedPublicKey.export({ type: "spki", format: "pem" }),
    );
    const result = verify(handoff, wrongKey);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /public key|keyId|decode/i);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("handoff verifier accepts coherent commercial, GovCloud, and China ARNs", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "platform-partition-"));
  try {
    for (const { name, partition, region } of [
      { name: "commercial", partition: "aws", region: "us-east-1" },
      { name: "govcloud", partition: "aws-us-gov", region: "us-gov-west-1" },
      { name: "china", partition: "aws-cn", region: "cn-north-1" },
    ]) {
      const signed = writeSignedHandoff(directory, name, (spec: any) => {
        spec.cluster.endpoint = `https://platform-prod.eks.${region}.example`;
        spec.bootstrapIdentity.principalArn = `arn:${partition}:iam::888877776666:role/InfrastructureApplyProd-Workload`;
        spec.cloudResources.region = region;
        spec.cloudResources.clusterArn = `arn:${partition}:eks:${region}:888877776666:cluster/platform-prod`;
        spec.cloudResources.secretsEncryptionKeyArn = `arn:${partition}:kms:${region}:888877776666:key/11111111-2222-3333-4444-555555555555`;
      });
      const result = verify(signed.handoff, signed.publicKey);
      assert.equal(result.status, 0, `${name}: ${result.stderr}`);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("activation rejects a kubeconfig with a different certificate authority", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "platform-kubeconfig-"));
  try {
    const revision = spawnSync("git", ["rev-parse", "HEAD"], {
      cwd: process.cwd(),
      encoding: "utf8",
    }).stdout.trim();
    const signed = writeSignedHandoff(directory, "ca-binding", (spec: any) => {
      spec.gitops.revision = revision;
    });
    const kubeconfig = {
      clusters: [
        {
          cluster: {
            server: "https://0123456789ABCDEF.gr7.us-east-1.eks.amazonaws.com",
            "certificate-authority-data": Buffer.from(
              "attacker-controlled-ca",
            ).toString("base64"),
          },
        },
      ],
      users: [
        {
          user: {
            exec: {
              args: [
                "--role-arn",
                "arn:aws:iam::888877776666:role/InfrastructureApplyProd-Workload",
              ],
            },
          },
        },
      ],
    };
    const kubectl = path.join(directory, "kubectl");
    writeFileSync(
      kubectl,
      `#!/bin/sh\nprintf '%s\\n' '${JSON.stringify(kubeconfig)}'\n`,
      { mode: 0o700 },
    );
    const result = spawnSync(
      process.execPath,
      [
        "scripts/activate-argocd.mjs",
        "--handoff",
        signed.handoff,
        "--public-key",
        signed.publicKey,
        "--kubeconfig",
        path.join(directory, "kubeconfig"),
        "--revision",
        revision,
        "--hostname",
        "argocd-platform.internal.example",
        "--oidc-issuer",
        "https://identity.example/realms/platform",
        "--oidc-client-id",
        "argocd-platform",
        "--oidc-client-secret-ref",
        "$oidc.organization.clientSecret",
        "--oidc-admin-group",
        "deus:infra:admins",
        "--execute",
      ],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: `${directory}${path.delimiter}${process.env.PATH}`,
        },
      },
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /certificate authority.*signed handoff/i);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("kubeconfig binding accepts only the signed endpoint, CA bytes, and role", () => {
  const spec = JSON.parse(readFileSync(handoff, "utf8")).spec;
  const config = {
    clusters: [
      {
        cluster: {
          server: spec.cluster.endpoint,
          "certificate-authority-data": Buffer.from(
            "qualification-platform-cluster-ca",
          ).toString("base64"),
        },
      },
    ],
    users: [
      {
        user: {
          exec: {
            args: ["--role-arn", spec.bootstrapIdentity.principalArn],
          },
        },
      },
    ],
  };
  const accepted = verifyKubeconfigBinding(spec, config);
  assert.equal(accepted.status, 0, accepted.stderr);
  const substituted = structuredClone(config);
  substituted.clusters[0].cluster["certificate-authority-data"] =
    Buffer.from("substituted-ca").toString("base64");
  const rejected = verifyKubeconfigBinding(spec, substituted);
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /certificate authority.*signed handoff/i);
});

test("minimal activation installs Argo CD and hands ownership to exact Git", () => {
  const result = spawnSync(
    process.execPath,
    [
      "scripts/activate-argocd.mjs",
      "--handoff",
      handoff,
      "--public-key",
      publicKey,
      "--kubeconfig",
      "/run/platform-promotion/kubeconfig",
      "--revision",
      "v0.1.1",
      "--hostname",
      "argocd-platform.internal.example",
      "--oidc-issuer",
      "https://identity.example/realms/platform",
      "--oidc-client-id",
      "argocd-platform",
      "--oidc-client-secret-ref",
      "$oidc.organization.clientSecret",
      "--oidc-admin-group",
      "deus:infra:admins",
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
  const plan = JSON.parse(result.stdout);
  assert.equal(plan.role, "platform");
  assert.equal(plan.helm.length, 2);
  assert.deepEqual(
    plan.helm.map((entry: any) => entry.arguments[4]),
    ["argocd", "argocd-database"],
  );
  assert.equal(
    plan.gitHandoff.repository,
    "https://github.com/codefly-dev/secure-saas-platform.git",
  );
  assert.equal(plan.gitHandoff.revision, "v0.1.1");
  assert.equal(
    plan.gitHandoff.entrypoint,
    "gitops/bootstrap/argocd/overlays/production/platform",
  );
  assert.equal(JSON.stringify(plan).includes("pulumi"), false);
});

test("Argo CD is OIDC-only with role-specific least privilege", () => {
  for (const clusterRole of ["platform", "execution"] as const) {
    const values: any = argocdHelmValues({
      clusterRole,
      argocdHostname: `argocd-${clusterRole}.internal.example`,
      oidcIssuer: "https://identity.example/realms/platform",
      oidcClientId: `argocd-${clusterRole}`,
      oidcClientSecretRef: "$oidc.organization.clientSecret",
      oidcAdminGroup: "deus:infra:admins",
    });
    assert.equal(values.configs.cm["admin.enabled"], false);
    assert.equal(values.configs.cm["users.anonymous.enabled"], false);
    assert.equal(values.configs.cm["exec.enabled"], false);
    assert.equal(values.configs.cm["resource.respectRBAC"], "strict");
    assert.match(
      values.configs.cm["oidc.config"],
      /enablePKCEAuthentication: true/,
    );
    const rules = JSON.stringify(argocdControllerRules(clusterRole));
    assert.equal(rules.includes('"*"'), false);
    assert.equal(rules.includes("runtimeclasses"), clusterRole === "execution");
    assert.equal(rules.includes("connectors"), clusterRole === "platform");
  }
  const databaseValues: any = databaseArgocdHelmValues();
  assert.equal(databaseValues.configs.cm["admin.enabled"], false);
  assert.equal(
    JSON.stringify(databaseValues.controller.clusterRoleRules.rules).includes(
      '"delete"',
    ),
    false,
  );
});

function verify(handoffFile: string, keyFile: string) {
  return spawnSync(
    process.execPath,
    [
      "scripts/verify-platform-iac-handoff.mjs",
      "--handoff",
      handoffFile,
      "--public-key",
      keyFile,
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
}

function verifyKubeconfigBinding(spec: any, config: any) {
  return spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      'import { assertKubeconfigBinding } from "./scripts/platform-handoff.mjs"; assertKubeconfigBinding(JSON.parse(process.argv[1]), JSON.parse(process.argv[2]));',
      JSON.stringify(spec),
      JSON.stringify(config),
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
}

function writeSignedHandoff(
  directory: string,
  name: string,
  mutateSpec: (spec: any) => void,
) {
  const document = JSON.parse(readFileSync(handoff, "utf8"));
  mutateSpec(document.spec);
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const canonicalSpec = canonicalJson(document.spec);
  document.specDigest = createHash("sha256")
    .update(canonicalSpec)
    .digest("hex");
  const keyId = createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
  document.signature = {
    algorithm: "ecdsa-p256-sha256",
    keyId,
    publicKeyReference: `key-id://sha256/${keyId}`,
    value: sign("sha256", Buffer.from(canonicalSpec), privateKey).toString(
      "base64",
    ),
  };
  const handoffFile = path.join(directory, `${name}.json`);
  const publicKeyFile = path.join(directory, `${name}.pub`);
  writeFileSync(handoffFile, `${JSON.stringify(document)}\n`);
  writeFileSync(
    publicKeyFile,
    publicKey.export({ type: "spki", format: "pem" }),
  );
  return { handoff: handoffFile, publicKey: publicKeyFile };
}

function canonicalJson(value: any): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}
