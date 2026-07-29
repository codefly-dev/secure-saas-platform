import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
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
    copyFileSync(
      "keys/qualification-platform-handoff-ecdsa-p256.pub",
      wrongKey,
    );
    writeFileSync(
      wrongKey,
      readFileSync(wrongKey, "utf8").replace("tR9e", "tR8e"),
    );
    const result = verify(handoff, wrongKey);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /public key|keyId|decode/i);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
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
      "v0.1.0",
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
  assert.equal(plan.gitHandoff.revision, "v0.1.0");
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
