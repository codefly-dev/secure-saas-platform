import test from "node:test";
import assert from "node:assert/strict";
import {
  argocdHelmValues,
  argocdExecCredentialArgs,
  databaseArgocdHelmValues,
  databaseInfrastructureControllerRules,
} from "../src/argocd";
import {
  argocdBootstrapHandoff,
  validateArgocdConfig,
  type ArgocdConfig,
} from "../src/config";

const config: ArgocdConfig = {
  clusterStackRef: "deus/platform/dev",
  clusterName: "platform-dev",
  clusterRole: "platform",
  clusterAccessRoleArn:
    "arn:aws:iam::888877776666:role/InfrastructureApplyNonProd-Workload",
  argocdHostname: "argocd.internal.example.com",
  chartVersion: "10.2.1",
  bootstrapRepository: "https://github.com/codefly-dev/secure-saas-infra.git",
  bootstrapRevision: "a".repeat(40),
  bootstrapDirectory: "gitops/bootstrap/argocd/overlays/dev/platform",
  oidcIssuer: "https://identity.example.com/realms/deus",
  oidcClientId: "argocd-platform-dev",
  oidcClientSecretRef: "$oidc.organization.clientSecret",
  oidcAdminGroup: "deus:infra:admins",
};

test("Argo CD is OIDC-only with local admin, anonymous, and ambient readonly access disabled", () => {
  assert.doesNotThrow(() => validateArgocdConfig(config));
  const values: any = argocdHelmValues(config);
  assert.equal(values.fullnameOverride, "argocd");
  assert.equal(values.configs.cm["admin.enabled"], false);
  assert.equal(values.configs.cm["users.anonymous.enabled"], false);
  assert.match(
    values.configs.cm["oidc.config"],
    /enablePKCEAuthentication: true/,
  );
  assert.match(values.configs.cm["oidc.config"], /requestedIDTokenClaims/);
  assert.match(
    values.configs.cm["oidc.config"],
    /clientSecret: \$oidc\.organization\.clientSecret/,
  );
  assert.equal(values.configs.rbac["policy.default"], "role:authenticated");
  assert.doesNotMatch(values.configs.rbac["policy.csv"], /role:readonly/);
  assert.match(
    values.configs.rbac["policy.csv"],
    /g, deus:infra:admins, role:admin/,
  );
  assert.equal(values.configs.rbac.scopes, "[groups]");
  assert.equal(values.server.service.type, "ClusterIP");
  assert.equal(values.configs.cm["exec.enabled"], false);
  assert.equal(values.configs.cm["resource.respectRBAC"], "strict");
  assert.equal(values.controller.clusterRoleRules.enabled, true);
  assert.equal(
    JSON.stringify(values.controller.clusterRoleRules.rules).includes('"*"'),
    false,
  );
});

test("Argo CD EKS authentication always assumes one explicit member-account role", () => {
  assert.deepEqual(
    argocdExecCredentialArgs(
      "platform-dev",
      "us-east-1",
      config.clusterAccessRoleArn,
    ),
    [
      "eks",
      "get-token",
      "--cluster-name",
      "platform-dev",
      "--region",
      "us-east-1",
      "--role-arn",
      config.clusterAccessRoleArn,
    ],
  );
});

test("Argo CD publishes a credential-free exact bootstrap handoff", () => {
  const handoff = argocdBootstrapHandoff(config);
  assert.deepEqual(handoff, {
    clusterRole: "platform",
    clusterName: "platform-dev",
    repository: "https://github.com/codefly-dev/secure-saas-infra.git",
    revision: "a".repeat(40),
    bootstrapEntrypoint: "gitops/bootstrap/argocd/overlays/dev/platform",
  });
  assert.doesNotMatch(
    JSON.stringify(handoff),
    /accessRole|arn:aws|certificate|credential|endpoint|password|secret|token/i,
  );
});

test("database infrastructure reconciliation uses a dedicated non-wildcard identity", () => {
  const values: any = databaseArgocdHelmValues();
  assert.equal(values.fullnameOverride, "argocd-database");
  assert.equal(values.crds.install, false);
  assert.equal(values.configs.cm["resource.respectRBAC"], "strict");
  assert.equal(
    values.controller.serviceAccount.name,
    "database-infrastructure-application-controller",
  );
  assert.equal(values.controller.clusterRoleRules.enabled, true);
  assert.deepEqual(
    values.controller.clusterRoleRules.rules,
    databaseInfrastructureControllerRules(),
  );
  const serialized = JSON.stringify(values.controller.clusterRoleRules.rules);
  for (const forbidden of [
    '"*"',
    "clusterpolicies",
    "pods",
    "deployments",
    "jobs",
    "secrets",
    "roles",
    "nodes",
    "impersonate",
    '"delete"',
    "deletecollection",
    "nonResourceURLs",
  ]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  assert.equal(values.applicationSet.enabled, false);
  assert.equal(values.dex.enabled, false);
});

test("Argo CD rejects credential-bearing issuers, secret values, wildcard groups, and mutable chart versions", () => {
  const cases: Array<[Partial<ArgocdConfig>, RegExp]> = [
    [
      { oidcIssuer: "https://admin:password@identity.example.com" },
      /credential-free exact HTTPS URL/,
    ],
    [{ oidcClientId: "*" }, /exact OIDC client ID/],
    [{ oidcClientSecretRef: "actual-secret" }, /secret-key reference/],
    [{ oidcAdminGroup: "deus:*" }, /exact OIDC group/],
    [{ chartVersion: "latest" }, /fully-qualified semver/],
    [
      { bootstrapRepository: "https://user:pass@example.invalid/repo" },
      /credential-free GitOps repository/,
    ],
    [{ bootstrapRevision: "main" }, /full Git commit SHA/],
    [{ bootstrapDirectory: "../untrusted" }, /bootstrap handoff/],
    [
      {
        bootstrapDirectory:
          "gitops/bootstrap/argocd/overlays/production/platform",
      },
      /bootstrap handoff/,
    ],
    [{ clusterRole: "execution" }, /bootstrap handoff/],
    [{ clusterAccessRoleArn: "*" }, /exact IAM role ARN/],
  ];
  for (const [change, expected] of cases) {
    assert.throws(
      () => validateArgocdConfig({ ...config, ...change }),
      expected,
    );
  }
});
