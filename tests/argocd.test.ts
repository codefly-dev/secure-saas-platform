import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { parseAllDocuments } from "yaml";
import {
  argocdHelmValues,
  argocdExecCredentialArgs,
  createArgocd,
  databaseArgocdHelmValues,
  databaseInfrastructureControllerRules,
} from "../src/argocd";
import {
  argocdBootstrapDirectory,
  argocdBootstrapHandoff,
  validateArgocdConfig,
  type ArgocdConfig,
} from "../src/config";
import {
  flushPulumiMocks,
  installPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";

const config: ArgocdConfig = {
  clusterStackRef: "deus/platform/dev",
  clusterName: "platform-dev",
  clusterRole: "platform",
  clusterAccessRoleArn:
    "arn:aws:iam::888877776666:role/InfrastructureApplyNonProd-Workload",
  argocdHostname: "argocd.internal.example.com",
  chartVersion: "10.2.1",
  bootstrap: {
    repository: "https://github.com/codefly-dev/secure-saas-infra.git",
    revision: "a".repeat(40),
    entrypoint: "gitops/bootstrap/argocd/overlays/dev/platform",
  },
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
  assert.equal(values.controller.metrics.serviceMonitor.enabled, false);
  assert.equal(values.server.metrics.serviceMonitor.enabled, false);
  assert.equal(values.repoServer.metrics.serviceMonitor.enabled, false);
  assert.equal(values.applicationSet.metrics.serviceMonitor.enabled, false);
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

test("Argo CD controller RBAC covers every resource in its selected role baseline", () => {
  const resourcesByKind: Record<string, string> = {
    AuthorizationPolicy: "authorizationpolicies",
    ClusterPolicy: "clusterpolicies",
    ConfigMap: "configmaps",
    Connector: "connectors",
    LimitRange: "limitranges",
    Namespace: "namespaces",
    NetworkPolicy: "networkpolicies",
    PeerAuthentication: "peerauthentications",
    ResourceQuota: "resourcequotas",
    RuntimeClass: "runtimeclasses",
    ServiceAccount: "serviceaccounts",
    Telemetry: "telemetries",
    ValidatingAdmissionPolicy: "validatingadmissionpolicies",
    ValidatingAdmissionPolicyBinding: "validatingadmissionpolicybindings",
  };

  for (const clusterRole of ["platform", "execution"] as const) {
    const roleConfig: ArgocdConfig = {
      ...config,
      clusterRole,
      clusterName: `${clusterRole}-dev`,
      bootstrap: {
        ...config.bootstrap,
        entrypoint: `gitops/bootstrap/argocd/overlays/dev/${clusterRole}`,
      },
    };
    const rules: any[] =
      argocdHelmValues(roleConfig).controller.clusterRoleRules.rules;
    assert.equal(
      JSON.stringify(rules).includes("connectors"),
      clusterRole === "platform",
    );
    assert.equal(
      JSON.stringify(rules).includes("runtimeclasses"),
      clusterRole === "execution",
    );
    const baseline = parseAllDocuments(
      execFileSync(
        "kubectl",
        ["kustomize", `gitops/overlays/dev/${clusterRole}`],
        { encoding: "utf8" },
      ),
    )
      .map((document) => document.toJSON() as any)
      .filter(Boolean);
    for (const resource of baseline) {
      const apiGroup = String(resource.apiVersion).includes("/")
        ? String(resource.apiVersion).split("/")[0]
        : "";
      const resourceName = resourcesByKind[resource.kind];
      assert.ok(
        resourceName,
        `${resource.kind} must have an RBAC resource name`,
      );
      assert.ok(
        rules.some(
          (rule) =>
            rule.apiGroups.includes(apiGroup) &&
            rule.resources.includes(resourceName) &&
            ["get", "list", "create", "update", "patch", "delete"].every(
              (verb) => rule.verbs.includes(verb),
            ),
        ),
        `${clusterRole} controller cannot reconcile ${apiGroup || "core"}/${resource.kind}`,
      );
    }
  }
});

test("Argo CD controller RBAC can reconcile the pinned monitoring stack", () => {
  for (const clusterRole of ["platform", "execution"] as const) {
    const roleConfig: ArgocdConfig = {
      ...config,
      clusterRole,
      clusterName: `${clusterRole}-dev`,
      bootstrap: {
        ...config.bootstrap,
        entrypoint: `gitops/bootstrap/argocd/overlays/dev/${clusterRole}`,
      },
    };
    const rules: any[] =
      argocdHelmValues(roleConfig).controller.clusterRoleRules.rules;
    const monitoringResources = new Set(
      rules
        .filter((rule) => rule.apiGroups.includes("monitoring.coreos.com"))
        .flatMap((rule) => rule.resources),
    );
    assert.deepEqual([...monitoringResources].sort(), [
      "alertmanagers",
      "podmonitors",
      "prometheuses",
      "prometheusrules",
      "servicemonitors",
    ]);
  }
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
  assert.equal(
    argocdBootstrapDirectory(config),
    `https://github.com/codefly-dev/secure-saas-infra//${config.bootstrap.entrypoint}?ref=${config.bootstrap.revision}`,
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

test("execution-role Argo CD installs no database control plane", async () => {
  const { resources } = await installPulumiMocks();
  createArgocd({
    ...config,
    clusterRole: "execution",
    clusterName: "execution-dev",
    bootstrap: {
      ...config.bootstrap,
      entrypoint: "gitops/bootstrap/argocd/overlays/dev/execution",
    },
  });
  await flushPulumiMocks();

  const namespaces = resourcesOfType(resources, "kubernetes:core/v1:Namespace");
  const releases = resourcesOfType(resources, "kubernetes:helm.sh/v3:Release");
  assert.equal(
    namespaces.some(
      (resource) => resource.inputs.metadata.name === "argocd-database",
    ),
    false,
  );
  assert.equal(
    releases.some((resource) => resource.name.includes("database")),
    false,
  );
  assert.equal(releases.length, 1);
  assert.equal(releases[0].inputs.version, config.chartVersion);
  assert.equal(
    releases[0].inputs.repositoryOpts.repo,
    "https://argoproj.github.io/argo-helm",
  );
  const bootstraps = resourcesOfType(
    resources,
    "kubernetes:kustomize/v2:Directory",
  );
  assert.equal(bootstraps.length, 1);
  assert.equal(
    bootstraps[0].inputs.directory,
    `https://github.com/codefly-dev/secure-saas-infra//gitops/bootstrap/argocd/overlays/dev/execution?ref=${config.bootstrap.revision}`,
  );
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
    [{ chartVersion: "latest" }, /qualified release/],
    [{ chartVersion: "10.2.2" }, /qualified release/],
    [
      {
        bootstrap: {
          ...config.bootstrap,
          repository: "https://user:pass@example.invalid/repo",
        },
      },
      /credential-free GitOps repository/,
    ],
    [
      { bootstrap: { ...config.bootstrap, revision: "main" } },
      /full Git commit SHA/,
    ],
    [
      { bootstrap: { ...config.bootstrap, entrypoint: "../untrusted" } },
      /bootstrap handoff/,
    ],
    [
      {
        bootstrap: {
          ...config.bootstrap,
          entrypoint: "gitops/bootstrap/argocd/overlays/production/platform",
        },
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
