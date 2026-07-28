import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import {
  cpSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseAllDocuments, stringify } from "yaml";

test("Argo CD bootstraps Istio ambient mode in the required order", () => {
  const expectedApps = [
    ["gateway-api-crds.application.yaml", /targetRevision: v1\.4\.0/],
    [
      "istio-base.application.yaml",
      /chart: base[\s\S]*targetRevision: 1\.29\.2/,
    ],
    ["istiod.application.yaml", /chart: istiod[\s\S]*profile: ambient/],
    ["istio-cni.application.yaml", /chart: cni[\s\S]*profile: ambient/],
    [
      "istio-ztunnel.application.yaml",
      /chart: ztunnel[\s\S]*targetRevision: 1\.29\.2/,
    ],
    [
      "istio-ingress-gateway.application.yaml",
      /chart: gateway[\s\S]*aws-load-balancer-scheme: internal/,
    ],
  ] as const;

  for (const [file, pattern] of expectedApps) {
    const body = readFileSync(
      `gitops/bootstrap/argocd/base/apps/${file}`,
      "utf8",
    );
    assert.match(body, pattern);
    assert.match(body, /automated:/);
  }
});

test("EKS Auto Mode exclusively owns the internal NLB while Istio owns L7 routing", () => {
  const gateway = readFileSync(
    "gitops/bootstrap/argocd/base/apps/istio-ingress-gateway.application.yaml",
    "utf8",
  );
  const bootstrap = readFileSync(
    "gitops/bootstrap/argocd/base/kustomization.yaml",
    "utf8",
  );
  assert.match(gateway, /loadBalancerClass: eks\.amazonaws\.com\/nlb/);
  assert.match(gateway, /aws-load-balancer-scheme: internal/);
  assert.match(gateway, /aws-load-balancer-nlb-target-type: ip/);
  assert.match(gateway, /aws-load-balancer-healthcheck-port: "15021"/);
  assert.match(gateway, /load_balancing\.cross_zone\.enabled=true/);
  assert.doesNotMatch(bootstrap, /aws-load-balancer-controller/i);
});

test("EKS Auto Mode network policy enforcement is enabled before restrictive NodeClasses", () => {
  const controller = readFileSync(
    "gitops/base/eks-auto-mode/network-policy-controller.yaml",
    "utf8",
  );
  const platform = readFileSync(
    "gitops/clusters/platform/kustomization.yaml",
    "utf8",
  );
  const execution = readFileSync(
    "gitops/clusters/execution/kustomization.yaml",
    "utf8",
  );
  const projects = readFileSync(
    "gitops/bootstrap/argocd/base/projects.appproject.yaml",
    "utf8",
  );
  assert.match(controller, /name: amazon-vpc-cni/);
  assert.match(controller, /namespace: kube-system/);
  assert.match(controller, /enable-network-policy-controller: "true"/);
  assert.match(platform, /..\/..\/base\/eks-auto-mode/);
  assert.match(execution, /..\/..\/base\/eks-auto-mode/);
  assert.match(projects, /namespace: kube-system/);
});

test("application namespaces are enrolled into Istio ambient mesh", () => {
  for (const namespace of ["platform", "workloads", "execution"]) {
    const body = readFileSync(
      `gitops/base/namespaces/${namespace}.yaml`,
      "utf8",
    );
    assert.match(body, /istio.io\/dataplane-mode: ambient/);
  }
});

test("mesh security defaults enforce mTLS and default-deny authorization", () => {
  const peerAuth = readFileSync(
    "gitops/base/istio-security/workloads-peer-authentication.yaml",
    "utf8",
  );
  const authz = readFileSync(
    "gitops/base/istio-security/execution-default-deny-authorization.yaml",
    "utf8",
  );
  const telemetry = readFileSync(
    "gitops/base/istio-security/mesh-default-telemetry.yaml",
    "utf8",
  );

  assert.match(peerAuth, /mode: STRICT/);
  assert.match(authz, /kind: AuthorizationPolicy/);
  assert.match(authz, /rules: \[\]/);
  assert.match(telemetry, /kind: Telemetry/);
  assert.match(telemetry, /name: envoy/);
});

test("execution workloads are fail-closed behind sandbox admission controls", () => {
  const runtimeClass = readFileSync(
    "gitops/base/runtime-classes/deus-microvm.yaml",
    "utf8",
  );
  const policy = readFileSync(
    "gitops/base/kyverno/require-execution-sandbox.yaml",
    "utf8",
  );
  const limits = readFileSync(
    "gitops/base/quotas/execution-limits.yaml",
    "utf8",
  );
  const executionKustomization = readFileSync(
    "gitops/clusters/execution/kustomization.yaml",
    "utf8",
  );

  assert.match(runtimeClass, /kind: RuntimeClass/);
  assert.match(runtimeClass, /name: deus-microvm/);
  assert.match(runtimeClass, /handler: kata-clh/);
  assert.match(runtimeClass, /deus.dev\/sandbox-runtime: microvm/);
  assert.match(policy, /runtimeClassName: deus-microvm/);
  assert.match(policy, /automountServiceAccountToken: false/);
  assert.match(policy, /ephemeral-storage/);
  assert.match(policy, /security.deus.dev\/tenant-id/);
  assert.match(policy, /security.deus.dev\/job-id/);
  assert.match(policy, /security.deus.dev\/source-revision/);
  assert.match(policy, /security.deus.dev\/egress-profile/);
  assert.match(policy, /security.deus.dev\/sandbox-provider/);
  assert.match(limits, /kind: LimitRange/);
  assert.match(limits, /kind: ResourceQuota/);
  assert.match(limits, /limits.ephemeral-storage/);
  assert.match(executionKustomization, /..\/..\/base\/runtime-classes/);
  assert.match(executionKustomization, /..\/..\/base\/quotas/);
});

test("application ServiceAccounts and Pods cannot mount Kubernetes API tokens", () => {
  const policy = readFileSync(
    "gitops/base/kyverno/deny-service-account-tokens.yaml",
    "utf8",
  );
  const kustomization = readFileSync(
    "gitops/base/kyverno/kustomization.yaml",
    "utf8",
  );
  assert.match(policy, /name: serviceaccount-automount-must-be-false/);
  assert.match(policy, /name: pod-automount-must-be-false/);
  assert.match(policy, /name: kubernetes-api-token-projection-forbidden/);
  assert.match(
    policy,
    /name: projected-cloud-token-must-match-infrastructure-owned-identity/,
  );
  assert.match(policy, /name: secret-volumes-forbidden/);
  assert.match(policy, /SEC_TOKEN_AUTOMOUNT_DENIED/);
  assert.match(policy, /SEC_TOKEN_PROJECTION_DENIED/);
  assert.match(policy, /SEC_CLOUD_TOKEN_BINDING_DENIED/);
  assert.match(policy, /SEC_SECRET_VOLUME_DENIED/);
  assert.match(
    policy,
    /security\.deus\.dev\/service-account-token-policy: restricted/,
  );
  assert.match(
    readFileSync("gitops/base/namespaces/workloads.yaml", "utf8"),
    /security\.deus\.dev\/service-account-token-policy: restricted/,
  );
  const defaultServiceAccounts = readFileSync(
    "gitops/base/namespaces/restricted-default-serviceaccounts.yaml",
    "utf8",
  );
  assert.equal(
    defaultServiceAccounts.match(/automountServiceAccountToken: false/g)
      ?.length,
    6,
  );
  assert.match(policy, /serviceAccountToken/);
  assert.match(policy, /failurePolicy: Fail/);
  assert.match(kustomization, /deny-service-account-tokens\.yaml/);
});

test("application images require Sigstore signatures, SLSA provenance, and SPDX SBOMs", () => {
  const digestPolicy = readFileSync(
    "gitops/base/kyverno/require-image-digests.yaml",
    "utf8",
  );
  const policy = readFileSync(
    "gitops/base/kyverno/verify-signed-provenance.yaml",
    "utf8",
  );
  const kustomization = readFileSync(
    "gitops/base/kyverno/kustomization.yaml",
    "utf8",
  );

  assert.match(policy, /kind: ClusterPolicy/);
  assert.match(policy, /name: verify-signed-provenance/);
  assert.match(policy, /failurePolicy: Fail/);
  assert.match(policy, /verifyImages:/);
  assert.match(policy, /subjectRegExp: https:\/\/github\\.com/);
  assert.match(policy, /issuer: https:\/\/token.actions.githubusercontent.com/);
  assert.match(policy, /ghcr\.io\/codefly-dev\/secure-saas-infra\/\*/);
  assert.match(policy, /codefly-dev\/secure-saas-infra/);
  assert.doesNotMatch(policy, /\[\^\/\]\+\/\[\^\/\]\+/);
  assert.match(policy, /type: https:\/\/slsa.dev\/provenance\/v1/);
  assert.match(policy, /type: https:\/\/spdx.dev\/Document/);
  assert.doesNotMatch(policy, /predicateType:/);
  assert.match(digestPolicy, /image: "\*@sha256:\*"/);
  assert.doesNotMatch(digestPolicy, /NotContains/);
  assert.match(kustomization, /verify-signed-provenance.yaml/);
});

test("Argo CD includes common platform operators", () => {
  const apps = [
    "cert-manager.application.yaml",
    "metrics-server.application.yaml",
    "kube-prometheus-stack.application.yaml",
    "vault-secrets-operator.application.yaml",
  ];

  for (const app of apps) {
    const body = readFileSync(
      `gitops/bootstrap/argocd/base/apps/${app}`,
      "utf8",
    );
    assert.match(body, /kind: Application/);
    assert.match(body, /automated:/);
  }
});

test("Argo CD bootstrap entrypoints render one immutable cluster role", () => {
  const common = [
    "falco",
    "istio-base",
    "istio-cni",
    "istio-ztunnel",
    "istiod",
    "kube-prometheus-stack",
    "kyverno",
    "metrics-server",
  ];
  for (const environment of ["dev", "staging", "production"]) {
    for (const clusterRole of ["platform", "execution"]) {
      const entrypoint = `gitops/bootstrap/argocd/overlays/${environment}/${clusterRole}`;
      const documents = parseAllDocuments(
        execFileSync("kubectl", ["kustomize", entrypoint], {
          encoding: "utf8",
        }),
      )
        .map((document) => document.toJSON() as any)
        .filter(Boolean);
      const applications = documents.filter(
        (document) => document.kind === "Application",
      );
      const expected =
        clusterRole === "platform"
          ? [
              "argo-rollouts",
              "cert-manager",
              "database-infrastructure-handoff",
              "external-dns",
              "gateway-api-crds",
              "istio-ingress-gateway",
              ...common,
              "platform-cluster-baseline",
              "tailscale-operator",
              "vault",
              "vault-secrets-operator",
            ].sort()
          : [...common, "execution-cluster-baseline"].sort();
      assert.deepEqual(
        applications.map((application) => application.metadata.name).sort(),
        expected,
      );
      const baselines = applications.filter((application) =>
        /-cluster-baseline$/.test(application.metadata.name),
      );
      assert.equal(baselines.length, 1);
      assert.equal(
        baselines[0].metadata.name,
        `${clusterRole}-cluster-baseline`,
      );
      assert.equal(
        baselines[0].spec.source.path,
        `gitops/overlays/${environment}/${clusterRole}`,
      );
      assert.match(baselines[0].spec.source.targetRevision, /^[a-f0-9]{40}$/);
      assert.equal(
        baselines[0].spec.destination.server,
        "https://kubernetes.default.svc",
      );
      assert.ok(
        baselines[0].spec.syncPolicy.syncOptions.includes(
          "FailOnSharedResource=true",
        ),
      );
    }
  }
});

test("Pulumi Argo CD handoffs align the qualified chart and immutable role entrypoints", () => {
  const revisions = new Set<string>();
  const chartVersions = new Set<string>();
  for (const environment of ["dev", "staging", "prod"]) {
    const overlayEnvironment =
      environment === "prod" ? "production" : environment;
    for (const clusterRole of ["platform", "execution"]) {
      const file = `Pulumi.argocd-${clusterRole}-${environment}.yaml.example`;
      const document = parseAllDocuments(
        readFileSync(file, "utf8"),
      )[0].toJSON();
      const config = document.config["secure-saas-infra:argocd"];
      assert.equal(config.clusterRole, clusterRole);
      assert.equal(config.clusterName, `${clusterRole}-${environment}`);
      assert.equal(
        config.bootstrapRepository,
        "https://github.com/codefly-dev/secure-saas-infra.git",
      );
      assert.match(config.bootstrapRevision, /^[a-f0-9]{40}$/);
      assert.equal(
        config.bootstrapDirectory,
        `gitops/bootstrap/argocd/overlays/${overlayEnvironment}/${clusterRole}`,
      );
      const rendered = parseAllDocuments(
        execFileSync("kubectl", ["kustomize", config.bootstrapDirectory], {
          encoding: "utf8",
        }),
      )
        .map((entry) => entry.toJSON() as any)
        .filter(Boolean);
      const baseline = rendered.find(
        (entry) =>
          entry.kind === "Application" &&
          entry.metadata?.name === `${clusterRole}-cluster-baseline`,
      );
      assert.equal(
        baseline.spec.source.targetRevision,
        config.bootstrapRevision,
      );
      revisions.add(config.bootstrapRevision);
      chartVersions.add(config.chartVersion);
    }
  }
  assert.deepEqual(
    [...revisions],
    ["1b932460fb825745fdc0a6d8c23fbdf5d196f1bb"],
  );
  assert.deepEqual([...chartVersions], ["10.2.1"]);
});

test("Argo CD qualification binds the chart artifact and proves two-cluster reconciliation", () => {
  const chart = readFileSync("scripts/qualify-argocd-chart.mjs", "utf8");
  const twoCluster = readFileSync(
    "scripts/validate-argocd-cluster-roles.mjs",
    "utf8",
  );
  for (const source of [chart, twoCluster]) {
    assert.match(source, /CHART_VERSION = "10\.2\.1"/);
    assert.match(
      source,
      /27e930e366d22c999002008ad5ec7961bda00410a84287210d0fffbee8150885/,
    );
    assert.match(source, /sha256\(chart\) !== CHART_DIGEST/);
  }
  assert.match(twoCluster, /installArgocd/);
  assert.match(twoCluster, /"resource\.respectRBAC": "strict"/);
  assert.match(twoCluster, /"selfsubjectaccessreviews"/);
  assert.match(twoCluster, /status\.sync\?\.status === "Synced"/);
  assert.match(twoCluster, /status\.health\?\.status === "Healthy"/);
  assert.match(twoCluster, /forbiddenMarker \|\| forbiddenApplication/);
  assert.match(twoCluster, /runOptional\("docker", \["rm", "-f"/);
});

test("all GitOps overlays render", () => {
  assert.doesNotThrow(() =>
    execFileSync(process.execPath, ["scripts/validate-gitops.mjs"], {
      stdio: "pipe",
    }),
  );
});

test("Argo AppProjects deny default authority and bind every Application to an exact boundary", () => {
  const rendered = execFileSync(
    "kubectl",
    ["kustomize", "gitops/bootstrap/argocd/overlays/dev/platform"],
    { encoding: "utf8" },
  );
  const documents = parseAllDocuments(rendered)
    .map((document) => document.toJSON() as any)
    .filter(Boolean);
  const projects = new Map(
    documents
      .filter((document) => document.kind === "AppProject")
      .map((project) => [project.metadata.name, project]),
  );
  assert.deepEqual([...projects.keys()].sort(), [
    "bootstrap",
    "database-infrastructure",
    "default",
    "platform-operators",
    "security",
    "tenant-delivery",
  ]);
  assert.deepEqual(projects.get("default").spec, {
    description:
      "Deny-all default project; every Application must select an owned project.",
    sourceRepos: [],
    destinations: [],
    clusterResourceWhitelist: [],
    namespaceResourceWhitelist: [],
  });
  for (const application of documents.filter(
    (document) => document.kind === "Application",
  )) {
    assert.notEqual(application.spec.project, "default");
    assert.ok(projects.has(application.spec.project));
  }
  const tenant = projects.get("tenant-delivery").spec;
  assert.deepEqual(tenant.clusterResourceWhitelist, []);
  const tenantKinds = new Set(
    tenant.namespaceResourceWhitelist.map(
      (resource: any) => `${resource.group}/${resource.kind}`,
    ),
  );
  for (const forbidden of [
    "/Secret",
    "rbac.authorization.k8s.io/Role",
    "rbac.authorization.k8s.io/RoleBinding",
    "apiextensions.k8s.io/CustomResourceDefinition",
  ]) {
    assert.equal(tenantKinds.has(forbidden), false, forbidden);
  }
  const databaseInfrastructure = projects.get("database-infrastructure").spec;
  assert.deepEqual(
    databaseInfrastructure.clusterResourceWhitelist
      .map((resource: any) => `${resource.group}/${resource.kind}`)
      .sort(),
    [
      "/Namespace",
      "eks.amazonaws.com/NodeClass",
      "karpenter.sh/NodePool",
    ].sort(),
  );
  assert.deepEqual(
    databaseInfrastructure.namespaceResourceWhitelist
      .map((resource: any) => `${resource.group}/${resource.kind}`)
      .sort(),
    ["/ServiceAccount", "networking.k8s.aws/ApplicationNetworkPolicy"],
  );
  assert.equal(
    databaseInfrastructure.destinations.length,
    9,
    "three access classes for each of the three checked database bindings",
  );
  assert.ok(
    databaseInfrastructure.destinations.every((destination: any) =>
      destination.namespace.endsWith("-development"),
    ),
  );
  const databaseApplications = documents.filter(
    (document) =>
      document.kind === "Application" &&
      document.metadata.name === "database-infrastructure-handoff",
  );
  assert.equal(databaseApplications.length, 1);
  assert.equal(databaseApplications[0].metadata.namespace, "argocd-database");
  assert.equal(databaseApplications[0].spec.project, "database-infrastructure");
  assert.equal(
    databaseApplications[0].spec.source.path,
    "gitops/generated/database/development",
  );
  assert.equal(databaseApplications[0].spec.syncPolicy.automated, undefined);
  assert.deepEqual(
    [...databaseApplications[0].spec.syncPolicy.syncOptions].sort(),
    [
      "CreateNamespace=false",
      "FailOnSharedResource=true",
      "PruneLast=true",
      "ServerSideApply=true",
    ].sort(),
  );

  const execution = parseAllDocuments(
    execFileSync(
      "kubectl",
      ["kustomize", "gitops/bootstrap/argocd/overlays/dev/execution"],
      { encoding: "utf8" },
    ),
  )
    .map((document) => document.toJSON() as any)
    .filter(Boolean);
  assert.equal(
    execution.some(
      (document) =>
        document.metadata?.name === "database-infrastructure" ||
        document.metadata?.name === "database-infrastructure-handoff",
    ),
    false,
  );
});

test("GitOps boundary gate rejects default, wildcard, tenant-cluster, repository, and resource-scope escalation", () => {
  const cases: Array<[string, (root: string) => void, RegExp]> = [
    [
      "second role Application",
      (root) =>
        mutateYaml(
          path.join(
            root,
            "bootstrap/argocd/overlays/dev/execution/kustomization.yaml",
          ),
          (documents) => {
            const patch = documents[0].patches.find(
              (candidate: any) =>
                candidate.target?.name ===
                "(argo-rollouts|cert-manager|database-infrastructure-handoff|external-dns|gateway-api-crds|istio-ingress-gateway|platform-cluster-baseline|tailscale-operator|vault|vault-secrets-operator)",
            );
            patch.target.name =
              "(argo-rollouts|cert-manager|database-infrastructure-handoff|external-dns|gateway-api-crds|istio-ingress-gateway|tailscale-operator|vault|vault-secrets-operator)";
          },
        ),
      /overlapping Argo ownership/,
    ],
    [
      "overlapping Argo ownership",
      (root) => {
        const entrypoint = path.join(
          root,
          "bootstrap/argocd/overlays/dev/platform",
        );
        writeFileSync(
          path.join(entrypoint, "duplicate-owner.application.yaml"),
          `apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: duplicate-platform-owner
  namespace: argocd
spec:
  project: bootstrap
  destination:
    server: https://kubernetes.default.svc
    namespace: platform
  source:
    repoURL: https://github.com/codefly-dev/secure-saas-infra.git
    targetRevision: 1b932460fb825745fdc0a6d8c23fbdf5d196f1bb
    path: gitops/overlays/dev/platform
`,
        );
        mutateYaml(path.join(entrypoint, "kustomization.yaml"), (documents) => {
          documents[0].resources.push("duplicate-owner.application.yaml");
        });
      },
      /overlapping Argo ownership/,
    ],
    [
      "remote destination substitution",
      (root) =>
        mutateYaml(
          path.join(
            root,
            "bootstrap/argocd/base/execution-cluster-baseline.application.yaml",
          ),
          (documents) => {
            documents[0].spec.destination.server =
              "https://remote.example.invalid";
          },
        ),
      /remote destination substitution denied/,
    ],
    [
      "default project",
      (root) =>
        mutateYaml(
          path.join(
            root,
            "bootstrap/argocd/base/apps/cert-manager.application.yaml",
          ),
          (documents) => {
            documents[0].spec.project = "default";
          },
        ),
      /cannot use the default AppProject/,
    ],
    [
      "wildcard repository",
      (root) =>
        mutateYaml(
          path.join(root, "bootstrap/argocd/base/projects.appproject.yaml"),
          (documents) => {
            project(documents, "platform-operators").spec.sourceRepos.push("*");
          },
        ),
      /unsafe source repository/,
    ],
    [
      "tenant cluster authority",
      (root) =>
        mutateYaml(
          path.join(root, "bootstrap/argocd/base/projects.appproject.yaml"),
          (documents) => {
            project(
              documents,
              "tenant-delivery",
            ).spec.clusterResourceWhitelist = [
              { group: "", kind: "Namespace" },
            ];
          },
        ),
      /tenant-delivery cannot own cluster-scoped resources/,
    ],
    [
      "wrong repository",
      (root) =>
        mutateYaml(
          path.join(
            root,
            "bootstrap/argocd/base/apps/cert-manager.application.yaml",
          ),
          (documents) => {
            documents[0].spec.source.repoURL = "https://example.invalid/charts";
          },
        ),
      /repository is outside/,
    ],
    [
      "baseline privilege",
      (root) =>
        mutateYaml(
          path.join(root, "bootstrap/argocd/base/projects.appproject.yaml"),
          (documents) => {
            project(documents, "bootstrap").spec.clusterResourceWhitelist =
              project(
                documents,
                "bootstrap",
              ).spec.clusterResourceWhitelist.filter(
                (resource: any) => resource.kind !== "Namespace",
              );
          },
        ),
      /resource '\/Namespace' is outside AppProject 'bootstrap'/,
    ],
    [
      "unsafe Casbin verb",
      (root) =>
        mutateYaml(
          path.join(root, "bootstrap/argocd/base/projects.appproject.yaml"),
          (documents) => {
            project(documents, "bootstrap").spec.roles[0].policies[0] =
              "p, proj:bootstrap:bootstrap-sync, applications, delete, bootstrap/platform-cluster-baseline, allow";
          },
        ),
      /unsafe Casbin tuple/,
    ],
    [
      "credential-bearing repository",
      (root) =>
        mutateYaml(
          path.join(root, "bootstrap/argocd/base/projects.appproject.yaml"),
          (documents) => {
            project(documents, "bootstrap").spec.sourceRepos[0] =
              "https://user:password@example.invalid/repository";
          },
        ),
      /unsafe source repository/,
    ],
    [
      "mutable production revision",
      (root) =>
        mutateYaml(
          path.join(
            root,
            "bootstrap/argocd/overlays/production/platform/platform-application-patch.yaml",
          ),
          (documents) => {
            documents[0].spec.source.targetRevision = "main";
          },
        ),
      /immutable platform cluster-baseline|unsafe target revision/,
    ],
    [
      "database source path substitution",
      (root) =>
        mutateYaml(
          path.join(
            root,
            "bootstrap/argocd/base/database-infrastructure-handoff.application.yaml",
          ),
          (documents) => {
            documents[0].spec.source.path =
              "gitops/generated/tenant-controlled";
          },
        ),
      /database-infrastructure-handoff must bind the exact project, repository, environment path, and destination/,
    ],
    [
      "database automated sync",
      (root) =>
        mutateYaml(
          path.join(
            root,
            "bootstrap/argocd/base/database-infrastructure-handoff.application.yaml",
          ),
          (documents) => {
            documents[0].spec.syncPolicy.automated = {
              prune: true,
              selfHeal: true,
            };
          },
        ),
      /must require an explicit reviewed sync/,
    ],
    [
      "database controller identity substitution",
      (root) =>
        mutateYaml(
          path.join(
            root,
            "base/kyverno/authorize-database-infrastructure-controller.yaml",
          ),
          (documents) => {
            documents[0].spec.rules[0].validate.deny.conditions.any[0].value =
              "system:serviceaccount:default:attacker";
          },
        ),
      /must authorize only the pinned Argo application-controller identity/,
    ],
    [
      "restricted namespace label removal",
      (root) =>
        mutateYaml(
          path.join(root, "base/namespaces/agent-broker.yaml"),
          (documents) => {
            delete documents[0].metadata.labels[
              "security.deus.dev/service-account-token-policy"
            ];
          },
        ),
      /restricted namespace enrollment/,
    ],
    [
      "default ServiceAccount re-enables tokens",
      (root) =>
        mutateYaml(
          path.join(
            root,
            "base/namespaces/restricted-default-serviceaccounts.yaml",
          ),
          (documents) => {
            documents[0].automountServiceAccountToken = true;
          },
        ),
      /default ServiceAccount protection/,
    ],
    [
      "broken development Argo overlay",
      (root) => {
        const file = path.join(
          root,
          "bootstrap/argocd/overlays/dev/platform/kustomization.yaml",
        );
        const value = readFileSync(file, "utf8");
        writeFileSync(file, `${value}\n  - missing-resource.yaml\n`);
      },
      /failed to render.*overlays\/dev\/platform/s,
    ],
  ];
  for (const [label, mutate, expected] of cases) {
    const root = mkdtempSync(path.join(os.tmpdir(), "deus-gitops-boundary-"));
    const copy = path.join(root, "gitops");
    try {
      cpSync("gitops", copy, { recursive: true });
      mutate(copy);
      const result = spawnSync(
        process.execPath,
        ["scripts/validate-gitops.mjs", "--gitops-root", copy],
        { encoding: "utf8" },
      );
      assert.notEqual(result.status, 0, label);
      assert.match(`${result.stdout}\n${result.stderr}`, expected, label);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});

function mutateYaml(file: string, mutate: (documents: any[]) => void) {
  const documents = parseAllDocuments(readFileSync(file, "utf8")).map(
    (document) => document.toJSON(),
  );
  mutate(documents);
  writeFileSync(
    file,
    `${documents.map((document) => stringify(document).trim()).join("\n---\n")}\n`,
  );
}

function project(documents: any[], name: string): any {
  const result = documents.find(
    (document) =>
      document.kind === "AppProject" && document.metadata?.name === name,
  );
  assert.ok(result, `missing AppProject '${name}'`);
  return result;
}
