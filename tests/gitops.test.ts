import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

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
  const limits = readFileSync("gitops/base/quotas/execution-limits.yaml", "utf8");
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

test("application images require Sigstore signatures, SLSA provenance, and SPDX SBOMs", () => {
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
  assert.match(policy, /predicateType: https:\/\/slsa.dev\/provenance\/v1/);
  assert.match(policy, /predicateType: https:\/\/spdx.dev\/Document/);
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

test("Argo CD bootstrap has environment overlays for platform and execution clusters", () => {
  for (const environment of ["dev", "staging", "production"]) {
    const bootstrap = readFileSync(
      `gitops/bootstrap/argocd/overlays/${environment}/kustomization.yaml`,
      "utf8",
    );
    const platformPatch = readFileSync(
      `gitops/bootstrap/argocd/overlays/${environment}/platform-application-patch.yaml`,
      "utf8",
    );
    const executionPatch = readFileSync(
      `gitops/bootstrap/argocd/overlays/${environment}/execution-application-patch.yaml`,
      "utf8",
    );

    assert.match(bootstrap, /platform-cluster-baseline/);
    assert.match(bootstrap, /execution-cluster-baseline/);
    assert.match(
      platformPatch,
      new RegExp(`gitops/overlays/${environment}/platform`),
    );
    assert.match(
      executionPatch,
      new RegExp(`gitops/overlays/${environment}/execution`),
    );
  }
});

test("all GitOps overlays render", () => {
  const overlays = [
    "gitops/bootstrap/argocd",
    "gitops/bootstrap/argocd/overlays/staging",
    "gitops/bootstrap/argocd/overlays/production",
    "gitops/overlays/dev/platform",
    "gitops/overlays/dev/execution",
    "gitops/overlays/staging/platform",
    "gitops/overlays/staging/execution",
    "gitops/overlays/production/platform",
    "gitops/overlays/production/execution",
  ];

  for (const overlay of overlays) {
    assert.doesNotThrow(
      () => execFileSync("kustomize", ["build", overlay], { stdio: "pipe" }),
      overlay,
    );
  }
});
