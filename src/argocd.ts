import * as aws from "@pulumi/aws";
import * as k8s from "@pulumi/kubernetes";
import * as pulumi from "@pulumi/pulumi";
import { ArgocdConfig, baseTags, named } from "./config";

export interface ArgocdResult {
  namespace: k8s.core.v1.Namespace;
  release: k8s.helm.v3.Release;
  databaseNamespace: k8s.core.v1.Namespace;
  databaseRelease: k8s.helm.v3.Release;
  bootstrap: k8s.kustomize.v2.Directory;
}

export function createArgocd(config: ArgocdConfig): ArgocdResult {
  const platformStack = new pulumi.StackReference("platform-cluster", {
    name: config.clusterStackRef,
  });

  const clusters = platformStack.requireOutput("eksClusters") as pulumi.Output<
    Record<
      string,
      {
        name: string;
        endpoint: string;
        certificateAuthority: { data: string };
      }
    >
  >;

  const cluster = clusters.apply((entries) => {
    const entry = entries[config.clusterName];
    if (!entry) {
      throw new Error(
        `argocd: cluster '${config.clusterName}' not found in platform stack outputs.`,
      );
    }
    return entry;
  });

  // The current operator session may be in the management account. Always
  // name the exact member-account role authorized by the cluster's EKS access
  // entry; never rely on whichever ambient IAM principal happens to run Pulumi.
  const kubeconfig = pulumi
    .all([cluster, aws.config.region])
    .apply(([clusterEntry, region]) => {
      if (!region) {
        throw new Error("argocd: aws:region must be configured explicitly.");
      }
      return JSON.stringify({
        apiVersion: "v1",
        clusters: [
          {
            name: "deus",
            cluster: {
              server: clusterEntry.endpoint,
              "certificate-authority-data":
                clusterEntry.certificateAuthority.data,
            },
          },
        ],
        contexts: [
          { name: "deus", context: { cluster: "deus", user: "deus" } },
        ],
        "current-context": "deus",
        users: [
          {
            name: "deus",
            user: {
              exec: {
                apiVersion: "client.authentication.k8s.io/v1beta1",
                command: "aws",
                args: argocdExecCredentialArgs(
                  clusterEntry.name,
                  region,
                  config.clusterAccessRoleArn,
                ),
              },
            },
          },
        ],
      });
    });

  const provider = new k8s.Provider(named("argocd-k8s-provider"), {
    kubeconfig,
    enableServerSideApply: true,
  });

  const namespace = new k8s.core.v1.Namespace(
    named("argocd-namespace"),
    {
      metadata: {
        name: "argocd",
        labels: {
          "security.deus.dev/trust-zone": "platform-control-plane",
          "pod-security.kubernetes.io/enforce": "baseline",
          "pod-security.kubernetes.io/audit": "restricted",
          "pod-security.kubernetes.io/warn": "restricted",
        },
      },
    },
    { provider },
  );

  const release = new k8s.helm.v3.Release(
    named("argocd-release"),
    {
      chart: "argo-cd",
      version: config.chartVersion,
      repositoryOpts: {
        repo: "https://argoproj.github.io/argo-helm",
      },
      namespace: namespace.metadata.name,
      cleanupOnFail: true,
      atomic: false,
      values: argocdHelmValues(config),
    },
    { provider, dependsOn: namespace },
  );

  const databaseNamespace = new k8s.core.v1.Namespace(
    named("argocd-database-namespace"),
    {
      metadata: {
        name: "argocd-database",
        labels: {
          "security.deus.dev/trust-zone":
            "database-infrastructure-control-plane",
          "pod-security.kubernetes.io/enforce": "restricted",
          "pod-security.kubernetes.io/audit": "restricted",
          "pod-security.kubernetes.io/warn": "restricted",
        },
      },
    },
    { provider },
  );

  const databaseRelease = new k8s.helm.v3.Release(
    named("argocd-database-release"),
    {
      chart: "argo-cd",
      version: config.chartVersion,
      repositoryOpts: {
        repo: "https://argoproj.github.io/argo-helm",
      },
      namespace: databaseNamespace.metadata.name,
      cleanupOnFail: true,
      atomic: false,
      values: databaseArgocdHelmValues(),
    },
    { provider, dependsOn: [databaseNamespace, release] },
  );

  // Apply the in-repo bootstrap kustomize so Argo CD self-manages every
  // platform application + per-cluster baseline. After this step Argo CD
  // pulls from the configured GitOps repo on its own.
  const bootstrap = new k8s.kustomize.v2.Directory(
    named("argocd-bootstrap"),
    {
      directory: config.bootstrapDirectory,
    },
    { provider, dependsOn: [release, databaseRelease] },
  );

  return {
    namespace,
    release,
    databaseNamespace,
    databaseRelease,
    bootstrap,
  };
}

export function argocdExecCredentialArgs(
  clusterName: string,
  region: string,
  roleArn: string,
): string[] {
  return [
    "eks",
    "get-token",
    "--cluster-name",
    clusterName,
    "--region",
    region,
    "--role-arn",
    roleArn,
  ];
}

export function argocdHelmValues(config: ArgocdConfig) {
  return {
    fullnameOverride: "argocd",
    global: {
      domain: config.argocdHostname,
    },
    configs: {
      params: {
        "server.insecure": false,
        "server.repo.server.timeout.seconds": 180,
      },
      cm: {
        "timeout.reconciliation": "180s",
        "application.resourceTrackingMethod": "annotation",
        "exec.enabled": false,
        "users.anonymous.enabled": false,
        "admin.enabled": false,
        "oidc.config": [
          "name: Organization OIDC",
          `issuer: ${config.oidcIssuer}`,
          `clientID: ${config.oidcClientId}`,
          `clientSecret: ${config.oidcClientSecretRef}`,
          'requestedScopes: ["openid", "profile", "email", "groups"]',
          'requestedIDTokenClaims: {"groups": {"essential": true}}',
          "enablePKCEAuthentication: true",
        ].join("\n"),
      },
      rbac: {
        "policy.default": "role:authenticated",
        "policy.csv": [
          "p, role:authenticated, applications, get, denied/denied, deny",
          `g, ${config.oidcAdminGroup}, role:admin`,
        ].join("\n"),
        scopes: "[groups]",
      },
    },
    controller: {
      replicas: 1,
      clusterRoleRules: {
        enabled: true,
        rules: sharedArgocdControllerRules(),
      },
      resources: {
        requests: { cpu: "250m", memory: "1Gi" },
        limits: { cpu: "2", memory: "2Gi" },
      },
      metrics: {
        enabled: true,
        serviceMonitor: { enabled: true },
      },
    },
    server: {
      replicas: 2,
      // ClusterIP only; reachable via Tailscale operator. No public LB.
      service: { type: "ClusterIP" },
      metrics: {
        enabled: true,
        serviceMonitor: { enabled: true },
      },
      extraArgs: ["--insecure=false"],
    },
    repoServer: {
      replicas: 2,
      metrics: {
        enabled: true,
        serviceMonitor: { enabled: true },
      },
    },
    applicationSet: {
      replicas: 1,
      metrics: {
        enabled: true,
        serviceMonitor: { enabled: true },
      },
    },
    notifications: { enabled: false },
    dex: { enabled: false },
    redis: { enabled: true },
    crds: { install: true },
  };
}

export function databaseArgocdHelmValues() {
  return {
    fullnameOverride: "argocd-database",
    crds: { install: false },
    configs: {
      params: {
        "server.insecure": false,
      },
      cm: {
        "application.resourceTrackingMethod": "annotation",
        "resource.respectRBAC": "strict",
        "exec.enabled": false,
        "users.anonymous.enabled": false,
        "admin.enabled": false,
      },
      rbac: {
        "policy.default": "",
        "policy.csv": "",
      },
    },
    controller: {
      replicas: 1,
      serviceAccount: {
        create: true,
        name: "database-infrastructure-application-controller",
        automountServiceAccountToken: true,
      },
      clusterRoleRules: {
        enabled: true,
        rules: databaseInfrastructureControllerRules(),
      },
      resources: {
        requests: { cpu: "100m", memory: "256Mi" },
        limits: { cpu: "1", memory: "1Gi" },
      },
    },
    applicationSet: { enabled: false },
    notifications: { enabled: false },
    dex: { enabled: false },
    server: {
      replicas: 1,
      service: { type: "ClusterIP" },
    },
    repoServer: { replicas: 1 },
    redis: { enabled: true },
  };
}

export function databaseInfrastructureControllerRules() {
  const managedVerbs = ["get", "list", "watch", "create", "update", "patch"];
  return [
    {
      apiGroups: [""],
      resources: ["namespaces", "serviceaccounts"],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["networking.k8s.aws"],
      resources: ["applicationnetworkpolicies"],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["eks.amazonaws.com"],
      resources: ["nodeclasses"],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["karpenter.sh"],
      resources: ["nodepools"],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["authorization.k8s.io"],
      resources: ["selfsubjectaccessreviews"],
      verbs: ["create"],
    },
  ];
}

function sharedArgocdControllerRules() {
  const managedVerbs = [
    "get",
    "list",
    "watch",
    "create",
    "update",
    "patch",
    "delete",
  ];
  return [
    {
      apiGroups: [""],
      resources: [
        "configmaps",
        "endpoints",
        "events",
        "limitranges",
        "namespaces",
        "persistentvolumeclaims",
        "resourcequotas",
        "secrets",
        "serviceaccounts",
        "services",
      ],
      verbs: managedVerbs,
    },
    {
      apiGroups: [
        "admissionregistration.k8s.io",
        "apiextensions.k8s.io",
        "apiregistration.k8s.io",
        "apps",
        "argoproj.io",
        "autoscaling",
        "batch",
        "gateway.networking.k8s.io",
        "monitoring.coreos.com",
        "networking.k8s.io",
        "node.k8s.io",
        "policy",
        "rbac.authorization.k8s.io",
        "security.istio.io",
        "tailscale.com",
        "telemetry.istio.io",
      ],
      resources: [
        "applications",
        "applicationsets",
        "appprojects",
        "authorizationpolicies",
        "clusterroles",
        "clusterrolebindings",
        "cronjobs",
        "customresourcedefinitions",
        "daemonsets",
        "deployments",
        "gateways",
        "horizontalpodautoscalers",
        "httproutes",
        "jobs",
        "mutatingwebhookconfigurations",
        "networkpolicies",
        "peerauthentications",
        "poddisruptionbudgets",
        "podmonitors",
        "prometheusrules",
        "roles",
        "rolebindings",
        "runtimeclasses",
        "servicemonitors",
        "statefulsets",
        "telemetries",
        "validatingwebhookconfigurations",
      ],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["authorization.k8s.io"],
      resources: ["selfsubjectaccessreviews"],
      verbs: ["create"],
    },
  ];
}
