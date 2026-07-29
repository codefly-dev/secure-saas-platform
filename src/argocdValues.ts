export const ARGOCD_CHART_VERSION = "10.2.1";
export const ARGOCD_CHART_DIGEST =
  "27e930e366d22c999002008ad5ec7961bda00410a84287210d0fffbee8150885";
export const ARGOCD_CHART_REPOSITORY = "https://argoproj.github.io/argo-helm";

export interface ArgocdHelmConfig {
  clusterRole: "platform" | "execution";
  argocdHostname: string;
  oidcIssuer: string;
  oidcClientId: string;
  oidcClientSecretRef: string;
  oidcAdminGroup: string;
}

export function argocdHelmValues(config: ArgocdHelmConfig) {
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
        "resource.respectRBAC": "strict",
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
        rules: argocdControllerRules(config.clusterRole),
      },
      resources: {
        requests: { cpu: "250m", memory: "1Gi" },
        limits: { cpu: "2", memory: "2Gi" },
      },
      metrics: {
        enabled: true,
        serviceMonitor: { enabled: false },
      },
    },
    server: {
      replicas: 2,
      service: { type: "ClusterIP" },
      metrics: {
        enabled: true,
        serviceMonitor: { enabled: false },
      },
      extraArgs: ["--insecure=false"],
    },
    repoServer: {
      replicas: 2,
      metrics: {
        enabled: true,
        serviceMonitor: { enabled: false },
      },
    },
    applicationSet: {
      replicas: 1,
      metrics: {
        enabled: true,
        serviceMonitor: { enabled: false },
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

export function argocdControllerRules(
  clusterRole: ArgocdHelmConfig["clusterRole"],
) {
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
      apiGroups: ["admissionregistration.k8s.io"],
      resources: [
        "mutatingwebhookconfigurations",
        "validatingadmissionpolicies",
        "validatingadmissionpolicybindings",
        "validatingwebhookconfigurations",
      ],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["apiextensions.k8s.io"],
      resources: ["customresourcedefinitions"],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["apiregistration.k8s.io"],
      resources: ["apiservices"],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["apps"],
      resources: ["daemonsets", "deployments", "statefulsets"],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["argoproj.io"],
      resources: ["applications", "applicationsets", "appprojects"],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["autoscaling"],
      resources: ["horizontalpodautoscalers"],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["batch"],
      resources: ["cronjobs", "jobs"],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["gateway.networking.k8s.io"],
      resources: ["gateways", "httproutes"],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["kyverno.io"],
      resources: ["clusterpolicies"],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["monitoring.coreos.com"],
      resources: [
        "alertmanagers",
        "podmonitors",
        "prometheuses",
        "prometheusrules",
        "servicemonitors",
      ],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["networking.k8s.io"],
      resources: ["ingresses", "networkpolicies"],
      verbs: managedVerbs,
    },
    ...(clusterRole === "execution"
      ? [
          {
            apiGroups: ["node.k8s.io"],
            resources: ["runtimeclasses"],
            verbs: managedVerbs,
          },
        ]
      : []),
    {
      apiGroups: ["policy"],
      resources: ["poddisruptionbudgets"],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["rbac.authorization.k8s.io"],
      resources: [
        "clusterroles",
        "clusterrolebindings",
        "roles",
        "rolebindings",
      ],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["security.istio.io"],
      resources: ["authorizationpolicies", "peerauthentications"],
      verbs: managedVerbs,
    },
    ...(clusterRole === "platform"
      ? [
          {
            apiGroups: ["tailscale.com"],
            resources: ["connectors"],
            verbs: managedVerbs,
          },
        ]
      : []),
    {
      apiGroups: ["telemetry.istio.io"],
      resources: ["telemetries"],
      verbs: managedVerbs,
    },
    {
      apiGroups: ["authorization.k8s.io"],
      resources: ["selfsubjectaccessreviews"],
      verbs: ["create"],
    },
  ];
}
