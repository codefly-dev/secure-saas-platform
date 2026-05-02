import * as aws from "@pulumi/aws";
import * as k8s from "@pulumi/kubernetes";
import * as pulumi from "@pulumi/pulumi";
import { ArgocdConfig, baseTags, named } from "./config";

export interface ArgocdResult {
  namespace: k8s.core.v1.Namespace;
  release: k8s.helm.v3.Release;
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

  // Build a kubeconfig that uses `aws eks get-token` for auth so the
  // running Pulumi shell's AWS credentials authenticate to the cluster.
  const kubeconfig = pulumi
    .all([cluster, aws.config.region])
    .apply(([clusterEntry, region]) =>
      JSON.stringify({
        apiVersion: "v1",
        clusters: [
          {
            name: "deus",
            cluster: {
              server: clusterEntry.endpoint,
              "certificate-authority-data": clusterEntry.certificateAuthority.data,
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
                args: [
                  "eks",
                  "get-token",
                  "--cluster-name",
                  clusterEntry.name,
                  "--region",
                  region,
                ],
              },
            },
          },
        ],
      }),
    );

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
      values: {
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
          },
          rbac: {
            "policy.default": "role:readonly",
          },
        },
        controller: {
          replicas: 1,
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
      },
    },
    { provider, dependsOn: namespace },
  );

  // Apply the in-repo bootstrap kustomize so Argo CD self-manages every
  // platform application + per-cluster baseline. After this step Argo CD
  // pulls from the configured GitOps repo on its own.
  const bootstrap = new k8s.kustomize.v2.Directory(
    named("argocd-bootstrap"),
    {
      directory: config.bootstrapDirectory,
    },
    { provider, dependsOn: release },
  );

  return { namespace, release, bootstrap };
}
