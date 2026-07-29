import * as aws from "@pulumi/aws";
import * as k8s from "@pulumi/kubernetes";
import * as pulumi from "@pulumi/pulumi";
import {
  ArgocdConfig,
  argocdBootstrapDirectory,
  argocdBootstrapHandoff,
  baseTags,
  named,
} from "./config";
export {
  argocdControllerRules,
  argocdHelmValues,
  databaseArgocdHelmValues,
  databaseInfrastructureControllerRules,
} from "./argocdValues";
import {
  ARGOCD_CHART_REPOSITORY,
  argocdHelmValues,
  databaseArgocdHelmValues,
} from "./argocdValues";

export interface ArgocdResult {
  namespace: k8s.core.v1.Namespace;
  release: k8s.helm.v3.Release;
  databaseNamespace?: k8s.core.v1.Namespace;
  databaseRelease?: k8s.helm.v3.Release;
  bootstrap: k8s.kustomize.v2.Directory;
  handoff: {
    clusterRole: "platform" | "execution";
    clusterName: string;
    repository: string;
    revision: string;
    bootstrapEntrypoint: string;
  };
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
        repo: ARGOCD_CHART_REPOSITORY,
      },
      namespace: namespace.metadata.name,
      cleanupOnFail: true,
      atomic: false,
      values: argocdHelmValues(config),
    },
    { provider, dependsOn: namespace },
  );

  const databaseNamespace =
    config.clusterRole === "platform"
      ? new k8s.core.v1.Namespace(
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
        )
      : undefined;

  const databaseRelease = databaseNamespace
    ? new k8s.helm.v3.Release(
        named("argocd-database-release"),
        {
          chart: "argo-cd",
          version: config.chartVersion,
          repositoryOpts: {
            repo: ARGOCD_CHART_REPOSITORY,
          },
          namespace: databaseNamespace.metadata.name,
          cleanupOnFail: true,
          atomic: false,
          values: databaseArgocdHelmValues(),
        },
        { provider, dependsOn: [databaseNamespace, release] },
      )
    : undefined;

  const bootstrap = new k8s.kustomize.v2.Directory(
    named("argocd-bootstrap"),
    {
      directory: argocdBootstrapDirectory(config),
    },
    {
      provider,
      dependsOn: databaseRelease ? [release, databaseRelease] : [release],
    },
  );

  return {
    namespace,
    release,
    databaseNamespace,
    databaseRelease,
    bootstrap,
    handoff: argocdBootstrapHandoff(config),
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
