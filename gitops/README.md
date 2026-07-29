# GitOps Baseline

This directory contains the Kubernetes desired state activated from a verified
cloud-IaC handoff.

The intent is:

- Argo CD manages these manifests.
- Cluster access is private and controlled through EKS Access Entries.
- Istio runs in ambient mode, with Gateway API CRDs, Istio CNI, ztunnel, and an internal ingress gateway managed by Argo CD.
- Every workload namespace starts with restricted pod security labels.
- Network policy starts at default-deny.
- Kyverno is the first policy engine. Gatekeeper can be added later if required by customer policy.
- Application images must be digest-pinned, Sigstore-verified, and backed by SLSA provenance plus SPDX SBOM attestations.
- Execution pods must use the `deus-microvm` RuntimeClass, include per-job audit metadata, and stay inside namespace quota and limit controls; regular container execution in the `execution` namespace is denied.
- cert-manager, metrics-server, kube-prometheus-stack, Vault Secrets Operator, Kyverno, Tailscale Operator, and Istio are bootstrap applications.

The `clusters/*/kustomization.yaml` files are the cluster entry points.

Environment overlays live under `gitops/overlays/<environment>/<cluster-role>`.

Bootstrap entrypoints live under
`gitops/bootstrap/argocd/overlays/<environment>/<cluster-role>`. Each
entrypoint creates exactly one cluster baseline Application for its target:

- `platform-cluster-baseline`
- `execution-cluster-baseline`

The activation CLI always selects both the signed environment and role. For
local rendering:

```sh
kubectl apply -k gitops/bootstrap/argocd/overlays/staging/platform
kubectl apply -k gitops/bootstrap/argocd/overlays/staging/execution
```
