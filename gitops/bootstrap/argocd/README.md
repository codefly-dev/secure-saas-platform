# Argo CD Bootstrap Applications

These manifests are intended for the management Argo CD instance after the cluster exists.

The Tailscale operator Application is intentionally separated from the cluster baseline because it needs OAuth credentials or workload identity federation configured first.

For production, do not commit Tailscale OAuth secrets. Prefer Vault-backed injection or workload identity federation once your issuer and Tailscale policy are ready.

Bootstrap order is controlled with Argo CD sync waves. Shared applications live under `base/apps`, and environment overlays live under `overlays/<environment>`.

1. cert-manager
2. Gateway API CRDs
3. Istio ambient control plane: base, istiod, CNI, ztunnel
4. internal Istio ingress gateway
5. Kyverno, metrics-server, observability, Vault Secrets Operator, Tailscale Operator
6. cluster baseline manifests

Istio is configured for ambient mode. Application namespaces are enrolled with `istio.io/dataplane-mode: ambient`; do not add sidecar injection labels unless we explicitly migrate a namespace to sidecar mode.

The root `gitops/bootstrap/argocd` kustomization points to the `dev` overlay by default. Use `gitops/bootstrap/argocd/overlays/staging` or `gitops/bootstrap/argocd/overlays/production` for those environments.
