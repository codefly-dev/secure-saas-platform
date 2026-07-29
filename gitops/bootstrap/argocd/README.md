# Argo CD Bootstrap Applications

These manifests are intended for the management Argo CD instance after the cluster exists.

The Tailscale operator Application is intentionally separated from the cluster baseline because it needs OAuth credentials or workload identity federation configured first.

For production, do not commit Tailscale OAuth secrets. Prefer Vault-backed injection or workload identity federation once your issuer and Tailscale policy are ready.

Bootstrap order is controlled with Argo CD sync waves. Shared applications live
under `base/apps`, but only the applications assigned to a cluster role render
from `overlays/<environment>/<platform|execution>`.

The bootstrap renders five explicit AppProjects before any Application:

- `default` is deny-all;
- `bootstrap` owns the role-specific IaC cluster baseline;
- `platform-operators` owns the pinned platform controllers;
- `security` owns Kyverno, Falco, Vault, and Vault Secrets Operator; and
- `tenant-delivery` has no cluster-scoped, RBAC, Secret, CRD, admission, or
  controller authority.

Source repositories, destinations, resource kinds, OIDC groups, and project
role policies are exact and wildcard-free. `scripts/validate-gitops.mjs`
renders each role entrypoint, rejects a second role or overlapping resource
owner, checks every Application against its project, and checks the in-repo
baseline resources against their project allowlist.

The Argo CD Pulumi stack requires an OIDC issuer, client ID, secret-key
reference, and exact administrator group. It disables the local admin and
anonymous users, gives the default authenticated role no ambient read access,
and enables PKCE. The referenced OIDC secret must exist before login; the
configuration never accepts the secret value itself.

1. cert-manager
2. Gateway API CRDs
3. Istio ambient control plane: base, istiod, CNI, ztunnel
4. internal Istio ingress gateway
5. Kyverno, metrics-server, observability, Vault Secrets Operator, Tailscale Operator
6. the selected cluster-role baseline manifests

Istio is configured for ambient mode. Application namespaces are enrolled with `istio.io/dataplane-mode: ambient`; do not add sidecar injection labels unless we explicitly migrate a namespace to sidecar mode.

The platform role additionally owns cert-manager, Gateway API and the Istio
ingress gateway, Vault, Vault Secrets Operator, ExternalDNS, Argo Rollouts,
Tailscale, and the database-infrastructure handoff. The execution role owns only
the shared mesh, policy, metrics, observability, and runtime-security operators.

Every in-repository Application source is pinned to a full Git commit SHA.
Pulumi publishes `argocdBootstrapHandoff` with the exact cluster role, cluster
name, credential-free repository URL, revision, and bootstrap entrypoint. Those
fields contain no access role, token, secret, endpoint, or certificate data.
