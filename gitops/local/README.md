# Local k3d GitOps

This is the developer companion to the production platform and execution
cluster overlays. It creates one disposable k3d cluster, installs the reviewed
Argo CD chart artifact, serves an exact snapshot of `gitops/` from a local
read-only Git remote, and waits until Argo CD reports the portable baseline
`Synced` and `Healthy`.

```sh
./scripts/local-k3d-up
./scripts/local-k3d-status
./scripts/local-k3d-down
```

All Kubernetes commands use the generated kubeconfig under
`.local/k3d/codefly-local/`; the scripts do not change the current kubectl
context. The API binds to loopback. The kubeconfig, local Git snapshot, chart,
generated local values, and evidence report live in the same ignored
mode-restricted state directory. Cloud credential environment variables are
removed from every child process.

The local overlay shares the provider-neutral namespace, quota, and
network-policy bases. It is deliberately one combined developer cluster. It
does not pretend to validate:

- the production platform/execution multi-cluster isolation gate;
- EKS Auto Mode, Pod Identity, ECR, NLB, Route 53, KMS, gp3, or other AWS APIs;
- the `deus-microvm` runtime, because k3d does not provide its Kata handler;
- host-level Falco behavior; or
- production Vault storage/unseal or Tailscale identity.

The AMD64 and ARM64 two-cluster CI jobs remain the promotion gate for exact
role isolation. AWS-specific behavior remains an AWS qualification gate.

The harness derives its local-sized Argo values and controller rules from
`src/argocdValues.ts`, pulls the same chart version used by production, and
refuses the artifact unless its SHA-256 digest matches the reviewed pin.
Generated product bundles can join the local overlay only through the
schema-validated `gitops/generated/modules` landing contract and a
platform-owned Application/AppProject binding.
