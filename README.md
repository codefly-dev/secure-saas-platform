# Secure SaaS platform

This repository is the protected release owner for the Kubernetes and GitOps
layer of the secure SaaS platform. Cloud IaC ends at a signed, credential-free
handoff; this repository verifies that handoff, minimally activates Argo CD,
and then gives reconciliation ownership to an immutable Git revision.

## Qualification

```sh
npm ci --ignore-scripts
npm run check
npm run qualify:argocd-two-cluster
```

The two-cluster qualification creates a disposable Git remote, installs Argo
CD into isolated platform and execution K3s clusters, and requires every
automated Application to report the exact source revision, `Synced`, and
`Healthy`. CI runs the same boundary on AMD64 and ARM64.

## Activation

The cloud owner publishes a
`infrastructure.deus.dev/platform-iac-handoff/v1` document and signs its
canonical `spec` with the reviewed ECDSA P-256 release key. The document
contains references and digests only: cluster role, endpoint and CA reference,
bootstrap identity reference, cloud resource IDs, Git source, policy digests,
and IaC evidence digests.

Verify it before cluster access:

```sh
node scripts/verify-platform-iac-handoff.mjs \
  --handoff /run/platform-promotion/handoff.json \
  --public-key /run/platform-promotion/infra-handoff.pub
```

`npm run activate -- ... --execute` checks the signed handoff against the
selected kubeconfig, installs the reviewed Argo CD chart, and applies only the
role-specific bootstrap Applications. From that point, Git owns reconciliation.

Production promotion is restricted to a reviewed signed commit or protected
immutable `v*` tag. The protected `production` environment runs activation on
the promotion runner and uploads evidence containing the resolved and observed
Argo revision, sync status, and health.
