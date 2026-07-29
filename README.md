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

## Manifest bundle landing

Codefly's separate deployment/promotion driver lands module and service
manifest bundles under `gitops/generated/modules/<environment>/<module>/<service>`
and records a provenance inventory in
`gitops/generated/modules/inventory.json`. Service and module plugins only emit
plain Kubernetes manifests; they never own repository source bindings or Argo CD
reconciliation objects, and they never need to know this repository exists.

The inventory conforms to
`schemas/codefly-manifest-bundle-inventory-v1.schema.json` and pins, per bundle,
the exact bundle digest, the producing plugin identity and contract version, the
environment, the module/service identity, and the reviewed immutable source
revision. The platform/promotion layer owns the Argo CD objects that bind
approved bundle paths to clusters.

```sh
npm run validate:manifest-bundles
```

Part of `npm run check`, this gate rejects plugin-owned Argo objects,
repository credentials, `repoURL`/`targetRevision` bindings, landing-path
ownership overlap, mutable revisions, cross-path writes, and stale
inventory/digest mismatches. The same contract covers local qualification and
production promotion.
