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
contains references and digests only: cluster role, endpoint and
content-addressed CA identity, bootstrap access-entry reference, cloud resource
IDs, Git source, policy digests, and IaC evidence digests. The cloud owner
materializes it from the `platformIacHandoff` Pulumi stack output with
`npm run handoff:publish` in `codefly-dev/secure-saas-infra`.

Verify it before cluster access:

```sh
node scripts/verify-platform-iac-handoff.mjs \
  --handoff /run/platform-promotion/handoff.json \
  --public-key /run/platform-promotion/infra-handoff.pub
```

`npm run activate -- ... --execute` checks the signed handoff against the
selected kubeconfig endpoint, CA bytes, and bootstrap role, installs the
reviewed Argo CD chart, and applies only the role-specific bootstrap
Applications. From that point, Git owns reconciliation.

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
or Kubernetes-object ownership overlap, mutable revisions, cross-path writes,
and stale inventory/digest mismatches. The live landing tree starts empty;
non-deployable examples remain under `fixtures/manifest-bundles/`. The same
contract covers local qualification and production promotion.

## Local k3d GitOps

The production platform/execution split and the developer k3d companion live
in this repository. Local k3d reconciles the portable baseline through Argo CD
from an exact disposable Git snapshot; it never direct-applies that baseline
as the final state.

```sh
npm run local:doctor
npm run local:up
npm run local:status
npm run local:down
```

The local API is loopback-only, the Argo chart must match the reviewed
production digest, subprocesses receive no AWS/Pulumi/cloud credential
variables, and `down` refuses resources without exact ownership markers. Local
state and kubeconfig credentials remain mode-restricted under ignored
`.local/`. This single combined cluster is a developer convenience; AMD64 and
ARM64 CI still prove exact platform/execution isolation with two disposable
clusters, and AWS behavior remains an AWS gate.

An existing exact-name k3d registry is reused only after its published ports
are proven loopback-only. It remains an independently preserved resource when
the cluster is removed.
