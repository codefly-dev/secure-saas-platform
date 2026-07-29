# Promoted manifest bundle landing tree

Codefly's separate deployment/promotion driver lands module and service
manifest bundles here. The originating service/module plugins never need to
know this repository exists: they emit plain Kubernetes manifests, and the
promotion driver places each bundle under
`gitops/generated/modules/<environment>/<module>/<service>` and records it in
`inventory.json`.

`inventory.json` is the provenance handoff. It conforms to
`schemas/codefly-manifest-bundle-inventory-v1.schema.json` and pins, for every
bundle, the exact bundle digest, the producing plugin identity and contract
version, the environment, the module/service identity, and the reviewed
immutable source revision that produced it.

The landing tree is plugin-owned desired state only. It must never contain
reconciliation authority:

- no Argo CD `Application`, `ApplicationSet`, or `AppProject` objects (any
  `argoproj.io` resource),
- no repository credentials or `Secret` objects,
- no `repoURL`, `targetRevision`, `sourceRepos`, or `repositories` bindings.

The platform/promotion layer owns the Argo CD objects that bind approved
bundle paths to clusters. Those live under `gitops/bootstrap/argocd`, preserve
cluster-role separation, and pin immutable revisions. `npm run
validate:manifest-bundles` enforces the whole contract and runs on every push
through `npm run check`, so the same rules cover local qualification and
production promotion.
