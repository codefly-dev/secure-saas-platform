#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import path from "node:path";
import { parseAllDocuments } from "yaml";

const gitopsRoot = argument("--gitops-root") ?? "gitops";
const environments = ["dev", "staging", "production"];
const clusterRoles = ["platform", "execution"];
const bootstrapEntrypoints = environments.flatMap((environment) =>
  clusterRoles.map(
    (clusterRole) => `bootstrap/argocd/overlays/${environment}/${clusterRole}`,
  ),
);
const baselineEntrypoints = environments.flatMap((environment) =>
  clusterRoles.map((clusterRole) => `overlays/${environment}/${clusterRole}`),
);
const relativeOverlays = [...bootstrapEntrypoints, ...baselineEntrypoints];
const overlays = relativeOverlays.map((overlay) =>
  path.join(gitopsRoot, overlay),
);

const standalone = spawnSync("kustomize", ["version"], { stdio: "ignore" });
const command = standalone.error ? "kubectl" : "kustomize";
const renderedByOverlay = new Map();

for (const overlay of overlays) {
  const args =
    command === "kustomize" ? ["build", overlay] : ["kustomize", overlay];
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) {
    console.error(
      `error: neither standalone kustomize nor kubectl kustomize is available (${result.error.message})`,
    );
    process.exit(1);
  }
  if (result.status !== 0) {
    console.error(`error: failed to render ${overlay}`);
    process.stderr.write(result.stderr);
    process.exit(result.status ?? 1);
  }
  renderedByOverlay.set(overlay, parseDocuments(result.stdout, overlay));
}

const argoOverlays = overlays.slice(0, bootstrapEntrypoints.length);
for (const overlay of argoOverlays) {
  const identity = bootstrapIdentity(overlay);
  validateRoleInventory(
    renderedByOverlay.get(overlay),
    overlay,
    identity,
    renderedByOverlay,
  );
  validateArgoBoundary(renderedByOverlay.get(overlay), overlay, identity);
  validateBaselineResources(renderedByOverlay.get(overlay), renderedByOverlay);
}
for (const overlay of overlays.slice(bootstrapEntrypoints.length)) {
  validateRestrictedNamespaceEnrollment(
    renderedByOverlay.get(overlay),
    overlay,
  );
}

console.log(`GitOps validation passed using '${command}'.`);

function parseDocuments(source, label) {
  return parseAllDocuments(source)
    .map((document) => {
      if (document.errors.length > 0) {
        throw new Error(
          `${label} rendered invalid YAML: ${document.errors.join(", ")}`,
        );
      }
      return document.toJSON();
    })
    .filter(Boolean);
}

function validateArgoBoundary(documents, label, identity) {
  const projects = documents.filter(
    (document) => document.kind === "AppProject",
  );
  const applications = documents.filter(
    (document) => document.kind === "Application",
  );
  const expected = [
    "bootstrap",
    ...(identity.clusterRole === "platform" ? ["database-infrastructure"] : []),
    "default",
    "platform-operators",
    "security",
    "tenant-delivery",
  ].sort();
  const names = projects.map((project) => project.metadata?.name).sort();
  if (JSON.stringify(names) !== JSON.stringify(expected)) {
    fail(label, `must render exactly AppProjects: ${expected.join(", ")}`);
  }
  const byName = new Map(
    projects.map((project) => [project.metadata.name, project]),
  );
  const deniedDefault = byName.get("default")?.spec;
  for (const field of [
    "sourceRepos",
    "destinations",
    "clusterResourceWhitelist",
    "namespaceResourceWhitelist",
  ]) {
    if (!Array.isArray(deniedDefault?.[field]) || deniedDefault[field].length) {
      fail(label, `default AppProject ${field} must be an explicit empty list`);
    }
  }
  const bootstrap = byName.get("bootstrap");
  const expectedBootstrapDestinations =
    identity.clusterRole === "platform"
      ? [
          "agent-broker",
          "agent-egress",
          "istio-system",
          "kube-system",
          "platform",
          "security",
          "tailscale",
          "workloads",
        ]
      : ["execution", "istio-system", "kube-system", "security"];
  assertExactSet(
    new Set(
      (bootstrap?.spec?.destinations ?? []).map(
        (destination) => destination.namespace,
      ),
    ),
    expectedBootstrapDestinations,
    label,
    "bootstrap AppProject destinations",
  );
  const expectedBaseline = `${identity.clusterRole}-cluster-baseline`;
  const bootstrapPolicies = (bootstrap?.spec?.roles ?? []).flatMap(
    (role) => role.policies ?? [],
  );
  if (
    bootstrapPolicies.length !== 2 ||
    bootstrapPolicies.some(
      (policy) => !policy.includes(`bootstrap/${expectedBaseline}`),
    )
  ) {
    fail(
      label,
      `bootstrap AppProject must authorize only '${expectedBaseline}'`,
    );
  }
  for (const project of projects.filter(
    (candidate) => candidate.metadata.name !== "default",
  )) {
    const spec = project.spec ?? {};
    if (!Array.isArray(spec.sourceRepos) || spec.sourceRepos.length === 0) {
      fail(
        label,
        `${project.metadata.name} must own exact source repositories`,
      );
    }
    for (const repo of spec.sourceRepos) {
      if (
        typeof repo !== "string" ||
        !safeRepoUrl(repo) ||
        repo.includes("*") ||
        /your-(?:org|github-org)/.test(repo)
      ) {
        fail(
          label,
          `${project.metadata.name} has unsafe source repository '${repo}'`,
        );
      }
    }
    const destinations = spec.destinations ?? [];
    if (destinations.length === 0) {
      fail(label, `${project.metadata.name} must own exact destinations`);
    }
    for (const destination of destinations) {
      if (
        destination.server !== "https://kubernetes.default.svc" ||
        typeof destination.namespace !== "string" ||
        destination.namespace.includes("*")
      ) {
        fail(label, `${project.metadata.name} has an unsafe destination`);
      }
    }
    for (const field of [
      "clusterResourceWhitelist",
      "namespaceResourceWhitelist",
    ]) {
      const seen = new Set();
      for (const resource of spec[field] ?? []) {
        const key = `${resource.group}/${resource.kind}`;
        if (
          typeof resource.group !== "string" ||
          typeof resource.kind !== "string" ||
          resource.group.includes("*") ||
          resource.kind.includes("*") ||
          seen.has(key)
        ) {
          fail(
            label,
            `${project.metadata.name} has unsafe or duplicate ${field} '${key}'`,
          );
        }
        seen.add(key);
      }
    }
    const expectedRoles = {
      bootstrap: ["bootstrap-sync"],
      "database-infrastructure": ["database-infrastructure-sync"],
      "platform-operators": ["operator-sync"],
      security: ["security-sync"],
      "tenant-delivery": [],
    }[project.metadata.name];
    const actualRoles = (spec.roles ?? []).map((role) => role.name).sort();
    if (JSON.stringify(actualRoles) !== JSON.stringify(expectedRoles)) {
      fail(label, `${project.metadata.name} has an unexpected role inventory`);
    }
    for (const role of spec.roles ?? []) {
      if (!Array.isArray(role.groups) || role.groups.length === 0) {
        fail(
          label,
          `${project.metadata.name}/${role.name} requires exact OIDC groups`,
        );
      }
      for (const policy of role.policies ?? []) {
        const fields =
          typeof policy === "string"
            ? policy.split(",").map((field) => field.trim())
            : [];
        const [type, principal, resource, action, object, effect] = fields;
        if (
          fields.length !== 6 ||
          type !== "p" ||
          principal !== `proj:${project.metadata.name}:${role.name}` ||
          resource !== "applications" ||
          !["get", "sync"].includes(action) ||
          !object?.startsWith(`${project.metadata.name}/`) ||
          effect !== "allow" ||
          policy.includes("*")
        ) {
          fail(
            label,
            `${project.metadata.name}/${role.name} has an unsafe Casbin tuple`,
          );
        }
      }
    }
  }
  const tenant = byName.get("tenant-delivery");
  if ((tenant.spec.clusterResourceWhitelist ?? []).length !== 0) {
    fail(label, "tenant-delivery cannot own cluster-scoped resources");
  }
  const tenantKinds = new Set(
    (tenant.spec.namespaceResourceWhitelist ?? []).map(
      (resource) => `${resource.group}/${resource.kind}`,
    ),
  );
  for (const forbidden of [
    "/Namespace",
    "/Secret",
    "apiextensions.k8s.io/CustomResourceDefinition",
    "rbac.authorization.k8s.io/Role",
    "rbac.authorization.k8s.io/RoleBinding",
    "admissionregistration.k8s.io/MutatingWebhookConfiguration",
    "admissionregistration.k8s.io/ValidatingWebhookConfiguration",
  ]) {
    if (tenantKinds.has(forbidden)) {
      fail(label, `tenant-delivery cannot own '${forbidden}'`);
    }
  }
  if (identity.clusterRole === "platform") {
    validateDatabaseInfrastructureProject(
      byName.get("database-infrastructure"),
      label,
    );
  }
  validateDatabaseInfrastructureApplication(
    applications,
    label,
    identity.clusterRole,
  );
  for (const application of applications) {
    const projectName = application.spec?.project;
    if (!projectName || projectName === "default") {
      fail(
        label,
        `${application.metadata?.name} cannot use the default AppProject`,
      );
    }
    const project = byName.get(projectName);
    if (!project)
      fail(
        label,
        `${application.metadata?.name} selects unknown project '${projectName}'`,
      );
    const source = application.spec.source;
    if (!project.spec.sourceRepos.includes(source.repoURL)) {
      fail(
        label,
        `${application.metadata.name} repository is outside '${projectName}'`,
      );
    }
    const destination = application.spec.destination;
    if (destination.server !== "https://kubernetes.default.svc") {
      fail(
        label,
        `${application.metadata.name} remote destination substitution denied`,
      );
    }
    if (
      !project.spec.destinations.some(
        (allowed) =>
          allowed.server === destination.server &&
          allowed.namespace === destination.namespace,
      )
    ) {
      fail(
        label,
        `${application.metadata.name} destination is outside '${projectName}'`,
      );
    }
    if (
      typeof source.targetRevision !== "string" ||
      source.targetRevision === "HEAD" ||
      source.targetRevision.includes("*") ||
      (source.repoURL ===
        "https://github.com/codefly-dev/secure-saas-platform.git" &&
        !/^(?:[a-f0-9]{40}|v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)$/.test(
          source.targetRevision,
        )) ||
      (label.includes("overlays/production") &&
        ([
          "main",
          "master",
          "develop",
          "development",
          "staging",
          "production",
        ].includes(source.targetRevision) ||
          !/^(?:[a-f0-9]{40}|v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)$/.test(
            source.targetRevision,
          )))
    ) {
      fail(label, `${application.metadata.name} has an unsafe target revision`);
    }
  }
  for (const projectName of ["platform-operators", "security"]) {
    const project = byName.get(projectName);
    const ownedApplications = applications.filter(
      (application) => application.spec?.project === projectName,
    );
    assertExactSet(
      new Set(project.spec.sourceRepos),
      new Set(
        ownedApplications.map((application) => application.spec.source.repoURL),
      ),
      label,
      `${projectName} role-specific source repositories`,
    );
    assertExactSet(
      new Set(
        project.spec.destinations.map((destination) => destination.namespace),
      ),
      new Set(
        ownedApplications.map(
          (application) => application.spec.destination.namespace,
        ),
      ),
      label,
      `${projectName} role-specific destinations`,
    );
    const role = project.spec.roles[0];
    assertExactSet(
      new Set(role.policies),
      new Set(
        ownedApplications.flatMap((application) =>
          ["get", "sync"].map(
            (action) =>
              `p, proj:${projectName}:${role.name}, applications, ${action}, ${projectName}/${application.metadata.name}, allow`,
          ),
        ),
      ),
      label,
      `${projectName} role-specific policies`,
    );
  }
  assertExactSet(
    new Set(
      byName
        .get("tenant-delivery")
        .spec.destinations.map((destination) => destination.namespace),
    ),
    [identity.clusterRole === "platform" ? "workloads" : "execution"],
    label,
    "tenant-delivery role-specific destinations",
  );
}

function bootstrapIdentity(label) {
  const match =
    /bootstrap\/argocd\/overlays\/(dev|staging|production)\/(platform|execution)$/.exec(
      label,
    );
  if (!match) fail(label, "is not an explicit environment/role entrypoint");
  return { environment: match[1], clusterRole: match[2] };
}

function validateRoleInventory(documents, label, identity, renderedByOverlay) {
  const applications = documents.filter(
    (document) => document.kind === "Application",
  );
  for (const application of applications) {
    if (
      application.spec?.destination?.server !== "https://kubernetes.default.svc"
    ) {
      fail(
        label,
        `${application.metadata?.name} remote destination substitution denied`,
      );
    }
  }
  validateArgoOwnership(applications, label, renderedByOverlay);
  const common = [
    "falco",
    "istio-base",
    "istio-cni",
    "istio-ztunnel",
    "istiod",
    "kube-prometheus-stack",
    "kyverno",
    "metrics-server",
  ];
  const expected =
    identity.clusterRole === "platform"
      ? [
          "argo-rollouts",
          "cert-manager",
          "database-infrastructure-handoff",
          "external-dns",
          "gateway-api-crds",
          "istio-ingress-gateway",
          ...common,
          "platform-cluster-baseline",
          "tailscale-operator",
          "vault",
          "vault-secrets-operator",
        ].sort()
      : [...common, "execution-cluster-baseline"].sort();
  const actual = applications
    .map((application) => application.metadata?.name)
    .sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(
      label,
      `${identity.clusterRole} role Application inventory must equal ${expected.join(", ")}`,
    );
  }

  const roleApplications = applications.filter((application) =>
    /^(?:platform|execution)-cluster-baseline$/.test(
      application.metadata?.name ?? "",
    ),
  );
  const baseline = roleApplications[0];
  if (
    roleApplications.length !== 1 ||
    baseline.metadata?.name !== `${identity.clusterRole}-cluster-baseline` ||
    baseline.spec?.project !== "bootstrap" ||
    baseline.spec?.source?.repoURL !==
      "https://github.com/codefly-dev/secure-saas-platform.git" ||
    baseline.spec?.source?.path !==
      `gitops/overlays/${identity.environment}/${identity.clusterRole}` ||
    !/^(?:[a-f0-9]{40}|v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)$/.test(
      baseline.spec?.source?.targetRevision ?? "",
    ) ||
    baseline.spec?.destination?.server !== "https://kubernetes.default.svc" ||
    baseline.spec?.destination?.namespace !== identity.clusterRole
  ) {
    fail(
      label,
      `must render exactly one immutable ${identity.clusterRole} cluster-baseline Application`,
    );
  }
  if (
    !(baseline.spec?.syncPolicy?.syncOptions ?? []).includes(
      "FailOnSharedResource=true",
    )
  ) {
    fail(label, `${baseline.metadata.name} must fail on shared resources`);
  }
}

function validateArgoOwnership(applications, label, renderedByOverlay) {
  const sources = new Map();
  const resources = new Map();
  for (const application of applications) {
    const source = application.spec?.source ?? {};
    const destination = application.spec?.destination ?? {};
    const sourceKey = [
      destination.server,
      destination.namespace,
      source.repoURL,
      source.chart ?? source.path,
    ].join("|");
    const previousSource = sources.get(sourceKey);
    if (previousSource) {
      fail(
        label,
        `overlapping Argo ownership between '${previousSource}' and '${application.metadata?.name}'`,
      );
    }
    sources.set(sourceKey, application.metadata?.name);

    if (
      source.repoURL !==
        "https://github.com/codefly-dev/secure-saas-platform.git" ||
      !/^gitops\/overlays\/(?:dev|staging|production)\/(?:platform|execution)$/.test(
        source.path ?? "",
      )
    ) {
      continue;
    }
    const rendered = renderedByOverlay.get(
      path.join(gitopsRoot, source.path.replace(/^gitops\//, "")),
    );
    if (!rendered) {
      fail(label, `${application.metadata?.name} has no rendered source`);
    }
    for (const resource of rendered) {
      const key = [
        resource.apiVersion,
        resource.kind,
        resource.metadata?.namespace ?? "<cluster>",
        resource.metadata?.name,
      ].join("|");
      const owner = resources.get(key);
      if (owner) {
        fail(
          label,
          `overlapping Argo ownership of '${key}' between '${owner}' and '${application.metadata?.name}'`,
        );
      }
      resources.set(key, application.metadata?.name);
    }
  }
}

function validateDatabaseInfrastructureApplication(
  applications,
  label,
  clusterRole,
) {
  const environment = environmentForLabel(label);
  const matches = applications.filter(
    (application) =>
      application.metadata?.name === "database-infrastructure-handoff",
  );
  const expectedCount = clusterRole === "platform" ? 1 : 0;
  if (matches.length !== expectedCount) {
    fail(
      label,
      `must render exactly ${expectedCount} controller-owned database-infrastructure-handoff Application`,
    );
  }
  if (expectedCount === 0) return;
  const application = matches[0];
  const expectedNamespace = `codefly-db-runtime-warden-saas-postgres-${environment}`;
  if (
    application.metadata?.namespace !== "argocd-database" ||
    application.metadata?.annotations?.["security.deus.dev/authority"] !==
      "infrastructure-controller" ||
    application.spec?.project !== "database-infrastructure" ||
    application.spec?.source?.repoURL !==
      "https://github.com/codefly-dev/secure-saas-platform.git" ||
    application.spec?.source?.path !==
      `gitops/generated/database/${environment}` ||
    application.spec?.destination?.server !==
      "https://kubernetes.default.svc" ||
    application.spec?.destination?.namespace !== expectedNamespace
  ) {
    fail(
      label,
      "database-infrastructure-handoff must bind the exact project, repository, environment path, and destination",
    );
  }
  if (application.spec?.syncPolicy?.automated !== undefined) {
    fail(
      label,
      "database-infrastructure-handoff must require an explicit reviewed sync",
    );
  }
  assertExactSet(
    new Set(application.spec?.syncPolicy?.syncOptions ?? []),
    [
      "CreateNamespace=false",
      "FailOnSharedResource=true",
      "PruneLast=true",
      "ServerSideApply=true",
    ],
    label,
    "database-infrastructure-handoff sync options",
  );
}

function validateDatabaseInfrastructureProject(project, label) {
  const environment = environmentForLabel(label);
  const expectedDestinations = [
    "mind-infra-postgres",
    "mind-users-postgres",
    "warden-saas-postgres",
  ]
    .flatMap((bindingId) =>
      ["runtime", "migration", "bootstrap"].map(
        (accessClass) =>
          `codefly-db-${accessClass}-${bindingId}-${environment}`,
      ),
    )
    .sort();
  const actualDestinations = (project?.spec?.destinations ?? [])
    .map((destination) => destination.namespace)
    .sort();
  if (
    JSON.stringify(actualDestinations) !== JSON.stringify(expectedDestinations)
  ) {
    fail(
      label,
      `database-infrastructure must own only exact ${environment} access-class namespaces`,
    );
  }
  const resourceSet = (field) =>
    new Set(
      (project?.spec?.[field] ?? []).map(
        (resource) => `${resource.group}/${resource.kind}`,
      ),
    );
  const cluster = resourceSet("clusterResourceWhitelist");
  const namespaced = resourceSet("namespaceResourceWhitelist");
  assertExactSet(
    cluster,
    ["/Namespace", "eks.amazonaws.com/NodeClass", "karpenter.sh/NodePool"],
    label,
    "database-infrastructure cluster resources",
  );
  assertExactSet(
    namespaced,
    ["/ServiceAccount", "networking.k8s.aws/ApplicationNetworkPolicy"],
    label,
    "database-infrastructure namespaced resources",
  );
}

function environmentForLabel(label) {
  return label.includes("overlays/staging")
    ? "staging"
    : label.includes("overlays/production")
      ? "production"
      : "development";
}

function assertExactSet(actual, expected, label, subject) {
  const values = [...actual].sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(values) !== JSON.stringify(wanted)) {
    fail(label, `${subject} must equal ${wanted.join(", ")}`);
  }
}

function validateRestrictedNamespaceEnrollment(documents, label) {
  const match =
    /overlays\/(?:dev|staging|production)\/(platform|execution)$/.exec(label);
  if (!match) fail(label, "is not an explicit environment/role baseline");
  const clusterRole = match[1];
  const expected =
    clusterRole === "platform"
      ? ["agent-broker", "agent-egress", "platform", "security", "workloads"]
      : ["execution", "security"];
  const expectedNamespaces =
    clusterRole === "platform"
      ? [
          "agent-broker",
          "agent-egress",
          "argo-rollouts",
          "cert-manager",
          "external-dns",
          "falco",
          "istio-ingress",
          "istio-system",
          "metrics-server",
          "observability",
          "platform",
          "security",
          "tailscale",
          "vault",
          "vault-secrets-operator",
          "workloads",
        ]
      : [
          "execution",
          "falco",
          "istio-system",
          "metrics-server",
          "observability",
          "security",
        ];
  assertExactSet(
    new Set(
      documents
        .filter((document) => document.kind === "Namespace")
        .map((document) => document.metadata.name),
    ),
    expectedNamespaces,
    label,
    `${clusterRole} namespace ownership`,
  );
  const restricted = documents
    .filter(
      (document) =>
        document.kind === "Namespace" &&
        document.metadata?.labels?.[
          "security.deus.dev/service-account-token-policy"
        ] === "restricted",
    )
    .map((document) => document.metadata.name)
    .sort();
  const protectedDefaults = documents
    .filter(
      (document) =>
        document.apiVersion === "v1" &&
        document.kind === "ServiceAccount" &&
        document.metadata?.name === "default" &&
        document.automountServiceAccountToken === false,
    )
    .map((document) => document.metadata.namespace)
    .sort();
  if (JSON.stringify(restricted) !== JSON.stringify(expected)) {
    fail(label, "restricted namespace enrollment is not the exact owned set");
  }
  if (JSON.stringify(protectedDefaults) !== JSON.stringify(expected)) {
    fail(
      label,
      "default ServiceAccount protection does not exactly cover restricted namespaces",
    );
  }
}

function safeRepoUrl(value) {
  if (typeof value !== "string" || !value.startsWith("https://")) return false;
  if (value.includes("?") || value.includes("#") || value.includes("*"))
    return false;
  try {
    const parsed = new URL(value);
    return !parsed.username && !parsed.password;
  } catch {
    return false;
  }
}

function validateBaselineResources(argoDocuments, renderedByOverlay) {
  const projects = new Map(
    argoDocuments
      .filter((document) => document.kind === "AppProject")
      .map((project) => [project.metadata.name, project]),
  );
  for (const application of argoDocuments.filter(
    (document) =>
      document.kind === "Application" &&
      /^gitops\/overlays\/(?:dev|staging|production)\/(?:platform|execution)$/.test(
        document.spec.source.path ?? "",
      ),
  )) {
    const sourcePath = application.spec.source.path;
    const resources = renderedByOverlay.get(
      path.join(gitopsRoot, sourcePath.replace(/^gitops\//, "")),
    );
    if (!resources)
      fail(sourcePath, "has no independently rendered validation target");
    const project = projects.get(application.spec.project);
    const clusterKinds = resourceSet(project.spec.clusterResourceWhitelist);
    const namespaceKinds = resourceSet(project.spec.namespaceResourceWhitelist);
    const destinationNamespaces = new Set(
      project.spec.destinations
        .filter(
          (destination) =>
            destination.server === "https://kubernetes.default.svc",
        )
        .map((destination) => destination.namespace),
    );
    const renderedClusterKinds = new Set();
    const renderedNamespaceKinds = new Set();
    for (const resource of resources) {
      const apiGroup = String(resource.apiVersion ?? "").split("/")[0];
      const group = String(resource.apiVersion).includes("/") ? apiGroup : "";
      const key = `${group}/${resource.kind}`;
      const scoped = resource.metadata?.namespace
        ? namespaceKinds
        : clusterKinds;
      (resource.metadata?.namespace
        ? renderedNamespaceKinds
        : renderedClusterKinds
      ).add(key);
      if (!scoped.has(key)) {
        fail(
          sourcePath,
          `${resource.metadata?.namespace ? "namespaced" : "cluster"} resource '${key}' is outside AppProject '${application.spec.project}'`,
        );
      }
      if (
        resource.metadata?.namespace &&
        !destinationNamespaces.has(resource.metadata.namespace)
      ) {
        fail(
          sourcePath,
          `resource '${key}' targets namespace '${resource.metadata.namespace}' outside AppProject '${application.spec.project}'`,
        );
      }
    }
    assertExactSet(
      clusterKinds,
      renderedClusterKinds,
      sourcePath,
      `${application.spec.project} cluster resource authority`,
    );
    assertExactSet(
      namespaceKinds,
      renderedNamespaceKinds,
      sourcePath,
      `${application.spec.project} namespace resource authority`,
    );
    if (sourcePath.endsWith("/platform")) {
      validateDatabaseControllerPolicy(resources, sourcePath);
    }
  }
}

function validateDatabaseControllerPolicy(resources, label) {
  const policies = resources.filter(
    (resource) =>
      resource.apiVersion === "kyverno.io/v1" &&
      resource.kind === "ClusterPolicy" &&
      resource.metadata?.name ===
        "authorize-database-infrastructure-controller",
  );
  if (policies.length !== 1) {
    fail(
      label,
      "must contain exactly one database infrastructure controller authorization policy",
    );
  }
  const policy = policies[0];
  if (
    policy.spec?.admission !== true ||
    policy.spec?.background !== false ||
    policy.spec?.failurePolicy !== "Fail" ||
    policy.spec?.validationFailureAction !== "Enforce"
  ) {
    fail(label, "database controller authorization policy must fail closed");
  }
  const expected = new Map([
    [
      "database-namespaces-controller-only",
      "SEC_DATABASE_CONTROLLER_IDENTITY_DENIED",
    ],
    [
      "database-namespaced-resources-controller-only",
      "SEC_DATABASE_CONTROLLER_IDENTITY_DENIED",
    ],
    [
      "database-cluster-resources-controller-only",
      "SEC_DATABASE_CONTROLLER_IDENTITY_DENIED",
    ],
    [
      "database-controller-namespace-ceiling",
      "SEC_DATABASE_CONTROLLER_SCOPE_DENIED",
    ],
    [
      "database-controller-namespaced-ceiling",
      "SEC_DATABASE_CONTROLLER_SCOPE_DENIED",
    ],
    [
      "database-controller-cluster-ceiling",
      "SEC_DATABASE_CONTROLLER_SCOPE_DENIED",
    ],
    [
      "database-controller-forbidden-kinds",
      "SEC_DATABASE_CONTROLLER_KIND_DENIED",
    ],
    [
      "database-controller-delete-denied",
      "SEC_DATABASE_CONTROLLER_DELETE_DENIED",
    ],
  ]);
  const rules = new Map(
    (policy.spec?.rules ?? []).map((rule) => [rule.name, rule]),
  );
  if (
    rules.size !== expected.size ||
    [...expected].some(
      ([name, message]) => rules.get(name)?.validate?.message !== message,
    )
  ) {
    fail(
      label,
      "database controller authorization policy rule inventory is incomplete or substituted",
    );
  }
  for (const name of [
    "database-namespaces-controller-only",
    "database-namespaced-resources-controller-only",
    "database-cluster-resources-controller-only",
  ]) {
    const conditions = rules.get(name)?.validate?.deny?.conditions?.any;
    if (
      !Array.isArray(conditions) ||
      conditions.length !== 1 ||
      conditions[0]?.key !== "{{ request.userInfo.username || '' }}" ||
      conditions[0]?.operator !== "NotEquals" ||
      conditions[0]?.value !==
        "system:serviceaccount:argocd-database:database-infrastructure-application-controller"
    ) {
      fail(
        label,
        `${name} must authorize only the pinned Argo application-controller identity`,
      );
    }
  }
  const serialized = JSON.stringify(policy);
  for (const required of [
    "system:serviceaccount:argocd-database:database-infrastructure-application-controller",
    "codefly-db-runtime-warden-saas-postgres-*",
    "codefly-db-migration-mind-users-postgres-*",
    "codefly-db-bootstrap-mind-infra-postgres-*",
    "warden-saas-postgres-runtime-access",
    "mind-users-postgres-migration-access",
    "mind-infra-postgres-bootstrap-access",
    "Pod/binding",
    "ClusterPolicy",
  ]) {
    if (!serialized.includes(required)) {
      fail(
        label,
        `database controller authorization policy is missing '${required}'`,
      );
    }
  }

  validateDatabaseControllerNativeAdmission(resources, label);
  validateDatabaseWorkloadNativeAdmission(resources, label);
}

function validateDatabaseWorkloadNativeAdmission(resources, label) {
  const policy = resources.find(
    (resource) =>
      resource.apiVersion === "admissionregistration.k8s.io/v1" &&
      resource.kind === "ValidatingAdmissionPolicy" &&
      resource.metadata?.name === "database-workload-native-boundary",
  );
  const binding = resources.find(
    (resource) =>
      resource.apiVersion === "admissionregistration.k8s.io/v1" &&
      resource.kind === "ValidatingAdmissionPolicyBinding" &&
      resource.metadata?.name === "database-workload-native-boundary",
  );
  const expressions = (policy?.spec?.validations ?? []).map((validation) =>
    String(validation.expression),
  );
  if (
    policy?.spec?.failurePolicy !== "Fail" ||
    binding?.spec?.policyName !== "database-workload-native-boundary" ||
    JSON.stringify(binding?.spec?.validationActions) !== '["Deny"]' ||
    !expressions.some(
      (expression) =>
        expression.includes("request.resource.resource == 'deployments'") &&
        !expression.includes("statefulsets"),
    )
  ) {
    fail(
      label,
      "database native workload boundary must allow only Deployments for runtime and fail closed",
    );
  }
}

function validateDatabaseControllerNativeAdmission(resources, label) {
  const policies = resources.filter(
    (resource) =>
      resource.apiVersion === "admissionregistration.k8s.io/v1" &&
      resource.kind === "ValidatingAdmissionPolicy" &&
      [
        "database-controller-native-scope",
        "database-controller-native-ownership",
      ].includes(resource.metadata?.name),
  );
  const bindings = resources.filter(
    (resource) =>
      resource.apiVersion === "admissionregistration.k8s.io/v1" &&
      resource.kind === "ValidatingAdmissionPolicyBinding" &&
      [
        "database-controller-native-scope",
        "database-controller-native-ownership",
      ].includes(resource.metadata?.name),
  );
  if (policies.length !== 2 || bindings.length !== 2) {
    fail(
      label,
      "database controller native admission policy or binding inventory is incomplete",
    );
  }
  for (const policy of policies) {
    if (policy.spec?.failurePolicy !== "Fail") {
      fail(label, `${policy.metadata.name} native admission must fail closed`);
    }
  }
  for (const binding of bindings) {
    if (
      binding.spec?.policyName !== binding.metadata.name ||
      JSON.stringify(binding.spec?.validationActions) !== '["Deny"]'
    ) {
      fail(
        label,
        `${binding.metadata.name} native admission binding is unsafe`,
      );
    }
  }
  const scope = policies.find(
    (policy) => policy.metadata.name === "database-controller-native-scope",
  );
  const matchConditions = scope.spec?.matchConditions ?? [];
  const validations = scope.spec?.validations ?? [];
  if (
    matchConditions.length !== 1 ||
    !String(matchConditions[0]?.expression).includes(
      "system:serviceaccount:argocd-database:database-infrastructure-application-controller",
    ) ||
    !validations.some(
      (validation) =>
        validation.expression === "request.operation != 'DELETE'" &&
        String(validation.message).includes(
          "SEC_DATABASE_CONTROLLER_DELETE_DENIED",
        ),
    )
  ) {
    fail(
      label,
      "database controller native scope must pin the actor and deny deletion",
    );
  }
}

function resourceSet(resources) {
  return new Set(
    (resources ?? []).map((resource) => `${resource.group}/${resource.kind}`),
  );
}

function fail(label, message) {
  throw new Error(`GitOps boundary violation in ${label}: ${message}.`);
}

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0) return undefined;
  const value = process.argv[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${name} requires a path.`);
  }
  return value;
}
