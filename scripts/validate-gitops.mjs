#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import path from "node:path";
import { parseAllDocuments } from "yaml";

const gitopsRoot = argument("--gitops-root") ?? "gitops";
const relativeOverlays = [
  "bootstrap/argocd",
  "bootstrap/argocd/overlays/dev",
  "bootstrap/argocd/overlays/staging",
  "bootstrap/argocd/overlays/production",
  "overlays/dev/platform",
  "overlays/dev/execution",
  "overlays/staging/platform",
  "overlays/staging/execution",
  "overlays/production/platform",
  "overlays/production/execution",
];
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

const argoOverlays = overlays.slice(0, 4);
for (const overlay of argoOverlays) {
  validateArgoBoundary(renderedByOverlay.get(overlay), overlay);
  validateBaselineResources(renderedByOverlay.get(overlay), renderedByOverlay);
}
for (const overlay of overlays.slice(4)) {
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

function validateArgoBoundary(documents, label) {
  const projects = documents.filter(
    (document) => document.kind === "AppProject",
  );
  const applications = documents.filter(
    (document) => document.kind === "Application",
  );
  const expected = [
    "bootstrap",
    "database-infrastructure",
    "default",
    "platform-operators",
    "security",
    "tenant-delivery",
  ];
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
  validateDatabaseInfrastructureProject(
    byName.get("database-infrastructure"),
    label,
  );
  validateDatabaseInfrastructureApplication(applications, label);
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
      (label.includes("overlays/production") &&
        source.path &&
        ([
          "main",
          "master",
          "develop",
          "development",
          "staging",
          "production",
        ].includes(source.targetRevision) ||
          !/^(?:[a-f0-9]{40}|v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)$/.test(
            source.targetRevision,
          )))
    ) {
      fail(label, `${application.metadata.name} has an unsafe target revision`);
    }
  }
}

function validateDatabaseInfrastructureApplication(applications, label) {
  const environment = environmentForLabel(label);
  const matches = applications.filter(
    (application) =>
      application.metadata?.name === "database-infrastructure-handoff",
  );
  if (matches.length !== 1) {
    fail(
      label,
      "must render exactly one controller-owned database-infrastructure-handoff Application",
    );
  }
  const application = matches[0];
  const expectedNamespace = `codefly-db-runtime-warden-saas-postgres-${environment}`;
  if (
    application.metadata?.namespace !== "argocd-database" ||
    application.metadata?.annotations?.["security.deus.dev/authority"] !==
      "infrastructure-controller" ||
    application.spec?.project !== "database-infrastructure" ||
    application.spec?.source?.repoURL !==
      "https://github.com/codefly-dev/secure-saas-infra.git" ||
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
  const expected = [
    "agent-broker",
    "agent-egress",
    "execution",
    "platform",
    "security",
    "workloads",
  ];
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
    for (const resource of resources) {
      const apiGroup = String(resource.apiVersion ?? "").split("/")[0];
      const group = String(resource.apiVersion).includes("/") ? apiGroup : "";
      const key = `${group}/${resource.kind}`;
      const scoped = resource.metadata?.namespace
        ? namespaceKinds
        : clusterKinds;
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
