import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";

const directory = path.resolve(
  "artifacts",
  "disposable-cluster-report-verifier-test",
);
const reportPath = path.join(directory, "report.json");

test("disposable-cluster verifier rejects tampering across every evidence boundary", () => {
  ensureBuild();
  const expectationsResult = spawnSync(
    process.execPath,
    ["scripts/verify-disposable-cluster-report.mjs", "--print-expectations"],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(expectationsResult.status, 0, expectationsResult.stderr);
  const expectations = JSON.parse(expectationsResult.stdout);
  const baseline = createReport(expectations);

  try {
    writeReport(baseline);
    const accepted = verify();
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.match(accepted.stdout, /61 exact checks/);

    const mutations: Array<{
      name: string;
      mutate: (report: any) => void;
      preserveDigest?: boolean;
      error: RegExp;
    }> = [
      {
        name: "stale report",
        mutate: (report) => {
          report.generatedAt = "1970-01-01T00:00:00.000Z";
          report.completedAt = "1970-01-01T00:00:01.000Z";
          report.durationMs = 1000;
        },
        error: /report is stale/,
      },
      {
        name: "report digest",
        mutate: (report) => {
          report.reportDigest = "0".repeat(64);
        },
        preserveDigest: true,
        error: /reportDigest/,
      },
      {
        name: "source revision",
        mutate: (report) => {
          report.source.revision = "0".repeat(40);
        },
        error: /source revision\/dirty state/,
      },
      {
        name: "source dirty state",
        mutate: (report) => {
          report.source.dirty = !report.source.dirty;
        },
        error: /source revision\/dirty state/,
      },
      {
        name: "scope",
        mutate: (report) => {
          report.scope.proves[0] = "substituted-proof";
        },
        error: /schema validation failed/,
      },
      {
        name: "check inventory",
        mutate: (report) => {
          report.checks[0].id = "substituted-check";
        },
        error: /check inventory/,
      },
      {
        name: "denial metadata",
        mutate: (report) => {
          const denial = report.checks.find(
            (entry: any) => entry.denialCode !== undefined,
          );
          denial.denialCode = "SEC_SUBSTITUTED_DENIAL";
        },
        error: /denial .* does not match/,
      },
      {
        name: "repository input digest",
        mutate: (report) => {
          report.inputs[expectations.inputPaths[0]] = "0".repeat(64);
        },
        error: /bound input digest/,
      },
      {
        name: "pinned runtime input",
        mutate: (report) => {
          report.inputs.k3sImage = `rancher/k3s@sha256:${"0".repeat(64)}`;
        },
        error: /input was substituted/,
      },
      {
        name: "controller image",
        mutate: (report) => {
          report.controllerImages[0].imageId = `reg.kyverno.io/kyverno/kyverno@sha256:${"0".repeat(64)}`;
        },
        error: /controller image inventory was substituted/,
      },
      {
        name: "cleanup",
        mutate: (report) => {
          report.cleanup.containerRemoved = false;
        },
        error: /schema validation failed/,
      },
    ];

    for (const mutation of mutations) {
      const hostile = structuredClone(baseline);
      mutation.mutate(hostile);
      if (!mutation.preserveDigest) bindDigest(hostile);
      writeReport(hostile);
      const rejected = verify();
      assert.notEqual(rejected.status, 0, mutation.name);
      assert.match(rejected.stderr, mutation.error, mutation.name);
    }

    const staleButCandidateBound = structuredClone(baseline);
    staleButCandidateBound.generatedAt = "1970-01-01T00:00:00.000Z";
    staleButCandidateBound.completedAt = "1970-01-01T00:00:01.000Z";
    staleButCandidateBound.durationMs = 1000;
    bindDigest(staleButCandidateBound);
    writeReport(staleButCandidateBound);
    const bound = verify(["--bound-by-qualified-candidate"]);
    assert.equal(bound.status, 0, bound.stderr);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function createReport(expectations: any): any {
  const inputs = Object.fromEntries(
    expectations.inputPaths.map((inputPath: string) => [
      inputPath,
      sha256(readFileSync(inputPath)),
    ]),
  );
  Object.assign(inputs, {
    k3sImage: expectations.k3sImage,
    kyvernoChart: expectations.kyvernoChart,
    fixtureImage: expectations.fixtureImage,
  });
  const report = {
    apiVersion: "security.deus.dev/disposable-cluster-validation/v1alpha1",
    kind: "DisposableClusterValidationReport",
    generatedAt: new Date(Date.now() - 1000).toISOString(),
    completedAt: new Date().toISOString(),
    durationMs: 1000,
    pass: true,
    runId: "secure-saas-infra-g5-1-00000000",
    scope: expectations.scope,
    source: {
      revision: git(["rev-parse", "HEAD"]),
      dirty: git(["status", "--porcelain", "--untracked-files=all"]).length > 0,
    },
    tools: {
      docker: "test",
      kubectl: "test",
      helm: "test",
      dockerContext: "test",
      dockerEndpoint: "unix:///test/docker.sock",
      kubernetes: "v1.35.0",
      kyverno: "v1.17.0",
    },
    cluster: {
      namespaceUid: "test-namespace-uid",
      apiServer: "https://127.0.0.1:6443",
      caSha256: "1".repeat(64),
    },
    inputs,
    checks: expectations.checks,
    controllerImages: expectations.controllerImages,
    cleanup: {
      containerRemoved: true,
      temporaryDirectoryRemoved: true,
    },
  };
  bindDigest(report);
  return report;
}

function writeReport(report: any): void {
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, {
    mode: 0o600,
  });
}

function verify(extra: string[] = []) {
  return spawnSync(
    process.execPath,
    [
      "scripts/verify-disposable-cluster-report.mjs",
      "--report",
      path.relative(process.cwd(), reportPath),
      ...extra,
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
}

function ensureBuild(): void {
  if (existsSync("dist/databaseAccess.js")) return;
  const result = spawnSync("npm", ["run", "build", "--silent"], {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
}

function bindDigest(report: any): void {
  delete report.reportDigest;
  report.reportDigest = sha256(canonicalJson(report));
}

function canonicalJson(value: any): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function git(arguments_: string[]): string {
  const result = spawnSync("git", arguments_, {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}
