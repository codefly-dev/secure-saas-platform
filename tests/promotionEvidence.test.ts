import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

test("promotion evidence binds exact observed revision and health", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "promotion-evidence-"));
  try {
    const revision = git(["rev-parse", "HEAD"]);
    const kubectl = path.join(directory, "kubectl");
    const output = path.join(directory, "evidence.json");
    writeFileSync(
      kubectl,
      `#!/bin/sh
printf '%s\\n' '{"status":{"sync":{"revision":"${revision}","status":"Synced"},"health":{"status":"Healthy"}}}'
`,
    );
    chmodSync(kubectl, 0o700);
    const result = record(revision, output, directory);
    assert.equal(result.status, 0, result.stderr);
    const evidence = JSON.parse(readFileSync(output, "utf8"));
    const { evidenceDigest, ...subject } = evidence;
    assert.equal(evidence.observed.revision, revision);
    assert.equal(evidence.observed.syncStatus, "Synced");
    assert.equal(evidence.observed.healthStatus, "Healthy");
    assert.equal(evidenceDigest, sha256(canonicalJson(subject)));

    const ajv = new Ajv2020({ strict: true, allErrors: true });
    addFormats(ajv);
    const validate = ajv.compile(
      JSON.parse(
        readFileSync(
          "schemas/platform-promotion-evidence-v1.schema.json",
          "utf8",
        ),
      ),
    );
    assert.equal(validate(evidence), true, JSON.stringify(validate.errors));

    writeFileSync(
      kubectl,
      `#!/bin/sh
printf '%s\\n' '{"status":{"sync":{"revision":"${revision}","status":"Synced"},"health":{"status":"Degraded"}}}'
`,
    );
    const rejected = record(
      revision,
      path.join(directory, "rejected.json"),
      directory,
    );
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /PROMOTION_OBSERVATION_MISMATCH/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function record(revision: string, output: string, binaryDirectory: string) {
  return spawnSync(
    process.execPath,
    [
      "scripts/record-promotion-evidence.mjs",
      "--revision",
      revision,
      "--cluster-role",
      "platform",
      "--application",
      "platform-cluster-baseline",
      "--namespace",
      "argocd",
      "--kubeconfig",
      "/run/platform-promotion/kubeconfig",
      "--output",
      output,
    ],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${binaryDirectory}${path.delimiter}${process.env.PATH}`,
      },
    },
  );
}

function git(arguments_: string[]): string {
  const result = spawnSync("git", arguments_, {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
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

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
