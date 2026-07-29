#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { lstatSync, writeFileSync } from "node:fs";
import path from "node:path";
import { canonicalJson, sha256 } from "./platform-handoff.mjs";

const args = parseArguments(process.argv.slice(2));
const resolvedRevision = run("git", [
  "rev-parse",
  "--verify",
  `${args.revision}^{commit}`,
]).trim();
const application = JSON.parse(
  run("kubectl", [
    "--kubeconfig",
    args.kubeconfig,
    "get",
    "application",
    args.application,
    "--namespace",
    args.namespace,
    "-o",
    "json",
  ]),
);
const observedRevision = application.status?.sync?.revision;
const syncStatus = application.status?.sync?.status;
const healthStatus = application.status?.health?.status;
if (
  observedRevision !== resolvedRevision ||
  syncStatus !== "Synced" ||
  healthStatus !== "Healthy"
) {
  throw new Error(
    `PROMOTION_OBSERVATION_MISMATCH expected ${resolvedRevision}/Synced/Healthy, observed ${observedRevision}/${syncStatus}/${healthStatus}.`,
  );
}
const evidence = {
  apiVersion: "evidence.deus.dev/platform-promotion/v1",
  kind: "PlatformPromotionEvidence",
  environment: "production",
  clusterRole: args.clusterRole,
  application: {
    namespace: args.namespace,
    name: args.application,
  },
  source: {
    repository: "https://github.com/codefly-dev/secure-saas-platform.git",
    requestedRevision: args.revision,
    resolvedRevision,
  },
  observed: {
    at: new Date().toISOString(),
    revision: observedRevision,
    syncStatus,
    healthStatus,
  },
};
const output = path.resolve(args.output);
if (existsUnsafe(output)) {
  throw new Error("Promotion evidence output must not be a symlink.");
}
writeFileSync(
  output,
  `${JSON.stringify(
    { ...evidence, evidenceDigest: sha256(canonicalJson(evidence)) },
    null,
    2,
  )}\n`,
  { mode: 0o600 },
);
process.stdout.write(`Recorded promotion evidence at ${output}.\n`);

function parseArguments(values) {
  const parsed = {};
  const names = new Map([
    ["--revision", "revision"],
    ["--cluster-role", "clusterRole"],
    ["--application", "application"],
    ["--namespace", "namespace"],
    ["--kubeconfig", "kubeconfig"],
    ["--output", "output"],
  ]);
  for (let index = 0; index < values.length; index += 2) {
    const key = names.get(values[index]);
    const value = values[index + 1];
    if (!key || !value || parsed[key]) usage();
    parsed[key] = value;
  }
  if (
    Object.keys(parsed).length !== names.size ||
    !["platform", "execution"].includes(parsed.clusterRole)
  ) {
    usage();
  }
  return parsed;
}

function run(command, commandArguments) {
  const result = spawnSync(command, commandArguments, {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  if (result.error || result.status !== 0) {
    throw new Error(
      `${command} ${commandArguments.join(" ")} failed: ${result.error?.message ?? result.stderr}`,
    );
  }
  return result.stdout.trim();
}

function existsUnsafe(file) {
  try {
    return lstatSync(file).isSymbolicLink();
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function usage() {
  process.stderr.write(
    "Usage: npm run promotion:evidence -- --revision <sha-or-tag> --cluster-role <platform|execution> --application <name> --namespace <name> --kubeconfig <file> --output <file>\n",
  );
  process.exit(2);
}
