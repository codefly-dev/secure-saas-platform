#!/usr/bin/env node

import { spawnSync } from "node:child_process";

const revision = argument("--revision");
if (
  !revision ||
  !/^(?:[a-f0-9]{40}|v\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)$/.test(revision)
) {
  fail("revision must be a full commit SHA or protected release tag.");
}
const resolved = git(["rev-parse", "--verify", `${revision}^{commit}`]);
git(["merge-base", "--is-ancestor", resolved, "refs/remotes/origin/main"]);
if (/^[a-f0-9]{40}$/.test(revision)) {
  const signature = git(["log", "-1", "--format=%G?", resolved]);
  if (!["G", "U"].includes(signature)) {
    fail("commit promotion requires a valid cryptographic signature.");
  }
} else {
  const tagType = git(["cat-file", "-t", `refs/tags/${revision}`]);
  if (!["tag", "commit"].includes(tagType)) {
    fail("release tag did not resolve to a Git object.");
  }
}
process.stdout.write(
  `${JSON.stringify({ requestedRevision: revision, resolvedRevision: resolved })}\n`,
);

function argument(name) {
  const occurrences = process.argv
    .slice(2)
    .map((value, index, values) => (value === name ? values[index + 1] : null))
    .filter(Boolean);
  if (occurrences.length !== 1 || process.argv.length !== 4) return undefined;
  return occurrences[0];
}

function git(arguments_) {
  const result = spawnSync("git", arguments_, {
    cwd: process.cwd(),
    encoding: "utf8",
  });
  if (result.error || result.status !== 0) {
    fail(result.error?.message ?? result.stderr.trim());
  }
  return result.stdout.trim();
}

function fail(message) {
  throw new Error(`PROMOTION_SOURCE_REJECTED ${message}`);
}
