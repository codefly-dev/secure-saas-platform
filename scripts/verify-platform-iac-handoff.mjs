#!/usr/bin/env node

import { verifyPlatformHandoff } from "./platform-handoff.mjs";

const args = parseArguments(process.argv.slice(2));
const handoff = verifyPlatformHandoff(args.handoff, args.publicKey);
process.stdout.write(
  `Verified signed ${handoff.spec.cluster.role} handoff for ${handoff.spec.cluster.name} at ${handoff.specDigest}.\n`,
);

function parseArguments(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];
    if (!["--handoff", "--public-key"].includes(flag) || !value) {
      usage();
    }
    const key = flag === "--handoff" ? "handoff" : "publicKey";
    if (parsed[key]) usage();
    parsed[key] = value;
  }
  if (!parsed.handoff || !parsed.publicKey) usage();
  return parsed;
}

function usage() {
  process.stderr.write(
    "Usage: node scripts/verify-platform-iac-handoff.mjs --handoff <file> --public-key <file>\n",
  );
  process.exit(2);
}
