#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);

const candidates = [
  process.env.AWS_BLEED_BIN,
  join(__dirname, "aws-bleed.exe"),
  join(__dirname, "aws-bleed"),
  join(__dirname, "..", "aws-bleed.exe"),
  join(__dirname, "..", "aws-bleed"),
].filter(Boolean);

const native = candidates.find((p) => existsSync(p));
if (native) {
  const result = spawnSync(native, argv, {
    stdio: "inherit",
    cwd: process.cwd(),
    env: process.env,
  });
  process.exit(result.status ?? 1);
}

const { main } = await import("../dist/cli.js");
const code = await main(argv);
process.exit(code);
