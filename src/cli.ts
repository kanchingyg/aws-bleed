#!/usr/bin/env node
/**
 * Command-line entrypoint for `aws-bleed` read-only AWS cost waste scanner and Terraform patch generator.
 *
 * @example
 * ```ts
 * import { main } from "@kanchingyg/aws-bleed";
 *
 * await main(["--region", "us-east-1", "--dry-run"]);
 * ```
 *
 * @module
 */
import { writeFileSync } from "node:fs";
import { createLiveAwsClient } from "./aws-live.js";
import {
  probeNCtx,
  redactSecrets,
  setGuards,
  setNCtx,
  setScanClient,
  startMcpServer,
  summarizeExecReport,
} from "./bridge.js";
import { formatFindingsTable, scanAwsWaste, totalMonthlyUsd } from "./scanners.js";
import { generateFinopsPatch } from "./terraform-patch.js";

const VERSION = "0.1.1";

interface ParsedCliArgs {
  mcp: boolean;
  patch?: string;
  dryRun: boolean;
  allowWrite: boolean;
  regions: string[];
  model?: string;
  help: boolean;
}

function parseArgs(argv: string[]): ParsedCliArgs {
  const regions: string[] = [];
  let patch: string | undefined;
  let model: string | undefined;
  let mcp = false;
  let dryRun = false;
  let allowWrite = false;
  let help = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--mcp") mcp = true;
    else if (a === "--dry-run") dryRun = true;
    else if (a === "--allow-write") allowWrite = true;
    else if (a === "--help" || a === "-h") help = true;
    else if (a === "--patch") patch = argv[++i];
    else if (a === "--region") regions.push(argv[++i]);
    else if (a === "--model") model = argv[++i];
  }
  if (regions.length === 0) regions.push(process.env.AWS_REGION ?? "us-east-1");
  return { mcp, patch, dryRun, allowWrite, regions, model, help };
}

function printHelp(): void {
  process.stderr.write(`aws-bleed v${VERSION} - read-only AWS waste scanner

Usage:
  npx aws-bleed [--region us-east-1]
  npx aws-bleed --patch fix-bleed.tf [--allow-write] [--dry-run]
  npx aws-bleed --mcp [--allow-write] [--dry-run]
  npx aws-bleed --model ollama/llama3.2  # local exec summary after scan

Options:
  --region <id>     Repeatable AWS region (default: AWS_REGION or us-east-1)
  --patch <file>    Write Terraform remediation (requires --allow-write unless --dry-run)
  --dry-run         Print patch to stdout instead of writing
  --allow-write     Enable disk writes for --patch and MCP generate_finops_patch
  --mcp             Start MCP stdio server
`);
}

/** Runs the `aws-bleed` CLI or MCP server with the provided argument vector and returns an exit code. */
export async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  if (args.help) {
    printHelp();
    return 0;
  }
  setGuards({ allowWrite: args.allowWrite, dryRun: args.dryRun });
  if (args.mcp) {
    const client = createLiveAwsClient(args.regions[0]);
    setScanClient(client);
    const probed = await probeNCtx(process.env.OLLAMA_HOST ?? "http://127.0.0.1:11434");
    setNCtx(probed.nCtx);
    startMcpServer({ name: "aws-bleed", version: VERSION });
    return 0;
  }
  const client = createLiveAwsClient(args.regions[0]);
  setScanClient(client);
  const probed = await probeNCtx(process.env.OLLAMA_HOST ?? "http://127.0.0.1:11434");
  setNCtx(probed.nCtx);
  const findings = await scanAwsWaste(client, args.regions);
  if (args.patch) {
    const code = generateFinopsPatch(findings, "terraform");
    if (args.dryRun || !args.allowWrite) {
      process.stdout.write(code);
      return 0;
    }
    writeFileSync(args.patch, code, "utf8");
    process.stderr.write(`Wrote ${args.patch} (${code.length} bytes)\n`);
    return 0;
  }
  process.stdout.write(formatFindingsTable(findings) + "\n");
  process.stderr.write(
    `Estimated bleed: $${totalMonthlyUsd(findings)}/mo across ${findings.length} findings\n`,
  );
  if (args.model) {
    const summary = await summarizeExecReport(findings, args.model);
    process.stdout.write("\n--- exec summary ---\n" + summary + "\n");
  }
  return 0;
}

const isMain = process.argv[1]?.includes("cli");
if (isMain) {
  main(process.argv.slice(2))
    .then((code) => {
      if (code !== 0) process.exit(code);
    })
    .catch((e) => {
      process.stderr.write(redactSecrets(String(e)) + "\n");
      process.exit(1);
    });
}
