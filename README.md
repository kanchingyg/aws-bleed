# aws-bleed

[![ci](https://github.com/kanchingyg/aws-bleed/actions/workflows/ci.yml/badge.svg)](https://github.com/kanchingyg/aws-bleed/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/aws-bleed/latest?label=npm)](https://www.npmjs.com/package/aws-bleed)
[![JSR](https://jsr.io/badges/@kanchingyg/aws-bleed)](https://jsr.io/@kanchingyg/aws-bleed)
[![JSR Score](https://jsr.io/badges/@kanchingyg/aws-bleed/score)](https://jsr.io/@kanchingyg/aws-bleed/score)
[![Go](https://img.shields.io/badge/engine-Go_%2B_TypeScript-00ADD8)](https://github.com/kanchingyg/aws-bleed)
[![license](https://img.shields.io/github/license/kanchingyg/aws-bleed)](https://github.com/kanchingyg/aws-bleed/blob/HEAD/LICENSE)

**5-second read-only scan** for expensive AWS hidden taxes: NAT Gateway traffic to S3/DynamoDB without free gateway endpoints, CloudWatch Logs with infinite retention, `gp2` and orphaned EBS volumes, idle Elastic IPs, and stale snapshots, complete with **USD/month estimates** and a **`fix-bleed.tf`** Terraform patch.

## Install

[Bun](https://bun.sh) / [npm](https://www.npmjs.com/package/aws-bleed):

```bash
bunx aws-bleed
npx aws-bleed

# or install in your project / globally
bun add -d aws-bleed
npm i -D aws-bleed
```

[JSR](https://jsr.io/@kanchingyg/aws-bleed):

```bash
bunx jsr add @kanchingyg/aws-bleed
npx jsr add @kanchingyg/aws-bleed
```

[Go (native binary)](https://github.com/kanchingyg/aws-bleed):

```bash
go install github.com/kanchingyg/aws-bleed@latest
```

The core engine is **Go** (`main.go`, `internal/`). TypeScript under `src/*.ts` is included for `npx` / `bunx` / JSR usage and MCP bridge helpers when no native binary is present.

## Quick start

```bash
npx aws-bleed
bunx aws-bleed
npx aws-bleed --patch fix-bleed.tf --allow-write
npx aws-bleed --mcp
```

## What you get

| Finding | Fix in patch |
| --- | --- |
| NAT in VPC without S3/DynamoDB gateway endpoints | `aws_vpc_endpoint` (Gateway) |
| Log groups with `retentionInDays = null` | `retention_in_days` |
| `gp2` volumes | `gp3` migration block |
| `available` volumes / idle EIPs / old snapshots | Comments + CLI cleanup hints |

## MCP + local models

```bash
npx aws-bleed --mcp
bunx aws-bleed --mcp
```

Use `summarize_exec_report` with `--model ollama/llama3.2` (or any OpenAI-compatible local server) so cost data stays on your machine.

## Requirements

- Node 18+ or Bun for `npx` / `bunx`, or Go 1.22+ for native CLI
- AWS credentials with read-only `Describe*` / `List*` (no writes unless you pass `--allow-write` for patch files)

## MCP Tools Reference

| Tool | Mutates | Description |
| --- | --- | --- |
| `scan_aws_bleed` | `false` | Run read-only FinOps checks across NAT Gateways, VPC Gateway Endpoints, EBS volumes, Elastic IPs, snapshots, and CloudWatch Log Groups. |
| `generate_finops_patch` | `false` | Render a `terraform` or `cloudformation` remediation patch (`aws_vpc_endpoint`, `gp3` migration, log retention). |
| `write_finops_patch` | `true` | Write the generated FinOps patch file to disk inside the workspace (requires `--allow-write`). |
| `summarize_exec_report` | `false` | Format a concise monthly waste report suitable for engineering review. |

## Editor and Agent Integration

### Cursor (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "aws-bleed": {
      "command": "npx",
      "args": ["-y", "aws-bleed", "--mcp"]
    }
  }
}
```

### Claude Code CLI

```bash
claude mcp add aws-bleed -- npx -y aws-bleed --mcp
```

### Programmatic Usage (JSR / TypeScript)

```ts
import * as bridge from "jsr:@kanchingyg/aws-bleed/bridge";
```

## Runtime Safety and Guardrails

- **Stdio frame isolation**: When `--mcp` is active, `hijackStdoutForMcp()` redirects accidental `console.log` calls to `stderr` so JSON-RPC 2.0 frames on `stdout` never corrupt.
- **Read-only by default**: Mutating tools (`mutates: true`) are blocked in `--dry-run` mode and require explicit `--allow-write` authorization.
- **Loop breaker**: Repeated identical `(toolName, args)` invocations are hashed with SHA-256 and halted after 3 consecutive repeats to prevent runaway agent loops.
- **Context budget truncation**: Tool outputs are middle-truncated (`60%` head / `40%` tail) scaled to the probed local model `n_ctx` (Ollama `/api/show`, llama.cpp `/props`, vLLM `/v1/models`).
- **Secret redaction and path normalization**: AWS keys (`AKIA*`, `ASIA*`), bearer tokens, and `sk-*` keys are scrubbed before returning tool output, and Windows drive paths (`C:\...`) translate cleanly to `/mnt/c/...` when WSL mode is enabled.

## License

[MIT](./LICENSE)
