---
name: aws-bleed
description: Read-only AWS waste scan (NAT endpoint tax, infinite logs, zombie EBS/EIPs) with Terraform fix output.
---

# aws-bleed

## When to use

- Before a FinOps PR: quantify hidden monthly bleed and generate `fix-bleed.tf`.
- From an agent: run MCP tools instead of hand-rolling Cost Explorer queries.

## CLI

```bash
npx aws-bleed
npx aws-bleed --region us-west-2 --patch fix-bleed.tf --allow-write
npx aws-bleed --patch fix-bleed.tf --dry-run
npx aws-bleed --mcp
```

## MCP tools

| Tool | Role |
| --- | --- |
| `scan_aws_waste` | Read-only `Describe*` scan, findings sorted by `monthlyUsdSaved` |
| `generate_finops_patch` | Terraform or shell patch (`--allow-write` to write `writePath`) |
| `summarize_exec_report` | Local Ollama/LM Studio summary (no USD amounts in the request) |

Register in `.cursor/mcp.json`:

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

## Safety

- Default is read-only; disk writes need `--allow-write`.
- Identical MCP tool calls trip the loop breaker on the third repeat.
