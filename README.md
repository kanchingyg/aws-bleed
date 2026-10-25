# aws-bleed

**5-second read-only scan** for the expensive AWS “hidden taxes”: NAT Gateway traffic to S3/Dynamo without free gateway endpoints, CloudWatch Logs with no retention, `gp2` and orphaned EBS, idle EIPs, and stale snapshots — with **USD/month estimates** and a **`fix-bleed.tf`** patch.

```bash
npx aws-bleed
npx aws-bleed --patch fix-bleed.tf --allow-write
npx aws-bleed --mcp
```

## What you get

| Finding | Fix in patch |
| --- | --- |
| NAT in VPC without S3/Dynamo gateway endpoints | `aws_vpc_endpoint` (Gateway) |
| Log groups with `retentionInDays = null` | `retention_in_days` |
| `gp2` volumes | `gp3` migration block |
| `available` volumes / idle EIPs / old snapshots | Comments + CLI hints |

## MCP + local models

```bash
npx aws-bleed --mcp
```

Use `summarize_exec_report` with `--model ollama/llama3.2` (or any OpenAI-compatible local server) so cost structure stays on your machine.

## Requirements

- Node 18+
- AWS credentials with read-only `Describe*` / `List*` (no writes unless you pass `--allow-write` for patch files)

## License

MIT
