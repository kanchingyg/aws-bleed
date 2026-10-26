package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/kanchingyg/aws-bleed/internal/awslive"
	"github.com/kanchingyg/aws-bleed/internal/mcp"
	"github.com/kanchingyg/aws-bleed/internal/scan"
	"github.com/kanchingyg/aws-bleed/internal/terraform"
)

const version = "0.1.0"

type cliArgs struct {
	mcp        bool
	patch      string
	dryRun     bool
	allowWrite bool
	regions    []string
	help       bool
}

func parseArgs(argv []string) cliArgs {
	out := cliArgs{regions: []string{}}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch a {
		case "--mcp":
			out.mcp = true
		case "--dry-run":
			out.dryRun = true
		case "--allow-write":
			out.allowWrite = true
		case "--help", "-h":
			out.help = true
		case "--patch":
			if i+1 < len(argv) {
				i++
				out.patch = argv[i]
			}
		case "--region":
			if i+1 < len(argv) {
				i++
				out.regions = append(out.regions, argv[i])
			}
		}
	}
	if len(out.regions) == 0 {
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = "us-east-1"
		}
		out.regions = []string{region}
	}
	return out
}

func printHelp() {
	_, _ = fmt.Fprintf(os.Stderr, `aws-bleed v%s — read-only AWS waste scanner

Usage:
  aws-bleed [--region us-east-1]
  aws-bleed --patch fix-bleed.tf [--allow-write] [--dry-run]
  aws-bleed --mcp [--allow-write] [--dry-run]

Options:
  --region <id>     Repeatable AWS region (default: AWS_REGION or us-east-1)
  --patch <file>    Write Terraform remediation (requires --allow-write unless --dry-run)
  --dry-run         Print patch to stdout instead of writing
  --allow-write     Enable disk writes for --patch and MCP generate_finops_patch
  --mcp             Start MCP stdio server
`, version)
}

func main() {
	args := parseArgs(os.Args[1:])
	if args.help {
		printHelp()
		os.Exit(0)
	}
	mcp.SetGuards(args.allowWrite, args.dryRun)

	client, err := awslive.NewLiveClient(args.regions[0])
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, mcp.RedactSecrets(err.Error()))
		os.Exit(1)
	}
	mcp.SetScanClient(client)

	if args.mcp {
		if err := mcp.RunServer("aws-bleed", version); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, mcp.RedactSecrets(err.Error()))
			os.Exit(1)
		}
		return
	}

	findings, err := scan.ScanAwsWaste(client, args.regions)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, mcp.RedactSecrets(err.Error()))
		os.Exit(1)
	}

	if args.patch != "" {
		code := terraform.GenerateFinopsPatch(findings, "terraform", nil)
		if args.dryRun || !args.allowWrite {
			_, _ = os.Stdout.WriteString(code)
			return
		}
		if err := os.WriteFile(args.patch, []byte(code), 0o644); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, mcp.RedactSecrets(err.Error()))
			os.Exit(1)
		}
		_, _ = fmt.Fprintf(os.Stderr, "Wrote %s (%d bytes)\n", args.patch, len(code))
		return
	}

	table := scan.FormatFindingsTable(findings, nil)
	_, _ = fmt.Fprintln(os.Stdout, table)
	_, _ = fmt.Fprintf(os.Stderr, "Estimated bleed: $%s/mo across %d findings\n",
		formatUSD(scan.TotalMonthlyUSD(findings)), len(findings))
}

func formatUSD(n float64) string {
	s := fmt.Sprintf("%.2f", n)
	return strings.TrimRight(strings.TrimRight(s, "0"), ".")
}
