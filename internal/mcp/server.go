package mcp

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/kanchingyg/aws-bleed/internal/scan"
	"github.com/kanchingyg/aws-bleed/internal/terraform"
)

const (
	DefaultNCtx   = 4096
	Version       = "0.1.1"
	truncMarker   = "[…truncated by aws-bleed…]"
	protocolVer   = "2024-11-05"
)

var (
	allowWrite   bool
	dryRun       bool
	nCtx         = DefaultNCtx
	scanClient   scan.Client
	lastFindings []scan.Finding

	loopMu       sync.Mutex
	loopLastHash string
	loopRepeat   int

	secretRE = regexp.MustCompile(`(?:sk-[a-zA-Z0-9]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|Bearer\s+[a-zA-Z0-9._-]+)`)
)

// SetGuards configures write and dry-run behavior for MCP tools.
func SetGuards(allow bool, dry bool) {
	allowWrite = allow
	dryRun = dry
}

// SetNCtx sets context window size for truncation.
func SetNCtx(value int) {
	if value > 0 {
		nCtx = value
	} else {
		nCtx = DefaultNCtx
	}
}

// SetScanClient sets the AWS inventory client for scan_aws_waste.
func SetScanClient(client scan.Client) {
	scanClient = client
}

// LastFindings returns findings from the most recent scan.
func LastFindings() []scan.Finding {
	return lastFindings
}

func canonicalizeJSON(value interface{}) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case bool:
		if v {
			return "true"
		}
		return "false"
	case float64:
		return fmt.Sprintf("%v", v)
	case string:
		b, _ := json.Marshal(v)
		return string(b)
	case []interface{}:
		parts := make([]string, len(v))
		for i, item := range v {
			parts[i] = canonicalizeJSON(item)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = fmt.Sprintf("%q:%s", k, canonicalizeJSON(v[k]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// ResetLoopBreaker clears loop detection state (for tests).
func ResetLoopBreaker() {
	loopMu.Lock()
	loopLastHash = ""
	loopRepeat = 0
	loopMu.Unlock()
}

// CheckLoopBreaker returns an error message on the third identical tool call.
func CheckLoopBreaker(toolName string, args interface{}) string {
	payload := toolName + ":" + canonicalizeJSON(args)
	hash := sha256.Sum256([]byte(payload))
	h := hex.EncodeToString(hash[:])
	loopMu.Lock()
	defer loopMu.Unlock()
	if h == loopLastHash {
		loopRepeat++
	} else {
		loopLastHash = h
		loopRepeat = 1
	}
	if loopRepeat >= 3 {
		return "LOOP_BREAKER: Identical tool call repeated 2 times consecutively. Stop calling tools and return your final synthesis."
	}
	return ""
}

// GuardMutatingTool reports whether a mutating tool is blocked.
func GuardMutatingTool(mutates bool) (blocked bool, reason string) {
	if !mutates {
		return false, ""
	}
	if dryRun {
		return false, ""
	}
	if !allowWrite {
		return true, "Read-only mode: pass --allow-write to enable mutating tools."
	}
	return false, ""
}

// RedactSecrets masks common credential patterns.
func RedactSecrets(text string) string {
	return secretRE.ReplaceAllString(text, "[REDACTED]")
}

// HeadTailTruncate keeps head and tail with an honest marker.
func HeadTailTruncate(text string, maxChars int) string {
	if len(text) <= maxChars {
		return text
	}
	headLen := int(float64(maxChars) * 0.6)
	tailLen := maxChars - headLen - len(truncMarker)
	if tailLen < 0 {
		tailLen = 0
	}
	return text[:headLen] + truncMarker + text[len(text)-tailLen:]
}

// RunServer handles MCP JSON-RPC on stdio.
func RunServer(serverName string, version string) error {
	stdin := bufio.NewReader(os.Stdin)
	stdout := os.Stdout
	for {
		line, err := stdin.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var msg map[string]interface{}
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}
		dispatchMessage(msg, serverName, version, stdout)
	}
}

func writeFrame(stdout *os.File, obj interface{}) {
	line, _ := json.Marshal(obj)
	line = append(line, '\n')
	_, _ = stdout.Write(line)
}

func dispatchMessage(msg map[string]interface{}, serverName, version string, stdout *os.File) {
	id := msg["id"]
	method, _ := msg["method"].(string)
	params, _ := msg["params"].(map[string]interface{})

	switch method {
	case "initialize":
		writeFrame(stdout, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      id,
			"result": map[string]interface{}{
				"protocolVersion": protocolVer,
				"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
				"serverInfo":      map[string]interface{}{"name": serverName, "version": version},
			},
		})
	case "notifications/initialized":
		return
	case "tools/list":
		writeFrame(stdout, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      id,
			"result": map[string]interface{}{
				"tools": defaultToolSchemas(),
			},
		})
	case "tools/call":
		name, _ := params["name"].(string)
		args, _ := params["arguments"].(map[string]interface{})
		if args == nil {
			args = map[string]interface{}{}
		}
		if loopErr := CheckLoopBreaker(name, args); loopErr != "" {
			writeFrame(stdout, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"content": []map[string]interface{}{{"type": "text", "text": loopErr}},
					"isError": true,
				},
			})
			return
		}
		mutates := name == "generate_finops_patch"
		if blocked, reason := GuardMutatingTool(mutates); blocked {
			writeFrame(stdout, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"content": []map[string]interface{}{{"type": "text", "text": reason}},
					"isError": true,
				},
			})
			return
		}
		result, err := handleTool(name, args)
		text := ""
		if err != nil {
			text = RedactSecrets(err.Error())
			writeFrame(stdout, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"result": map[string]interface{}{
					"content": []map[string]interface{}{{"type": "text", "text": text}},
					"isError": true,
				},
			})
			return
		}
		b, _ := json.MarshalIndent(result, "", "  ")
		text = RedactSecrets(string(b))
		budget := int(float64(nCtx*4) * 0.3)
		text = HeadTailTruncate(text, budget)
		writeFrame(stdout, map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      id,
			"result": map[string]interface{}{
				"content": []map[string]interface{}{{"type": "text", "text": text}},
			},
		})
	default:
		if id != nil {
			writeFrame(stdout, map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      id,
				"error":   map[string]interface{}{"code": -32601, "message": "Method not found: " + method},
			})
		}
	}
}

func defaultToolSchemas() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name":        "scan_aws_waste",
			"description": "Scan AWS account for hidden cost bleed (read-only).",
			"inputSchema": map[string]interface{}{
				"type":                 "object",
				"properties":           map[string]interface{}{"regions": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}},
				"additionalProperties": false,
			},
			"annotations": map[string]interface{}{"readOnlyHint": true},
		},
		{
			"name":        "generate_finops_patch",
			"description": "Emit Terraform or CLI patch for selected findings.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"findingIds": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
					"format":     map[string]interface{}{"type": "string", "enum": []string{"terraform", "cli"}},
					"writePath":  map[string]interface{}{"type": "string"},
				},
				"required":               []string{"format"},
				"additionalProperties": false,
			},
			"annotations": map[string]interface{}{"destructiveHint": true},
		},
		{
			"name":        "summarize_exec_report",
			"description": "Local LLM executive summary for FinOps PR (no USD sent).",
			"inputSchema": map[string]interface{}{
				"type":                 "object",
				"properties":           map[string]interface{}{"findingIds": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}}, "model": map[string]interface{}{"type": "string"}},
				"additionalProperties": false,
			},
			"annotations": map[string]interface{}{"readOnlyHint": true},
		},
	}
}

func handleTool(name string, args map[string]interface{}) (map[string]interface{}, error) {
	switch name {
	case "scan_aws_waste":
		if scanClient == nil {
			return nil, fmt.Errorf("No AWS scan client configured")
		}
		regions := []string{"us-east-1"}
		if raw, ok := args["regions"].([]interface{}); ok && len(raw) > 0 {
			regions = make([]string, len(raw))
			for i, r := range raw {
				regions[i] = fmt.Sprint(r)
			}
		}
		all, err := scan.ScanAwsWaste(scanClient, regions)
		if err != nil {
			return nil, err
		}
		lastFindings = all
		shown := scan.TruncateFindingsForMcp(all, nCtx)
		total := scan.TotalMonthlyUSD(all)
		totalCount := len(all)
		table := scan.FormatFindingsTable(shown, &scan.FormatOptions{
			TotalCount:      &totalCount,
			TotalMonthlyUSD: &total,
		})
		findingsJSON := make([]map[string]interface{}, len(shown))
		for i, f := range shown {
			findingsJSON[i] = findingToMap(f)
		}
		return map[string]interface{}{
			"findings":        findingsJSON,
			"totalFindings":   len(all),
			"totalMonthlyUsd": total,
			"table":           table,
		}, nil
	case "generate_finops_patch":
		format := "terraform"
		if f, ok := args["format"].(string); ok && f != "" {
			format = f
		}
		var ids []string
		if raw, ok := args["findingIds"].([]interface{}); ok {
			for _, id := range raw {
				ids = append(ids, fmt.Sprint(id))
			}
		}
		code := terraform.GenerateFinopsPatch(lastFindings, format, ids)
		writePath, _ := args["writePath"].(string)
		if writePath != "" && allowWrite && !dryRun {
			if err := os.WriteFile(writePath, []byte(code), 0o644); err != nil {
				return nil, err
			}
			return map[string]interface{}{"written": writePath, "bytes": len(code)}, nil
		}
		return map[string]interface{}{"code": code}, nil
	case "summarize_exec_report":
		return map[string]interface{}{"summary": "FinOps summary requires local OpenAI-compatible endpoint (use npx bridge or --model)."}, nil
	default:
		return map[string]interface{}{"error": "unknown tool"}, nil
	}
}

func findingToMap(f scan.Finding) map[string]interface{} {
	return map[string]interface{}{
		"id":              f.ID,
		"kind":            f.Kind,
		"region":          f.Region,
		"monthlyUsdSaved": f.MonthlyUSDSaved,
		"evidence":        f.Evidence,
	}
}

// DispatchMessage exposes JSON-RPC dispatch for tests.
func DispatchMessage(msg map[string]interface{}, serverName, version string, w io.Writer) {
	f, ok := w.(*os.File)
	if !ok {
		return
	}
	dispatchMessage(msg, serverName, version, f)
}
