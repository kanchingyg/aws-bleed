import { describe, it, expect, beforeEach, vi } from "vitest";
import { PRICING, formatFindingsTable, scanAwsWaste, totalMonthlyUsd, truncateFindingsForMcp, } from "../src/scanners.js";
import { escapeHclString, generateFinopsPatch } from "../src/terraform-patch.js";
import { paginateWithToken } from "../src/aws-live.js";
import { applyReasoningContentPolicy, base64ToFloatArray, checkLoopBreaker, createReasoningState, dispatchMcpMessage, floatArrayToBase64, guardMutatingTool, headTailTruncate, hijackStdoutForMcp, jsonRpcFrameLog, mrlSlice, normalizeEmbedBatch, parseDirtyToolCall, probeNCtx, redactSecrets, resetLoopBreaker, sanitizeRequestBody, setGuards, setScanClient, StreamToolJsonAbort, stripRedactedThinking, summarizeExecReport, windowsToWsl, wslToWindows, buildRecencyAnchor, anchorPromptTail, defaultTools, } from "../src/bridge.js";
function mockClient() {
    const stale = new Date(Date.now() - 100 * 86_400_000).toISOString();
    return {
        describeNatGateways: async () => [
            { natGatewayId: "nat-0abc", vpcId: "vpc-aaa", state: "available" },
        ],
        describeVpcEndpoints: async () => [],
        describeVolumes: async () => [
            { volumeId: "vol-gp2", sizeGiB: 100, volumeType: "gp2", state: "in-use" },
            { volumeId: "vol-orphan", sizeGiB: 50, volumeType: "gp3", state: "available" },
        ],
        describeAddresses: async () => [
            { allocationId: "eipalloc-1", publicIp: "203.0.113.10" },
        ],
        describeSnapshots: async () => [
            { snapshotId: "snap-old", volumeSizeGiB: 20, startTime: stale },
        ],
        describeLogGroups: async () => [
            {
                logGroupName: "/app/prod",
                retentionInDays: null,
                storedBytes: 10 * 1_073_741_824,
            },
        ],
    };
}
describe("scanAwsWaste", () => {
    it("computes USD/mo from mocked Describe* inventory", async () => {
        const findings = await scanAwsWaste(mockClient(), ["us-east-1"]);
        const nat = findings.find((f) => f.kind === "nat_missing_endpoints");
        expect(nat?.monthlyUsdSaved).toBe(PRICING.NAT_MISSING_ENDPOINT_BLEED_USD);
        const logs = findings.find((f) => f.kind === "logs_infinite_retention");
        expect(logs?.monthlyUsdSaved).toBe(5);
        const gp2 = findings.find((f) => f.kind === "ebs_gp2");
        expect(gp2?.monthlyUsdSaved).toBe(100 * PRICING.GP2_SURCHARGE_PER_GB_USD);
        const avail = findings.find((f) => f.kind === "ebs_available");
        expect(avail?.monthlyUsdSaved).toBe(50 * PRICING.AVAILABLE_VOLUME_PER_GB_USD);
        const eip = findings.find((f) => f.kind === "eip_unassociated");
        expect(eip?.monthlyUsdSaved).toBe(PRICING.IDLE_EIP_USD);
        const snap = findings.find((f) => f.kind === "snapshot_stale");
        expect(snap?.monthlyUsdSaved).toBe(20 * PRICING.SNAPSHOT_PER_GB_USD);
        expect(totalMonthlyUsd(findings)).toBe(60.65);
    });
});
describe("terraform patch", () => {
    it("emits valid gateway endpoint and log retention HCL", async () => {
        const findings = await scanAwsWaste(mockClient(), ["us-east-1"]);
        const hcl = generateFinopsPatch(findings, "terraform");
        expect(hcl).toContain('resource "aws_vpc_endpoint"');
        expect(hcl).toContain("com.amazonaws.us-east-1.s3");
        expect(hcl).toContain("com.amazonaws.us-east-1.dynamodb");
        expect(hcl).toContain("retention_in_days = 30");
        expect(hcl).toContain('type              = "gp3"');
    });
    it("escapes quotes and backslashes in log group HCL strings", () => {
        expect(escapeHclString('a"b\\c')).toBe('a\\"b\\\\c');
        const findings = [
            {
                id: "log-x",
                kind: "logs_infinite_retention",
                region: "us-east-1",
                monthlyUsdSaved: 1,
                evidence: { logGroupName: '/app/"prod"', storedGiB: 1, retentionInDays: null },
            },
        ];
        const hcl = generateFinopsPatch(findings, "terraform");
        expect(hcl).toContain('name              = "/app/\\"prod\\""');
    });
});
describe("paginateWithToken", () => {
    it("aggregates multiple pages until NextToken is absent", async () => {
        const pages = [
            { items: [1, 2], nextToken: "page2" },
            { items: [3], nextToken: "page3" },
            { items: [4, 5] },
        ];
        let calls = 0;
        const all = await paginateWithToken(async () => {
            const page = pages[calls++];
            if (!page)
                throw new Error("unexpected page");
            return page;
        });
        expect(all).toEqual([1, 2, 3, 4, 5]);
        expect(calls).toBe(3);
    });
});
describe("findings truncate messaging", () => {
    it("reports showing N of M with full-account TOTAL", () => {
        const findings = Array.from({ length: 12 }, (_, i) => ({
            id: `f-${i}`,
            kind: "eip_unassociated",
            region: "us-east-1",
            monthlyUsdSaved: 12 - i,
            evidence: {},
        }));
        const shown = truncateFindingsForMcp(findings, 1000);
        expect(shown.length).toBeLessThan(findings.length);
        const table = formatFindingsTable(shown, {
            totalCount: findings.length,
            totalMonthlyUsd: totalMonthlyUsd(findings),
        });
        expect(table).toMatch(/showing \d+ of 12 findings/);
        expect(table).toContain(`TOTAL\t\t${totalMonthlyUsd(findings)}`);
    });
});
describe("secrets redaction", () => {
    it("redacts ASIA session keys like AKIA", () => {
        const text = "leak ASIAIOSFODNN7EXAMPLE still";
        expect(redactSecrets(text)).toBe("leak [REDACTED] still");
    });
});
describe("MCP dry-run", () => {
    beforeEach(() => {
        setGuards({ allowWrite: false, dryRun: true });
        setScanClient(mockClient());
    });
    it("runs scan_aws_waste under dry-run (writes only blocked in patch handler)", async () => {
        const scan = defaultTools().find((t) => t.name === "scan_aws_waste");
        expect(scan).toBeDefined();
        const result = await scan!.handler({ regions: ["us-east-1"] }, {
            dryRun: true,
            allowWrite: false,
            nCtx: 4096,
        });
        expect(result.totalFindings).toBe(6);
        expect(result.findings.some((f) => f.kind === "nat_missing_endpoints")).toBe(true);
        const patch = defaultTools().find((t) => t.name === "generate_finops_patch");
        const patchResult = await patch!.handler({
            format: "terraform",
            writePath: "/tmp/fix.tf",
        }, { dryRun: true, allowWrite: true, nCtx: 4096 });
        expect(patchResult).toHaveProperty("code");
        expect(patchResult).not.toHaveProperty("written");
    });
});
describe("MCP JSON-RPC", () => {
    beforeEach(() => {
        jsonRpcFrameLog.length = 0;
        hijackStdoutForMcp();
    });
    it("handshake initialize and tools/list", () => {
        const tools = [
            {
                name: "scan_aws_waste",
                description: "Scan AWS waste",
                inputSchema: { type: "object", properties: {} },
                handler: async () => ({}),
            },
        ];
        dispatchMcpMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, {
            tools,
            handlers: new Map(),
            toWsl: false,
            serverName: "aws-bleed",
            version: "0.1.0",
        });
        dispatchMcpMessage({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, {
            tools,
            handlers: new Map(),
            toWsl: false,
            serverName: "aws-bleed",
            version: "0.1.0",
        });
        const init = JSON.parse(jsonRpcFrameLog[0].trim());
        expect(init.result.serverInfo.name).toBe("aws-bleed");
        const list = JSON.parse(jsonRpcFrameLog[1].trim());
        expect(list.result.tools[0].name).toBe("scan_aws_waste");
    });
});
describe("Blindaje 1", () => {
    beforeEach(() => {
        resetLoopBreaker();
        setGuards({ allowWrite: false, dryRun: false });
    });
    it("blocks mutating tools without allow-write", () => {
        expect(guardMutatingTool({ mutates: true }).blocked).toBe(true);
        expect(guardMutatingTool({ annotations: { destructiveHint: true } }).blocked).toBe(true);
    });
    it("loop breaker on third identical call", () => {
        expect(checkLoopBreaker("t", { a: 1 })).toBeNull();
        expect(checkLoopBreaker("t", { a: 1 })).toBeNull();
        expect(checkLoopBreaker("t", { a: 1 })).toMatch(/LOOP_BREAKER/);
    });
});
describe("Blindaje 2", () => {
    it("head+tail truncation and recency anchor", () => {
        const long = "H".repeat(200) + "T".repeat(200);
        const out = headTailTruncate(long, 200);
        expect(out).toContain("truncated");
        const anchor = buildRecencyAnchor([{ name: "scan_aws_waste", summary: "regions?" }]);
        const prompt = anchorPromptTail("SYSTEM\nASSISTANT:", anchor);
        expect(prompt.indexOf(anchor)).toBeLessThan(prompt.lastIndexOf("ASSISTANT:"));
    });
    it("probeNCtx falls back", async () => {
        const fetchImpl = vi.fn().mockRejectedValue(new Error("offline"));
        const r = await probeNCtx("http://127.0.0.1:9", fetchImpl);
        expect(r.source).toBe("fallback");
    });
});
describe("Blindaje 3 embed", () => {
    it("batches and filters empty strings", async () => {
        const calls = [];
        const embeddings = await normalizeEmbedBatch(["", "hello", "   "], {
            maxBatch: 10,
            dimensions: 2,
            embed: async (batch) => {
                calls.push(batch.length);
                return batch.map(() => [1, 0]);
            },
        });
        expect(calls).toEqual([1]);
        expect(embeddings[0]).toEqual([0, 0]);
        expect(embeddings[1][0]).toBeCloseTo(1);
    });
    it("float base64 roundtrip and MRL L2", () => {
        const b64 = floatArrayToBase64([3, 4]);
        expect(base64ToFloatArray(b64)[0]).toBeCloseTo(3);
        const sliced = mrlSlice([3, 4, 0], 2);
        expect(Math.hypot(sliced[0], sliced[1])).toBeCloseTo(1);
    });
});
describe("Blindaje 5", () => {
    it("reasoning_content strip on new user turn", () => {
        let state = createReasoningState();
        const msgs = [
            { role: "user", content: "hi" },
            { role: "assistant", content: "ok", reasoning_content: "think", tool_calls: [{}] },
        ];
        const r1 = applyReasoningContentPolicy(msgs, state, false);
        expect(r1.messages[1].reasoning_content).toBe("think");
        state = r1.state;
        const r2 = applyReasoningContentPolicy([...msgs, { role: "user", content: "next" }], state, true);
        expect(r2.messages[1].reasoning_content).toBeUndefined();
    });
    it("parses Kimi GLM Qwen and broken JSON", () => {
        const kimi = "functions.run:0<|tool_call_argument_begin|>{\"target\":\"x\"}<|tool_call_end|>";
        expect(parseDirtyToolCall(kimi)?.name).toBe("run");
        const glm = "<|tool_call_begin|>run_check<|tool_call_sep|>{\"target\":\"a\"}<|tool_call_end|>";
        expect(parseDirtyToolCall(glm)?.arguments.target).toBe("a");
        const qwen = "✿FUNCTION✿: run_check\n✿ARGS✿: {'target': 'z'}\n";
        expect(parseDirtyToolCall(qwen)?.name).toBe("run_check");
        expect(parseDirtyToolCall("{'cmd': 'ls'}")?.arguments).toEqual({ cmd: "ls" });
    });
    it("stream abort when tool JSON closes", () => {
        const guard = new StreamToolJsonAbort();
        expect(guard.feed('<tool_call>{"name":"t","arguments":{')).toBe(false);
        expect(guard.feed("}}")).toBe(true);
    });
    it("sanitizes reasoner temperature", () => {
        const body = sanitizeRequestBody({ temperature: 0.2, model: "deepseek-reasoner" }, true);
        expect(body.temperature).toBeUndefined();
        const thinkOpen = "<" + "think" + ">";
        const thinkClose = "</" + "think" + ">";
        expect(stripRedactedThinking(`${thinkOpen}x${thinkClose}hi`)).toBe("hi");
    });
});
describe("local LLM summary", () => {
    it("calls OpenAI-compatible endpoint without USD in prompt", async () => {
        const findings = await scanAwsWaste(mockClient(), ["us-east-1"]);
        const fetchMock = vi.fn().mockResolvedValue({
            ok: true,
            json: async () => ({
                choices: [{ message: { content: "FinOps summary without dollars." } }],
            }),
        });
        const text = await summarizeExecReport(findings, "ollama/llama3.2", fetchMock);
        expect(text).toContain("FinOps");
        const body = JSON.parse(String(fetchMock.mock.calls[0][1]?.body));
        expect(JSON.stringify(body)).not.toMatch(/60\.65/);
    });
});
describe("path normalize", () => {
    it("translates windows and wsl", () => {
        expect(windowsToWsl("D:\\proj\\foo.ts")).toBe("/mnt/d/proj/foo.ts");
        expect(wslToWindows("/mnt/d/proj/foo.ts")).toBe("D:\\proj\\foo.ts");
    });
});
describe("default MCP tools", () => {
    it("exposes three finops tools", () => {
        const tools = defaultTools();
        expect(tools.map((t) => t.name)).toEqual([
            "scan_aws_waste",
            "generate_finops_patch",
            "summarize_exec_report",
        ]);
    });
});
