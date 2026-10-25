#!/usr/bin/env node
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { formatFindingsTable, scanAwsWaste, truncateFindingsForMcp, totalMonthlyUsd, } from "./scanners.js";
import { generateFinopsPatch } from "./terraform-patch.js";
export const DEFAULT_N_CTX = 4096;
const TRUNC_MARKER = "[…truncated by aws-bleed…]";
let allowWrite = false;
let dryRun = false;
let nCtx = DEFAULT_N_CTX;
let scanClient = null;
let lastFindings = [];
export function setScanClient(client) {
    scanClient = client;
}
export function getLastFindings() {
    return lastFindings;
}
export function setGuards(opts) {
    allowWrite = Boolean(opts.allowWrite);
    dryRun = Boolean(opts.dryRun);
}
export function setNCtx(value) {
    nCtx = value > 0 ? value : DEFAULT_N_CTX;
}
export function canonicalizeJson(value) {
    if (value === null || value === undefined)
        return "null";
    if (typeof value !== "object")
        return JSON.stringify(value);
    if (Array.isArray(value))
        return `[${value.map((v) => canonicalizeJson(v)).join(",")}]`;
    const obj = value;
    const keys = Object.keys(obj).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`).join(",")}}`;
}
const loopState = { lastHash: "", repeatCount: 0 };
export function resetLoopBreaker() {
    loopState.lastHash = "";
    loopState.repeatCount = 0;
}
export function checkLoopBreaker(toolName, args) {
    const h = createHash("sha256")
        .update(`${toolName}:${canonicalizeJson(args)}`)
        .digest("hex");
    if (h === loopState.lastHash)
        loopState.repeatCount++;
    else {
        loopState.lastHash = h;
        loopState.repeatCount = 1;
    }
    if (loopState.repeatCount >= 3) {
        return "LOOP_BREAKER: Identical tool call repeated 2 times consecutively. Stop calling tools and return your final synthesis.";
    }
    return null;
}
export function guardMutatingTool(tool) {
    if (!(tool?.mutates || tool?.annotations?.destructiveHint))
        return { blocked: false };
    if (dryRun)
        return { blocked: false };
    if (!allowWrite) {
        return { blocked: true, reason: "Read-only mode: pass --allow-write to enable mutating tools." };
    }
    return { blocked: false };
}
const WIN_DRIVE_RE = /^([A-Za-z]):\\(.*)$/;
const WSL_RE = /^\/mnt\/([a-z])\/(.*)$/i;
export function windowsToWsl(p) {
    const m = p.match(WIN_DRIVE_RE);
    if (!m)
        return p;
    return `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, "/")}`;
}
export function wslToWindows(p) {
    const m = p.match(WSL_RE);
    if (!m)
        return p;
    return `${m[1].toUpperCase()}:\\${m[2].replace(/\//g, "\\")}`;
}
export function normalizePathsDeep(value, toWsl) {
    if (typeof value === "string") {
        if (toWsl && WIN_DRIVE_RE.test(value))
            return windowsToWsl(value);
        if (!toWsl && WSL_RE.test(value))
            return wslToWindows(value);
        return value;
    }
    if (Array.isArray(value))
        return value.map((v) => normalizePathsDeep(v, toWsl));
    if (value && typeof value === "object") {
        const out = {};
        for (const [k, v] of Object.entries(value)) {
            out[k] = normalizePathsDeep(v, toWsl);
        }
        return out;
    }
    return value;
}
const SECRET_RE = /(?:sk-[a-zA-Z0-9]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|Bearer\s+[a-zA-Z0-9._-]+)/g;
export function redactSecrets(text) {
    return text.replace(SECRET_RE, "[REDACTED]");
}
let stdoutHijacked = false;
let jsonRpcWrite = null;
export const jsonRpcFrameLog = [];
export function hijackStdoutForMcp() {
    if (stdoutHijacked)
        return;
    stdoutHijacked = true;
    const native = process.stdout.write.bind(process.stdout);
    jsonRpcWrite = (line) => native(line);
    process.stdout.write = ((chunk, ...args) => {
        const str = typeof chunk === "string" ? chunk : Buffer.from(chunk).toString();
        if (str.trim().startsWith("{") && str.includes('"jsonrpc"')) {
            return native(chunk, ...args);
        }
        process.stderr.write(str);
        return true;
    });
}
export function writeJsonRpcFrame(obj) {
    const line = JSON.stringify(obj) + "\n";
    jsonRpcFrameLog.push(line);
    if (jsonRpcWrite)
        jsonRpcWrite(line);
    else
        process.stdout.write(line);
}
export function headTailTruncate(text, maxChars) {
    if (text.length <= maxChars)
        return text;
    const headLen = Math.floor(maxChars * 0.6);
    const tailLen = Math.max(0, Math.floor(maxChars * 0.4) - TRUNC_MARKER.length);
    return text.slice(0, headLen) + TRUNC_MARKER + text.slice(-tailLen);
}
export function buildRecencyAnchor(tools) {
    const lines = tools.map((t) => `- ${t.name}(${t.summary})`);
    return `[AVAILABLE TOOLS - ANCHORED FOR RECENCY]\n${lines.join("\n")}\nTo call a tool, output ONLY: <tool_call>{"name":"TOOL","arguments":{}}</tool_call>`;
}
export function anchorPromptTail(prompt, anchor) {
    const marker = "ASSISTANT:";
    const idx = prompt.lastIndexOf(marker);
    if (idx < 0)
        return `${prompt}\n\n${anchor}\n${marker}`;
    return prompt.slice(0, idx) + `\n${anchor}\n` + prompt.slice(idx);
}
export async function probeNCtx(baseUrl, fetchImpl = fetch) {
    const base = baseUrl.replace(/\/$/, "");
    try {
        const props = await fetchImpl(`${base}/props`);
        if (props.ok) {
            const j = (await props.json());
            if (j.n_ctx && j.n_ctx > 0)
                return { nCtx: j.n_ctx, source: "llama.cpp" };
        }
    }
    catch {
        /* continue */
    }
    try {
        const show = await fetchImpl(`${base}/api/show`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: "dummy" }),
        });
        if (show.ok) {
            const j = (await show.json());
            for (const [k, v] of Object.entries(j.model_info ?? {})) {
                if (k.includes("context_length") && typeof v === "number" && v > 0) {
                    return { nCtx: v, source: "ollama" };
                }
            }
        }
    }
    catch {
        /* continue */
    }
    try {
        const models = await fetchImpl(`${base}/v1/models`);
        if (models.ok) {
            const j = (await models.json());
            const len = j.data?.[0]?.max_model_len;
            if (len && len > 0)
                return { nCtx: len, source: "vllm" };
        }
    }
    catch {
        /* continue */
    }
    return { nCtx: DEFAULT_N_CTX, source: "fallback" };
}
export function stripRedactedThinking(text) {
    const think = "think";
    return text
        .replace(/<think>[\s\S]*?<\/redacted_thinking>\s*/gi, "")
        .replace(new RegExp(`<${think}>[\\s\\S]*?<\\/${think}>\\s*`, "gi"), "")
        .trim();
}
export function createReasoningState() {
    return { inToolLoop: false };
}
export function applyReasoningContentPolicy(messages, state, newUserTurn) {
    if (newUserTurn)
        state.inToolLoop = false;
    const out = messages.map((m) => {
        const copy = { ...m };
        if (newUserTurn && m.role === "assistant")
            delete copy.reasoning_content;
        return copy;
    });
    return { messages: out, state };
}
export function sanitizeRequestBody(body, reasoner) {
    const out = { ...body };
    if (reasoner) {
        delete out.temperature;
        delete out.top_p;
    }
    return out;
}
export function l2Normalize(vec) {
    let sum = 0;
    for (const v of vec)
        sum += v * v;
    const norm = Math.sqrt(sum) || 1;
    return vec.map((v) => v / norm);
}
export function mrlSlice(vec, dimensions) {
    return l2Normalize(vec.slice(0, dimensions));
}
export function floatArrayToBase64(vec) {
    const buf = Buffer.alloc(vec.length * 4);
    for (let i = 0; i < vec.length; i++)
        buf.writeFloatLE(vec[i], i * 4);
    return buf.toString("base64");
}
export function base64ToFloatArray(b64) {
    const buf = Buffer.from(b64, "base64");
    const out = [];
    for (let i = 0; i < buf.length; i += 4)
        out.push(buf.readFloatLE(i));
    return out;
}
export function chunkArray(arr, size) {
    const out = [];
    for (let i = 0; i < arr.length; i += size)
        out.push(arr.slice(i, i + size));
    return out;
}
export async function normalizeEmbedBatch(inputs, options) {
    const nonEmpty = inputs.map((t, i) => ({ t, i })).filter((x) => x.t.trim().length > 0);
    const batches = chunkArray(nonEmpty, options.maxBatch);
    const vectors = new Map();
    for (const batch of batches) {
        const texts = batch.map((b) => b.t);
        const got = await options.embed(texts, options.dimensions);
        for (let j = 0; j < batch.length; j++) {
            let vec = got[j] ?? [];
            if (options.dimensions && vec.length >= options.dimensions) {
                vec = mrlSlice(vec, options.dimensions);
            }
            vectors.set(batch[j].i, vec);
        }
    }
    const dim = options.dimensions ?? vectors.values().next().value?.length ?? 0;
    return inputs.map((_, i) => vectors.get(i) ?? new Array(dim).fill(0));
}
function repairJson(raw) {
    let s = raw.trim();
    s = s.replace(/,\s*([}\]])/g, "$1");
    s = s.replace(/'/g, '"');
    const open = (s.match(/\{/g) ?? []).length;
    const close = (s.match(/\}/g) ?? []).length;
    if (open > close)
        s += "}".repeat(open - close);
    return s;
}
export function parseDirtyToolCall(content) {
    const text = stripRedactedThinking(content);
    const hermes = text.match(/<tool_call>\s*([\s\S]*?)\s*<\/tool_call>/i);
    if (hermes) {
        try {
            const obj = JSON.parse(repairJson(hermes[1]));
            if (obj?.name) {
                return { name: obj.name, arguments: obj.arguments ?? {} };
            }
        }
        catch {
            /* continue */
        }
    }
    const kimi = text.match(/functions\.([^:<\|]+):\d+<\|(?:redacted_)?tool_call_argument_begin\|>([\s\S]*?)<\|(?:redacted_)?tool_call_end(?:_kimi)?\|>/i);
    if (kimi) {
        try {
            return { name: kimi[1].trim(), arguments: JSON.parse(repairJson(kimi[2])) };
        }
        catch {
            return { name: kimi[1].trim(), arguments: {} };
        }
    }
    const glm = text.match(/<\|(?:redacted_)?tool_call_begin(?:_kimi)?\|>([^<\|]+)<\|tool_call_sep\|>([\s\S]*?)<\|(?:redacted_)?tool_call_end(?:_kimi)?\|>/i);
    if (glm) {
        try {
            return { name: glm[1].trim(), arguments: JSON.parse(repairJson(glm[2])) };
        }
        catch {
            return { name: glm[1].trim(), arguments: {} };
        }
    }
    const qwen = text.match(/✿FUNCTION✿:\s*([^\n]+)\s*✿ARGS✿:\s*([\s\S]*?)(?:✿RESULT✿|$)/i);
    if (qwen) {
        try {
            return { name: qwen[1].trim(), arguments: JSON.parse(repairJson(qwen[2])) };
        }
        catch {
            return { name: qwen[1].trim(), arguments: {} };
        }
    }
    const iq = text.match(/\{\s*['"]?cmd['"]?\s*:\s*['"]([^'"]+)['"]/);
    if (iq)
        return { name: "run_shell", arguments: { cmd: iq[1] } };
    return null;
}
export class StreamToolJsonAbort {
    depth = 0;
    started = false;
    feed(chunk) {
        for (const c of chunk) {
            if (c === "{") {
                this.depth++;
                this.started = true;
            }
            else if (c === "}") {
                this.depth--;
                if (this.started && this.depth === 0)
                    return true;
            }
        }
        return false;
    }
}
export function resolveOpenAiBase(model) {
    if (!model || model.startsWith("ollama/")) {
        const name = model?.replace(/^ollama\//, "") ?? "llama3.2";
        return { baseUrl: "http://127.0.0.1:11434/v1", model: name };
    }
    if (model.startsWith("http")) {
        const u = new URL(model);
        return { baseUrl: u.origin + u.pathname.replace(/\/$/, ""), model: "local" };
    }
    return { baseUrl: "http://127.0.0.1:1234/v1", model };
}
export async function summarizeExecReport(findings, model, fetchImpl = fetch) {
    const outline = findings.map((f) => ({ kind: f.kind, region: f.region, id: f.id }));
    const { baseUrl, model: modelId } = resolveOpenAiBase(model);
    const body = sanitizeRequestBody({
        model: modelId,
        messages: [
            {
                role: "user",
                content: `Summarize FinOps remediation categories (no dollar amounts, no account IDs): ${JSON.stringify(outline)}`,
            },
        ],
    }, modelId.includes("reasoner") || modelId.includes("r1"));
    const res = await fetchImpl(`${baseUrl}/chat/completions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
    });
    const j = (await res.json());
    const raw = j.choices?.[0]?.message?.content ?? "No summary returned.";
    return redactSecrets(stripRedactedThinking(raw));
}
export function defaultTools() {
    return [
        {
            name: "scan_aws_waste",
            description: "Scan AWS account for hidden cost bleed (read-only).",
            inputSchema: {
                type: "object",
                properties: {
                    regions: { type: "array", items: { type: "string" } },
                },
                additionalProperties: false,
            },
            annotations: { readOnlyHint: true },
            handler: async (args, ctx) => {
                if (!scanClient)
                    throw new Error("No AWS scan client configured");
                const regions = args.regions ?? ["us-east-1"];
                const all = await scanAwsWaste(scanClient, regions);
                lastFindings = all;
                const shown = truncateFindingsForMcp(all, ctx.nCtx);
                return {
                    findings: shown,
                    totalFindings: all.length,
                    totalMonthlyUsd: totalMonthlyUsd(all),
                    table: formatFindingsTable(shown, {
                        totalCount: all.length,
                        totalMonthlyUsd: totalMonthlyUsd(all),
                    }),
                };
            },
        },
        {
            name: "generate_finops_patch",
            description: "Emit Terraform or CLI patch for selected findings.",
            inputSchema: {
                type: "object",
                properties: {
                    findingIds: { type: "array", items: { type: "string" } },
                    format: { type: "string", enum: ["terraform", "cli"] },
                    writePath: { type: "string" },
                },
                required: ["format"],
                additionalProperties: false,
            },
            annotations: { destructiveHint: true },
            mutates: true,
            handler: async (args, ctx) => {
                const format = args.format ?? "terraform";
                const code = generateFinopsPatch(lastFindings, format, args.findingIds);
                const writePath = args.writePath;
                if (writePath && ctx.allowWrite && !ctx.dryRun) {
                    writeFileSync(writePath, code, "utf8");
                    return { written: writePath, bytes: code.length };
                }
                return { code };
            },
        },
        {
            name: "summarize_exec_report",
            description: "Local LLM executive summary for FinOps PR (no USD sent).",
            inputSchema: {
                type: "object",
                properties: {
                    findingIds: { type: "array", items: { type: "string" } },
                    model: { type: "string" },
                },
                additionalProperties: false,
            },
            annotations: { readOnlyHint: true },
            handler: async (args) => {
                const ids = args.findingIds;
                const subset = ids && ids.length > 0 ? lastFindings.filter((f) => ids.includes(f.id)) : lastFindings;
                const summary = await summarizeExecReport(subset, args.model);
                return { summary };
            },
        },
    ];
}
export function startMcpServer(metaOrOpts?, toolsArg?, options?) {
    hijackStdoutForMcp();
    let tools;
    let serverName = "aws-bleed";
    let version = "0.1.0";
    let toWsl = process.env.AWS_BLEED_PATH_WSL === "1";
    if (toolsArg !== undefined && metaOrOpts && "version" in metaOrOpts) {
        const meta = metaOrOpts;
        serverName = meta.name;
        version = meta.version;
        tools = toolsArg;
        if (options?.allowWrite)
            setGuards({ allowWrite: true });
    }
    else {
        const opts = (metaOrOpts ?? {});
        tools = opts.tools ?? defaultTools();
        serverName = opts.name ?? serverName;
        version = opts.version ?? version;
        toWsl = opts.pathToWsl ?? toWsl;
    }
    const handlers = new Map(tools.map((t) => [t.name, t]));
    let buffer = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
        buffer += chunk;
        let idx;
        while ((idx = buffer.indexOf("\n")) >= 0) {
            const line = buffer.slice(0, idx).trim();
            buffer = buffer.slice(idx + 1);
            if (!line)
                continue;
            let msg;
            try {
                msg = JSON.parse(line);
            }
            catch {
                continue;
            }
            dispatchMcpMessage(msg, { tools, handlers, toWsl, serverName, version });
        }
    });
}
export function dispatchMcpMessage(msg, ctx) {
    const { id, method, params } = msg;
    if (method === "initialize") {
        writeJsonRpcFrame({
            jsonrpc: "2.0",
            id,
            result: {
                protocolVersion: "2024-11-05",
                capabilities: { tools: {} },
                serverInfo: { name: ctx.serverName, version: ctx.version },
            },
        });
        return;
    }
    if (method === "notifications/initialized")
        return;
    if (method === "tools/list") {
        writeJsonRpcFrame({
            jsonrpc: "2.0",
            id,
            result: {
                tools: ctx.tools.map((t) => ({
                    name: t.name,
                    description: t.description,
                    inputSchema: t.inputSchema,
                    annotations: t.annotations,
                })),
            },
        });
        return;
    }
    if (method === "tools/call") {
        const name = params?.name;
        const args = normalizePathsDeep(params?.arguments ?? {}, ctx.toWsl);
        const loopErr = checkLoopBreaker(name, args);
        if (loopErr) {
            writeJsonRpcFrame({
                jsonrpc: "2.0",
                id,
                result: { content: [{ type: "text", text: loopErr }], isError: true },
            });
            return;
        }
        const tool = ctx.handlers.get(name);
        const guard = guardMutatingTool(tool);
        if (guard.blocked) {
            writeJsonRpcFrame({
                jsonrpc: "2.0",
                id,
                result: { content: [{ type: "text", text: guard.reason ?? "blocked" }], isError: true },
            });
            return;
        }
        void (async () => {
            try {
                const result = tool
                    ? await tool.handler(args, { dryRun, allowWrite, nCtx })
                    : { error: "unknown tool" };
                let text = redactSecrets(typeof result === "string" ? result : JSON.stringify(result, null, 2));
                text = headTailTruncate(text, Math.floor(nCtx * 4 * 0.3));
                text = normalizePathsDeep(text, !ctx.toWsl);
                writeJsonRpcFrame({
                    jsonrpc: "2.0",
                    id,
                    result: { content: [{ type: "text", text }] },
                });
            }
            catch (e) {
                writeJsonRpcFrame({
                    jsonrpc: "2.0",
                    id,
                    result: { content: [{ type: "text", text: redactSecrets(String(e)) }], isError: true },
                });
            }
        })();
        return;
    }
    if (id !== undefined) {
        writeJsonRpcFrame({
            jsonrpc: "2.0",
            id,
            error: { code: -32601, message: `Method not found: ${method}` },
        });
    }
}
