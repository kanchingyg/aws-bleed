#!/usr/bin/env node
/**
 * MCP stdio server, context window guards, tool-call parser, and FinOps report bridge for `aws-bleed`.
 *
 * @example
 * ```ts
 * import { startMcpServer, defaultTools } from "@kanchingyg/aws-bleed/bridge";
 *
 * startMcpServer({ name: "aws-bleed", version: "0.1.1", tools: defaultTools() });
 * ```
 *
 * @module
 */
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import {
  formatFindingsTable,
  scanAwsWaste,
  truncateFindingsForMcp,
  totalMonthlyUsd,
  type AwsScanClient,
  type BleedFinding,
} from "./scanners.js";
import { generateFinopsPatch, type FinopsPatchFormat } from "./terraform-patch.js";

export type { AwsScanClient, BleedFinding, FinopsPatchFormat };
export type { BleedFindingKind, NatGatewayItem, VpcEndpointItem, VolumeItem, AddressItem, SnapshotItem, LogGroupItem, FormatFindingsOptions } from "./scanners.js";

/** Default LLM context window budget in tokens when probing falls back. */
export const DEFAULT_N_CTX = 4096;
const TRUNC_MARKER = "[…truncated by aws-bleed…]";

/** Runtime safety guard configuration for mutating MCP tools. */
export interface GuardOptions {
  /** Whether disk-writing tools are allowed to execute. */
  allowWrite?: boolean;
  /** Whether mutating tools should simulate execution without writing. */
  dryRun?: boolean;
}

/** Result of evaluating a mutating tool against active safety guards. */
export interface GuardCheckResult {
  /** True when execution must be blocked. */
  blocked: boolean;
  /** Human-readable explanation when blocked. */
  reason?: string;
}

/** Compact tool signature used to construct recency anchors. */
export interface ToolSignatureSummary {
  /** Tool identifier. */
  name: string;
  /** Short parameter or behavior summary. */
  summary: string;
}

/** Result of probing a local LLM server for its context window size. */
export interface NCtxProbeResult {
  /** Detected or fallback context length in tokens. */
  nCtx: number;
  /** Server family that reported the context window (`llama.cpp`, `ollama`, `vllm`, or `fallback`). */
  source: string;
}

/** Multi-turn reasoning loop state tracker. */
export interface ReasoningState {
  /** Whether the conversation is currently inside an active tool-call loop. */
  inToolLoop: boolean;
}

/** Chat message structure used by `applyReasoningContentPolicy`. */
export interface ChatMessage {
  /** Message author role (`user`, `assistant`, `system`, `tool`). */
  role: string;
  /** Text content of the message. */
  content?: string;
  /** Optional reasoning trace field used by DeepSeek/Qwen reasoning models. */
  reasoning_content?: string;
  /** Additional provider-specific properties. */
  [key: string]: unknown;
}

/** Options for batch embedding normalization and MRL dimension slicing. */
export interface NormalizeEmbedBatchOptions {
  /** Maximum number of strings per upstream request batch. */
  maxBatch: number;
  /** Optional target Matryoshka dimension to slice and L2-normalize to. */
  dimensions?: number;
  /** Upstream batch embedding function. */
  embed: (texts: string[], dimensions?: number) => Promise<number[][]>;
}

/** Parsed tool call extracted from raw or non-standard model output. */
export interface ParsedDirtyToolCall {
  /** Invoked tool name. */
  name: string;
  /** Parsed tool arguments object. */
  arguments: Record<string, unknown>;
}

/** Runtime execution context passed to MCP tool handlers. */
export interface McpToolExecutionContext {
  /** Whether dry-run mode is active. */
  dryRun: boolean;
  /** Whether disk writes are permitted. */
  allowWrite: boolean;
  /** Active context window size in tokens. */
  nCtx: number;
}

/** MCP tool definition registered with the `aws-bleed` stdio server. */
export interface AwsBleedMcpTool {
  /** Tool name exposed over MCP `tools/list`. */
  name: string;
  /** Human-readable tool description. */
  description: string;
  /** JSON Schema describing tool arguments. */
  inputSchema: Record<string, unknown>;
  /** MCP tool annotations (`readOnlyHint`, `destructiveHint`). */
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
  };
  /** True when the tool writes files or mutates external state. */
  mutates?: boolean;
  /** Async handler invoked on `tools/call`. */
  handler: (args: Record<string, unknown>, ctx: McpToolExecutionContext) => Promise<unknown>;
}

/** Options for starting the `aws-bleed` MCP stdio server. */
export interface StartMcpServerOptions {
  /** Server name reported during MCP initialization. */
  name?: string;
  /** Server version string reported during MCP initialization. */
  version?: string;
  /** Tool list to expose (defaults to `defaultTools()`). */
  tools?: AwsBleedMcpTool[];
  /** Whether incoming file paths should be converted to WSL `/mnt/<drive>` format. */
  pathToWsl?: boolean;
  /** Whether disk writes are enabled. */
  allowWrite?: boolean;
}

/** JSON-RPC 2.0 request frame received over stdio. */
export interface JsonRpcMessage {
  /** JSON-RPC request identifier. */
  id?: string | number | null;
  /** Method name (`initialize`, `tools/list`, `tools/call`, etc.). */
  method?: string;
  /** Method parameters object. */
  params?: {
    name?: string;
    arguments?: Record<string, unknown>;
    [key: string]: unknown;
  };
}

/** Dispatch context holding registered tools and server metadata for MCP message routing. */
export interface McpDispatchContext {
  /** Registered tool definitions. */
  tools: AwsBleedMcpTool[];
  /** Lookup map from tool name to tool definition. */
  handlers: Map<string, AwsBleedMcpTool>;
  /** Whether to normalize paths to WSL format. */
  toWsl: boolean;
  /** Server name reported in `initialize`. */
  serverName: string;
  /** Server version reported in `initialize`. */
  version: string;
}

let allowWrite = false;
let dryRun = false;
let nCtx = DEFAULT_N_CTX;
let scanClient: AwsScanClient | null = null;
let lastFindings: BleedFinding[] = [];

/** Registers the active read-only AWS inventory client used by MCP tools. */
export function setScanClient(client: AwsScanClient | null): void {
  scanClient = client;
}

/** Returns the findings cached from the most recent `scan_aws_waste` run. */
export function getLastFindings(): BleedFinding[] {
  return lastFindings;
}

/** Configures write-protection and dry-run guards for MCP tool execution. */
export function setGuards(opts: GuardOptions): void {
  allowWrite = Boolean(opts.allowWrite);
  dryRun = Boolean(opts.dryRun);
}

/** Sets the active token context budget used for MCP output truncation. */
export function setNCtx(value: number): void {
  nCtx = value > 0 ? value : DEFAULT_N_CTX;
}

/** Serializes any JSON value with deterministically sorted object keys for hashing. */
export function canonicalizeJson(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => canonicalizeJson(v)).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`).join(",")}}`;
}

const loopState = { lastHash: "", repeatCount: 0 };

/** Resets the consecutive identical tool-call loop breaker state. */
export function resetLoopBreaker(): void {
  loopState.lastHash = "";
  loopState.repeatCount = 0;
}

/** Tracks consecutive identical tool calls and returns an error string on the third repeat. */
export function checkLoopBreaker(toolName: string, args: unknown): string | null {
  const h = createHash("sha256")
    .update(`${toolName}:${canonicalizeJson(args)}`)
    .digest("hex");
  if (h === loopState.lastHash) loopState.repeatCount++;
  else {
    loopState.lastHash = h;
    loopState.repeatCount = 1;
  }
  if (loopState.repeatCount >= 3) {
    return "LOOP_BREAKER: Identical tool call repeated 2 times consecutively. Stop calling tools and return your final synthesis.";
  }
  return null;
}

/** Checks whether a tool is allowed to execute under the current `allowWrite` and `dryRun` guards. */
export function guardMutatingTool(tool: AwsBleedMcpTool | undefined): GuardCheckResult {
  if (!(tool?.mutates || tool?.annotations?.destructiveHint)) return { blocked: false };
  if (dryRun) return { blocked: false };
  if (!allowWrite) {
    return { blocked: true, reason: "Read-only mode: pass --allow-write to enable mutating tools." };
  }
  return { blocked: false };
}

const WIN_DRIVE_RE = /^([A-Za-z]):\\(.*)$/;
const WSL_RE = /^\/mnt\/([a-z])\/(.*)$/i;

/** Converts a Windows drive path (`C:\foo\bar`) to a WSL mount path (`/mnt/c/foo/bar`). */
export function windowsToWsl(p: string): string {
  const m = p.match(WIN_DRIVE_RE);
  if (!m) return p;
  return `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, "/")}`;
}

/** Converts a WSL mount path (`/mnt/c/foo/bar`) to a Windows drive path (`C:\foo\bar`). */
export function wslToWindows(p: string): string {
  const m = p.match(WSL_RE);
  if (!m) return p;
  return `${m[1].toUpperCase()}:\\${m[2].replace(/\//g, "\\")}`;
}

/** Recursively normalizes string paths inside an arbitrary value between Windows and WSL formats. */
export function normalizePathsDeep<T>(value: T, toWsl: boolean): T {
  if (typeof value === "string") {
    if (toWsl && WIN_DRIVE_RE.test(value)) return windowsToWsl(value) as unknown as T;
    if (!toWsl && WSL_RE.test(value)) return wslToWindows(value) as unknown as T;
    return value;
  }
  if (Array.isArray(value)) return value.map((v) => normalizePathsDeep(v, toWsl)) as unknown as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = normalizePathsDeep(v, toWsl);
    }
    return out as unknown as T;
  }
  return value;
}

const SECRET_RE = /(?:sk-[a-zA-Z0-9]{20,}|(?:AKIA|ASIA)[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|Bearer\s+[a-zA-Z0-9._-]+)/g;

/** Scrubs AWS access keys, bearer tokens, OpenAI keys, and GitHub tokens from text output. */
export function redactSecrets(text: string): string {
  return text.replace(SECRET_RE, "[REDACTED]");
}

let stdoutHijacked = false;
let jsonRpcWrite: ((line: string) => boolean) | null = null;

/** Log of outbound JSON-RPC frames emitted by the server (used for inspection and tests). */
export const jsonRpcFrameLog: string[] = [];

/** Redirects non-JSON-RPC `process.stdout.write` calls to `stderr` to protect the MCP stdio stream. */
export function hijackStdoutForMcp(): void {
  if (stdoutHijacked) return;
  stdoutHijacked = true;
  const native = process.stdout.write.bind(process.stdout);
  jsonRpcWrite = (line: string): boolean => native(line);
  process.stdout.write = ((chunk: string | Uint8Array, ...args: unknown[]): boolean => {
    const str = typeof chunk === "string" ? chunk : Buffer.from(chunk).toString();
    if (str.trim().startsWith("{") && str.includes('"jsonrpc"')) {
      return (native as (...a: unknown[]) => boolean)(chunk, ...args);
    }
    process.stderr.write(str);
    return true;
  }) as typeof process.stdout.write;
}

/** Serializes and writes a single newline-delimited JSON-RPC 2.0 frame to stdout. */
export function writeJsonRpcFrame(obj: Record<string, unknown>): void {
  const line = JSON.stringify(obj) + "\n";
  jsonRpcFrameLog.push(line);
  if (jsonRpcWrite) jsonRpcWrite(line);
  else process.stdout.write(line);
}

/** Truncates text exceeding `maxChars` by keeping the first 60% and last 40% around a marker. */
export function headTailTruncate(text: string, maxChars: number): string {
  if (text.length <= maxChars) return text;
  const headLen = Math.floor(maxChars * 0.6);
  const tailLen = Math.max(0, Math.floor(maxChars * 0.4) - TRUNC_MARKER.length);
  return text.slice(0, headLen) + TRUNC_MARKER + text.slice(-tailLen);
}

/** Builds a compact tool-signature reminder block for prompt-tail recency anchoring. */
export function buildRecencyAnchor(tools: ToolSignatureSummary[]): string {
  const lines = tools.map((t) => `- ${t.name}(${t.summary})`);
  return `[AVAILABLE TOOLS - ANCHORED FOR RECENCY]\n${lines.join("\n")}\nTo call a tool, output ONLY: <tool_call>{"name":"TOOL","arguments":{}}</tool_call>`;
}

/** Injects a tool recency anchor immediately before the final `ASSISTANT:` turn marker. */
export function anchorPromptTail(prompt: string, anchor: string): string {
  const marker = "ASSISTANT:";
  const idx = prompt.lastIndexOf(marker);
  if (idx < 0) return `${prompt}\n\n${anchor}\n${marker}`;
  return prompt.slice(0, idx) + `\n${anchor}\n` + prompt.slice(idx);
}

/** Probes a local LLM endpoint (`llama.cpp`, `Ollama`, or `vLLM`) for its active context window size. */
export async function probeNCtx(baseUrl: string, fetchImpl: typeof fetch = fetch): Promise<NCtxProbeResult> {
  const base = baseUrl.replace(/\/$/, "");
  try {
    const props = await fetchImpl(`${base}/props`);
    if (props.ok) {
      const j = (await props.json()) as { n_ctx?: number };
      if (j.n_ctx && j.n_ctx > 0) return { nCtx: j.n_ctx, source: "llama.cpp" };
    }
  } catch {
    /* continue */
  }
  try {
    const show = await fetchImpl(`${base}/api/show`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "dummy" }),
    });
    if (show.ok) {
      const j = (await show.json()) as { model_info?: Record<string, unknown> };
      for (const [k, v] of Object.entries(j.model_info ?? {})) {
        if (k.includes("context_length") && typeof v === "number" && v > 0) {
          return { nCtx: v, source: "ollama" };
        }
      }
    }
  } catch {
    /* continue */
  }
  try {
    const models = await fetchImpl(`${base}/v1/models`);
    if (models.ok) {
      const j = (await models.json()) as { data?: Array<{ max_model_len?: number }> };
      const len = j.data?.[0]?.max_model_len;
      if (len && len > 0) return { nCtx: len, source: "vllm" };
    }
  } catch {
    /* continue */
  }
  return { nCtx: DEFAULT_N_CTX, source: "fallback" };
}

/** Strips `<think>...</think>` blocks from model responses. */
export function stripRedactedThinking(text: string): string {
  const think = "think";
  return text
    .replace(/<think>[\s\S]*?<\/redacted_thinking>\s*/gi, "")
    .replace(new RegExp(`<${think}>[\\s\\S]*?<\\/${think}>\\s*`, "gi"), "")
    .trim();
}

/** Initializes a fresh reasoning state tracker for multi-turn tool loops. */
export function createReasoningState(): ReasoningState {
  return { inToolLoop: false };
}

/** Strips `reasoning_content` from prior assistant turns when a new user turn begins. */
export function applyReasoningContentPolicy(
  messages: ChatMessage[],
  state: ReasoningState,
  newUserTurn: boolean,
): { messages: ChatMessage[]; state: ReasoningState } {
  if (newUserTurn) state.inToolLoop = false;
  const out = messages.map((m) => {
    const copy: ChatMessage = { ...m };
    if (newUserTurn && m.role === "assistant") delete copy.reasoning_content;
    return copy;
  });
  return { messages: out, state };
}

/** Removes sampling parameters rejected by reasoning models (`temperature`, `top_p`). */
export function sanitizeRequestBody(
  body: Record<string, unknown>,
  reasoner: boolean,
): Record<string, unknown> {
  const out = { ...body };
  if (reasoner) {
    delete out.temperature;
    delete out.top_p;
  }
  return out;
}

/** Normalizes a numeric vector to unit L2 length. */
export function l2Normalize(vec: number[]): number[] {
  let sum = 0;
  for (const v of vec) sum += v * v;
  const norm = Math.sqrt(sum) || 1;
  return vec.map((v) => v / norm);
}

/** Slices a Matryoshka embedding vector to `dimensions` and re-normalizes it to unit L2 length. */
export function mrlSlice(vec: number[], dimensions: number): number[] {
  return l2Normalize(vec.slice(0, dimensions));
}

/** Encodes a float32 array as a little-endian base64 string. */
export function floatArrayToBase64(vec: number[]): string {
  const buf = Buffer.alloc(vec.length * 4);
  for (let i = 0; i < vec.length; i++) buf.writeFloatLE(vec[i], i * 4);
  return buf.toString("base64");
}

/** Decodes a little-endian base64 float32 string back into a number array. */
export function base64ToFloatArray(b64: string): number[] {
  const buf = Buffer.from(b64, "base64");
  const out: number[] = [];
  for (let i = 0; i < buf.length; i += 4) out.push(buf.readFloatLE(i));
  return out;
}

/** Splits an array into contiguous chunks of at most `size` elements. */
export function chunkArray<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

/** Batches non-empty inputs for embedding, applies MRL slicing, and zero-fills blank entries. */
export async function normalizeEmbedBatch(
  inputs: string[],
  options: NormalizeEmbedBatchOptions,
): Promise<number[][]> {
  const nonEmpty = inputs.map((t, i) => ({ t, i })).filter((x) => x.t.trim().length > 0);
  const batches = chunkArray(nonEmpty, options.maxBatch);
  const vectors = new Map<number, number[]>();
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

function repairJson(raw: string): string {
  let s = raw.trim();
  s = s.replace(/,\s*([}\]])/g, "$1");
  s = s.replace(/'/g, '"');
  const open = (s.match(/\{/g) ?? []).length;
  const close = (s.match(/\}/g) ?? []).length;
  if (open > close) s += "}".repeat(open - close);
  return s;
}

/** Extracts a structured tool call from Hermes, Kimi, GLM, Qwen, or raw JSON model output. */
export function parseDirtyToolCall(content: string): ParsedDirtyToolCall | null {
  const text = stripRedactedThinking(content);
  const hermes = text.match(/<tool_call>\s*([\s\S]*?)\s*<\/tool_call>/i);
  if (hermes) {
    try {
      const obj = JSON.parse(repairJson(hermes[1])) as { name?: string; arguments?: Record<string, unknown> };
      if (obj?.name) {
        return { name: obj.name, arguments: obj.arguments ?? {} };
      }
    } catch {
      /* continue */
    }
  }
  const kimi = text.match(
    /functions\.([^:<|]+):\d+<\|(?:redacted_)?tool_call_argument_begin\|>([\s\S]*?)<\|(?:redacted_)?tool_call_end(?:_kimi)?\|>/i,
  );
  if (kimi) {
    try {
      return {
        name: kimi[1].trim(),
        arguments: JSON.parse(repairJson(kimi[2])) as Record<string, unknown>,
      };
    } catch {
      return { name: kimi[1].trim(), arguments: {} };
    }
  }
  const glm = text.match(
    /<\|(?:redacted_)?tool_call_begin(?:_kimi)?\|>([^<|]+)<\|tool_call_sep\|>([\s\S]*?)<\|(?:redacted_)?tool_call_end(?:_kimi)?\|>/i,
  );
  if (glm) {
    try {
      return {
        name: glm[1].trim(),
        arguments: JSON.parse(repairJson(glm[2])) as Record<string, unknown>,
      };
    } catch {
      return { name: glm[1].trim(), arguments: {} };
    }
  }
  const qwen = text.match(/✿FUNCTION✿:\s*([^\n]+)\s*✿ARGS✿:\s*([\s\S]*?)(?:✿RESULT✿|$)/i);
  if (qwen) {
    try {
      return {
        name: qwen[1].trim(),
        arguments: JSON.parse(repairJson(qwen[2])) as Record<string, unknown>,
      };
    } catch {
      return { name: qwen[1].trim(), arguments: {} };
    }
  }
  const iq = text.match(/\{\s*['"]?cmd['"]?\s*:\s*['"]([^'"]+)['"]/);
  if (iq) return { name: "run_shell", arguments: { cmd: iq[1] } };
  return null;
}

/** Streaming brace-depth tracker that signals when a complete JSON object has been emitted. */
export class StreamToolJsonAbort {
  /** Current nesting depth of `{` and `}` characters. */
  depth = 0;
  /** Whether an opening brace has been observed in the stream. */
  started = false;
  /** Feeds a streamed text chunk and returns true once the root JSON object closes. */
  feed(chunk: string): boolean {
    for (const c of chunk) {
      if (c === "{") {
        this.depth++;
        this.started = true;
      } else if (c === "}") {
        this.depth--;
        if (this.started && this.depth === 0) return true;
      }
    }
    return false;
  }
}

/** Resolves a model spec (`ollama/llama3.2`, HTTP URL, or model ID) into an OpenAI-compatible base URL and model name. */
export function resolveOpenAiBase(model?: string): { baseUrl: string; model: string } {
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

/** Generates a privacy-preserving executive FinOps summary via a local OpenAI-compatible model without sending dollar amounts. */
export async function summarizeExecReport(
  findings: BleedFinding[],
  model?: string,
  fetchImpl: typeof fetch = fetch,
): Promise<string> {
  const outline = findings.map((f) => ({ kind: f.kind, region: f.region, id: f.id }));
  const { baseUrl, model: modelId } = resolveOpenAiBase(model);
  const body = sanitizeRequestBody(
    {
      model: modelId,
      messages: [
        {
          role: "user",
          content: `Summarize FinOps remediation categories (no dollar amounts, no account IDs): ${JSON.stringify(outline)}`,
        },
      ],
    },
    modelId.includes("reasoner") || modelId.includes("r1"),
  );
  const res = await fetchImpl(`${baseUrl}/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const j = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
  const raw = j.choices?.[0]?.message?.content ?? "No summary returned.";
  return redactSecrets(stripRedactedThinking(raw));
}

/** Builds the default MCP tool definitions (`scan_aws_waste`, `generate_finops_patch`, `summarize_exec_report`). */
export function defaultTools(): AwsBleedMcpTool[] {
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
        if (!scanClient) throw new Error("No AWS scan client configured");
        const regions = (args.regions as string[] | undefined) ?? ["us-east-1"];
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
        const format = (args.format as FinopsPatchFormat | undefined) ?? "terraform";
        const findingIds = args.findingIds as string[] | undefined;
        const code = generateFinopsPatch(lastFindings, format, findingIds);
        const writePath = args.writePath as string | undefined;
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
        const ids = args.findingIds as string[] | undefined;
        const subset =
          ids && ids.length > 0 ? lastFindings.filter((f) => ids.includes(f.id)) : lastFindings;
        const summary = await summarizeExecReport(subset, args.model as string | undefined);
        return { summary };
      },
    },
  ];
}

/** Starts the `aws-bleed` JSON-RPC 2.0 MCP server over `process.stdin` and `process.stdout`. */
export function startMcpServer(
  metaOrOpts?: StartMcpServerOptions,
  toolsArg?: AwsBleedMcpTool[],
  options?: { allowWrite?: boolean },
): void {
  hijackStdoutForMcp();
  let tools: AwsBleedMcpTool[];
  let serverName = "aws-bleed";
  let version = "0.1.1";
  let toWsl = process.env.AWS_BLEED_PATH_WSL === "1";
  if (toolsArg !== undefined && metaOrOpts && "version" in metaOrOpts) {
    serverName = metaOrOpts.name ?? serverName;
    version = metaOrOpts.version ?? version;
    tools = toolsArg;
    if (options?.allowWrite) setGuards({ allowWrite: true });
  } else {
    const opts = metaOrOpts ?? {};
    tools = opts.tools ?? defaultTools();
    serverName = opts.name ?? serverName;
    version = opts.version ?? version;
    toWsl = opts.pathToWsl ?? toWsl;
  }
  const handlers = new Map(tools.map((t) => [t.name, t]));
  let buffer = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => {
    buffer += chunk;
    let idx: number;
    while ((idx = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (!line) continue;
      let msg: JsonRpcMessage;
      try {
        msg = JSON.parse(line) as JsonRpcMessage;
      } catch {
        continue;
      }
      dispatchMcpMessage(msg, { tools, handlers, toWsl, serverName, version });
    }
  });
}

/** Routes a single incoming JSON-RPC 2.0 MCP request (`initialize`, `tools/list`, `tools/call`) and writes the response frame. */
export function dispatchMcpMessage(msg: JsonRpcMessage, ctx: McpDispatchContext): void {
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
  if (method === "notifications/initialized") return;
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
    const name = params?.name ?? "";
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
        let text = redactSecrets(
          typeof result === "string" ? result : JSON.stringify(result, null, 2),
        );
        text = headTailTruncate(text, Math.floor(nCtx * 4 * 0.3));
        text = normalizePathsDeep(text, !ctx.toWsl);
        writeJsonRpcFrame({
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text }] },
        });
      } catch (e) {
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
