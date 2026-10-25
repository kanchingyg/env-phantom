import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

export type McpToolAnnotations = {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
};

export type McpToolDef = {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
    additionalProperties?: boolean;
  };
  annotations?: McpToolAnnotations;
  mutates?: boolean;
};

export type GuardOptions = { allowWrite?: boolean; dryRun?: boolean };

let allowWrite = false;
let dryRun = false;

export function setGuards(opts: GuardOptions): void {
  allowWrite = Boolean(opts.allowWrite);
  dryRun = Boolean(opts.dryRun);
}

export function canonicalizeJson(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalizeJson(v)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(obj[k])}`).join(",")}}`;
}

export function loopBreakerHash(toolName: string, args: unknown): string {
  return createHash("sha256")
    .update(`${toolName}:${canonicalizeJson(args)}`)
    .digest("hex");
}

const loopState = { lastHash: "", repeatCount: 0 };

export function resetLoopBreaker(): void {
  loopState.lastHash = "";
  loopState.repeatCount = 0;
}

export function checkLoopBreaker(toolName: string, args: unknown): string | null {
  const h = loopBreakerHash(toolName, args);
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

export function guardMutatingTool(tool: McpToolDef): { blocked: boolean; reason?: string } {
  if (!tool.mutates) return { blocked: false };
  if (dryRun) return { blocked: false };
  if (!allowWrite) {
    return {
      blocked: true,
      reason: "Read-only mode: pass --allow-write to enable mutating tools.",
    };
  }
  return { blocked: false };
}

const WIN_DRIVE_RE = /^([A-Za-z]):\\(.*)$/;
const WSL_RE = /^\/mnt\/([a-z])\/(.*)$/i;

export function windowsToWsl(p: string): string {
  const m = p.match(WIN_DRIVE_RE);
  if (!m) return p;
  return `/mnt/${m[1].toLowerCase()}/${m[2].replace(/\\/g, "/")}`;
}

export function wslToWindows(p: string): string {
  const m = p.match(WSL_RE);
  if (!m) return p;
  return `${m[1].toUpperCase()}:\\${m[2].replace(/\//g, "\\")}`;
}

export function normalizePathsDeep<T>(value: T, toWsl: boolean): T {
  if (typeof value === "string") {
    if (toWsl && WIN_DRIVE_RE.test(value)) return windowsToWsl(value) as T;
    if (!toWsl && WSL_RE.test(value)) return wslToWindows(value) as T;
    if (value.startsWith("file:///")) {
      const raw = value.slice(8).replace(/\//g, "\\");
      return (toWsl ? windowsToWsl(raw) : raw) as T;
    }
    return value;
  }
  if (Array.isArray(value)) return value.map((v) => normalizePathsDeep(v, toWsl)) as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = normalizePathsDeep(v, toWsl);
    return out as T;
  }
  return value;
}

let jsonRpcWrite: ((line: string) => void) | null = null;
let stdoutHijacked = false;

export function hijackStdoutForMcp(): void {
  if (stdoutHijacked) return;
  stdoutHijacked = true;
  const native = process.stdout.write.bind(process.stdout);
  jsonRpcWrite = (line: string) => {
    native(line);
  };
  process.stdout.write = ((chunk: unknown, ...args: unknown[]) => {
    const str = typeof chunk === "string" ? chunk : Buffer.from(chunk as Buffer).toString();
    if (jsonRpcWrite && str.trim().startsWith("{") && str.includes('"jsonrpc"')) {
      return native(chunk as string, ...(args as []));
    }
    process.stderr.write(str);
    return true;
  }) as typeof process.stdout.write;
}

export const jsonRpcFrameLog: string[] = [];

export function writeJsonRpcFrame(obj: object): void {
  const line = JSON.stringify(obj) + "\n";
  jsonRpcFrameLog.push(line);
  if (jsonRpcWrite) jsonRpcWrite(line);
  else process.stdout.write(line);
}

export type McpServerOptions = {
  name?: string;
  version?: string;
  tools?: McpToolDef[];
  handlers?: Record<string, (args: Record<string, unknown>) => Promise<unknown>>;
  pathToWsl?: boolean;
  nCtx?: number;
};

export function startMcpServer(opts: McpServerOptions = {}): void {
  hijackStdoutForMcp();
  const tools = opts.tools ?? [];
  const handlers = opts.handlers ?? {};
  const toWsl = opts.pathToWsl ?? process.env.ENV_PHANTOM_PATH_WSL === "1";
  const meta = { name: opts.name ?? "env-phantom", version: opts.version ?? "0.1.0" };

  const stdin = process.stdin;
  stdin.setEncoding("utf8");
  let buffer = "";
  stdin.on("data", (chunk: string) => {
    buffer += chunk;
    let idx: number;
    while ((idx = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line) as {
          jsonrpc?: string;
          id?: number | string;
          method?: string;
          params?: Record<string, unknown>;
        };
        dispatchMcpMessage(msg, { ...opts, tools, handlers, pathToWsl: toWsl, ...meta });
      } catch {
        /* skip */
      }
    }
  });
}

export function dispatchMcpMessage(
  msg: {
    jsonrpc?: string;
    id?: number | string;
    method?: string;
    params?: Record<string, unknown>;
  },
  opts: McpServerOptions & { name?: string; version?: string } = {},
): void {
  const tools = opts.tools ?? [];
  const handlers = opts.handlers ?? {};
  const toWsl = opts.pathToWsl ?? false;
  const nCtx = opts.nCtx ?? DEFAULT_N_CTX;
  const meta = { name: opts.name ?? "env-phantom", version: opts.version ?? "0.1.0" };
  handleMessage(msg, tools, handlers, toWsl, nCtx, meta);
}

function handleMessage(
  msg: {
    jsonrpc?: string;
    id?: number | string;
    method?: string;
    params?: Record<string, unknown>;
  },
  tools: McpToolDef[],
  handlers: Record<string, (args: Record<string, unknown>) => Promise<unknown>>,
  toWsl: boolean,
  nCtx: number,
  meta: { name: string; version: string },
): void {
  const { id, method, params } = msg;
  if (method === "initialize") {
    writeJsonRpcFrame({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: meta.name, version: meta.version },
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
        tools: tools.map((t) => ({
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
    const name = params?.name as string;
    const args = normalizePathsDeep(
      (params?.arguments as Record<string, unknown>) ?? {},
      toWsl,
    );
    const tool = tools.find((t) => t.name === name);
    const loopErr = checkLoopBreaker(name, args);
    if (loopErr) {
      writeJsonRpcFrame({
        jsonrpc: "2.0",
        id,
        result: { content: [{ type: "text", text: loopErr }], isError: true },
      });
      return;
    }
    if (tool) {
      const guard = guardMutatingTool(tool);
      if (guard.blocked) {
        writeJsonRpcFrame({
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text: guard.reason ?? "blocked" }],
            isError: true,
          },
        });
        return;
      }
    }
    if (dryRun) {
      writeJsonRpcFrame({
        jsonrpc: "2.0",
        id,
        result: {
          content: [
            {
              type: "text",
              text: `[dry-run] Would call ${name} with ${canonicalizeJson(args)}`,
            },
          ],
        },
      });
      return;
    }
    const handler = handlers[name];
    void (async () => {
      try {
        let result: unknown;
        if (handler) result = await handler(args);
        else result = { ok: true, tool: name, args };
        const text = typeof result === "string" ? result : JSON.stringify(result, null, 2);
        writeJsonRpcFrame({
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text: finalizeMcpToolText(text, { nCtx, toWsl }) }],
          },
        });
      } catch (e) {
        writeJsonRpcFrame({
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text: finalizeMcpToolText(String(e), { nCtx, toWsl }) }],
            isError: true,
          },
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

export const DEFAULT_N_CTX = 4096;
export const TRUNCATION_MARKER = "[...TRUNCATED BY ENV-PHANTOM CONTEXT GUARD...]";

const IM_END = "<|" + "redacted_im_end" + "|>";
export const MULTI_FAMILY_STOP_SEQUENCES = [
  "</tool_call>",
  "</tool_calls>",
  IM_END,
  "<|eot_id|>",
  "<|end|>",
  "<|observation|>",
  "<|tool_calls_section_end|>",
  "<｜tool▁calls▁end｜>",
  "\n✿RESULT✿",
  "\nOBS:",
  "\nObservation:",
  "\nUSER:",
  "\nHuman:",
];

export type NCtxSource = "llama.cpp" | "ollama" | "vllm" | "fallback";

export async function probeNCtx(
  baseUrl: string,
  fetchImpl: typeof fetch = fetch,
): Promise<{ nCtx: number; source: NCtxSource }> {
  const base = baseUrl.replace(/\/$/, "");
  try {
    const props = await fetchImpl(`${base}/props`);
    if (props.ok) {
      const j = (await props.json()) as {
        default_generation_settings?: { n_ctx?: number };
        n_ctx?: number;
      };
      const n = j.n_ctx ?? j.default_generation_settings?.n_ctx;
      if (typeof n === "number" && n > 0) return { nCtx: n, source: "llama.cpp" };
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
      const first = j.data?.[0];
      if (first?.max_model_len && first.max_model_len > 0) {
        return { nCtx: first.max_model_len, source: "vllm" };
      }
    }
  } catch {
    /* continue */
  }
  return { nCtx: DEFAULT_N_CTX, source: "fallback" };
}

export function headTailTruncate(text: string, maxChars: number): string {
  if (text.length <= maxChars) return text;
  const headLen = Math.floor(maxChars * 0.6);
  const tailLen = Math.floor(maxChars * 0.4) - TRUNCATION_MARKER.length;
  if (tailLen < 0) return text.slice(0, maxChars);
  return text.slice(0, headLen) + TRUNCATION_MARKER + text.slice(-tailLen);
}

export function toolOutputBudgetChars(nCtx: number, charsPerToken = 4): number {
  return Math.floor(nCtx * charsPerToken * 0.3);
}

export function truncateToolOutput(text: string, nCtx: number): string {
  return headTailTruncate(text, toolOutputBudgetChars(nCtx));
}

export function redactSecrets(text: string): string {
  return String(text)
    .replace(/(api[_-]?key|token|password|secret)\s*[=:]\s*[^\s]+/gi, "$1=[REDACTED]")
    .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, "Bearer [REDACTED]")
    .replace(/sk-[A-Za-z0-9]{20,}/g, "[REDACTED]");
}

export function finalizeMcpToolText(
  text: string,
  opts?: { nCtx?: number; toWsl?: boolean },
): string {
  const nCtx = opts?.nCtx ?? DEFAULT_N_CTX;
  const toWsl = opts?.toWsl ?? false;
  return normalizePathsDeep(
    redactSecrets(truncateToolOutput(String(text), nCtx)),
    !toWsl,
  );
}

export type ToolSignature = { name: string; summary: string };

export function buildRecencyAnchor(sigs: ToolSignature[]): string {
  const lines = sigs.map((s) => `- ${s.name}: ${s.summary}`);
  return [
    "[AVAILABLE TOOLS — ANCHORED FOR RECENCY]",
    ...lines,
    'To call a tool, output ONLY: <tool_call>{"name": "TOOL_NAME", "arguments": {...}}</tool_call>',
  ].join("\n");
}

export function anchorPromptTail(prompt: string, anchor: string): string {
  const marker = "\nASSISTANT:";
  const idx = prompt.lastIndexOf(marker);
  if (idx === -1) return `${prompt}\n\n${anchor}\n${marker}`;
  return `${prompt.slice(0, idx)}\n\n${anchor}\n${prompt.slice(idx)}`;
}

export class StreamToolJsonAbort {
  private depth = 0;
  private started = false;
  private acc = "";

  feed(chunk: string): boolean {
    this.acc += chunk;
    if (!this.started) {
      if (
        /<tool_call>/i.test(this.acc) ||
        /✿FUNCTION✿/i.test(this.acc) ||
        /<\|tool_call_argument_begin\|>/i.test(this.acc) ||
        /"name"\s*:\s*"/.test(this.acc)
      ) {
        this.started = true;
      }
    }
    this.depth = countBraceFrom(this.acc);
    return this.started && this.depth === 0 && /\{[\s\S]*\}/.test(this.acc);
  }

  reset(): void {
    this.depth = 0;
    this.started = false;
    this.acc = "";
  }
}

function countBraceFrom(text: string): number {
  let depth = 0;
  let inString = false;
  let escape = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (escape) {
      escape = false;
      continue;
    }
    if (inString) {
      if (c === "\\") escape = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
      continue;
    }
    if (c === "{") depth++;
    else if (c === "}") depth--;
  }
  return depth;
}

export type ToolSchema = {
  type?: string;
  properties?: Record<string, { type?: string }>;
};

export type ParsedToolCall = { name: string; arguments: Record<string, unknown> };

export function stripRedactedThinking(text: string): string {
  return text.replace(/<think>[\s\S]*?(?:<\/redacted_thinking>|$)/gi, "");
}

function repairJson(raw: string): string {
  let s = raw.trim();
  if (!s) return "{}";
  s = s.replace(/\/\/[^\n]*/g, "");
  s = s.replace(/,\s*([}\]])/g, "$1");
  s = s.replace(/'/g, '"');
  s = s.replace(/([{,]\s*)([a-zA-Z_][a-zA-Z0-9_]*)(\s*:)/g, '$1"$2"$3');
  const open = (s.match(/\{/g) ?? []).length;
  const close = (s.match(/\}/g) ?? []).length;
  if (open > close) s += "}".repeat(open - close);
  return s;
}

function tryParseObject(raw: string): Record<string, unknown> | null {
  for (const a of [raw, repairJson(raw)]) {
    try {
      const v = JSON.parse(a);
      if (v && typeof v === "object" && !Array.isArray(v)) return v as Record<string, unknown>;
    } catch {
      /* next */
    }
  }
  return null;
}

export function parseDirtyToolCall(content: string, schema?: ToolSchema): ParsedToolCall | null {
  const text = stripRedactedThinking(content);
  const hermes = text.match(/<tool_call>\s*([\s\S]*?)\s*<\/tool_call>/i);
  if (hermes) {
    const obj = tryParseObject(hermes[1]);
    if (obj?.name && typeof obj.name === "string") {
      const args =
        (obj.arguments as Record<string, unknown>) ??
        (obj.args as Record<string, unknown>) ??
        {};
      return { name: obj.name, arguments: args };
    }
  }
  const kimi = text.match(
    /functions\.([^:<\|]+):\d+<\|(?:redacted_)?tool_call_argument_begin\|>([\s\S]*?)<\|(?:redacted_)?tool_call_end/i,
  );
  if (kimi) {
    const obj = tryParseObject(kimi[2]);
    return { name: kimi[1].trim(), arguments: obj ?? {} };
  }
  const glm = text.match(
    /<\|(?:redacted_)?tool_call_begin[^|]*\|>([^<\|]+)<\|tool_call_sep\|>([\s\S]*?)<\|/i,
  );
  if (glm) {
    const obj = tryParseObject(glm[2]);
    return { name: glm[1].trim(), arguments: obj ?? {} };
  }
  const qwenFn = text.match(/✿FUNCTION✿:\s*([^\n]+)\s*✿ARGS✿:\s*([\s\S]*?)(?:✿RESULT✿|$)/i);
  if (qwenFn) {
    const obj = tryParseObject(qwenFn[2]);
    return { name: qwenFn[1].trim(), arguments: obj ?? {} };
  }
  const iqBroken = text.match(/\{\s*['"]?cmd['"]?\s*:\s*['"]([^'"]+)['"]/);
  if (iqBroken) return { name: "run_shell", arguments: { cmd: iqBroken[1] } };
  return null;
}

export type ChatMessage = {
  role: string;
  content?: string | null;
  tool_calls?: unknown[];
  reasoning_content?: string;
};

export type ProviderId =
  | "deepseek"
  | "dashscope"
  | "moonshot"
  | "zhipu"
  | "minimax"
  | "siliconflow"
  | "generic";

export function detectProvider(baseUrl: string): ProviderId {
  const u = baseUrl.toLowerCase();
  if (u.includes("deepseek")) return "deepseek";
  if (u.includes("dashscope")) return "dashscope";
  if (u.includes("moonshot")) return "moonshot";
  if (u.includes("bigmodel") || u.includes("zhipu")) return "zhipu";
  if (u.includes("minimax")) return "minimax";
  if (u.includes("siliconflow")) return "siliconflow";
  return "generic";
}

export function isReasoningModel(model: string): boolean {
  return /deepseek-reasoner|qwq|glm-z1|kimi-k2-thinking|thinking/i.test(model);
}

export function sanitizeRequestBody(
  body: Record<string, unknown>,
  model: string,
): Record<string, unknown> {
  const out = { ...body };
  if (isReasoningModel(model)) {
    for (const key of ["temperature", "top_p", "presence_penalty", "frequency_penalty"]) {
      delete out[key];
    }
  }
  return out;
}

export function normalizeToolChoice(toolChoice: unknown, provider: ProviderId): unknown {
  if (toolChoice === "required" || toolChoice === "any") {
    if (
      provider === "dashscope" ||
      provider === "moonshot" ||
      provider === "zhipu" ||
      provider === "minimax" ||
      provider === "siliconflow"
    ) {
      return "auto";
    }
  }
  return toolChoice;
}

export type ReasoningState = { inToolLoop: boolean; lastUserTurnIndex: number };

export function createReasoningState(): ReasoningState {
  return { inToolLoop: false, lastUserTurnIndex: -1 };
}

export function applyReasoningContentPolicy(
  messages: ChatMessage[],
  state: ReasoningState,
): { messages: ChatMessage[]; state: ReasoningState } {
  let lastUser = -1;
  for (let i = 0; i < messages.length; i++) {
    if (messages[i].role === "user") lastUser = i;
  }
  const newUserTurn = lastUser > state.lastUserTurnIndex;
  if (newUserTurn) state = { ...state, lastUserTurnIndex: lastUser, inToolLoop: false };
  const hasPendingTools = messages.some(
    (m) => m.role === "assistant" && m.tool_calls && m.tool_calls.length > 0,
  );
  if (hasPendingTools) state = { ...state, inToolLoop: true };
  const cleaned = messages.map((m, idx) => {
    const copy = { ...m };
    if (copy.content && typeof copy.content === "string") {
      copy.content = stripRedactedThinking(copy.content);
    }
    if (newUserTurn && copy.role === "assistant" && idx < lastUser) {
      delete copy.reasoning_content;
    }
    if (!state.inToolLoop && copy.role === "assistant") delete copy.reasoning_content;
    return copy;
  });
  return { messages: cleaned, state };
}

export const EMBED_LOCK = ".env-phantom-embed-lock.json";

export type EmbedLock = { provider: string; model: string; dimension: number };

export function readEmbedLock(repoRoot: string): EmbedLock | null {
  const p = join(repoRoot, EMBED_LOCK);
  if (!existsSync(p)) return null;
  return JSON.parse(readFileSync(p, "utf8")) as EmbedLock;
}

export function writeEmbedLock(repoRoot: string, lock: EmbedLock): void {
  writeFileSync(join(repoRoot, EMBED_LOCK), JSON.stringify(lock, null, 2));
}

export function assertDimensionFingerprint(lock: EmbedLock | null, dim: number): void {
  if (!lock) return;
  if (lock.dimension !== dim) {
    throw new Error(`Dimension fingerprint mismatch: lock expects ${lock.dimension}, got ${dim}`);
  }
}

export function l2Normalize(vec: number[]): number[] {
  let sum = 0;
  for (const v of vec) sum += v * v;
  const norm = Math.sqrt(sum) || 1;
  return vec.map((v) => v / norm);
}

export function mrlSlice(vec: number[], dimensions: number): number[] {
  return l2Normalize(vec.slice(0, dimensions));
}

export function floatArrayToBase64(vec: number[]): string {
  const buf = Buffer.alloc(vec.length * 4);
  for (let i = 0; i < vec.length; i++) buf.writeFloatLE(vec[i], i * 4);
  return buf.toString("base64");
}

export function base64ToFloatArray(b64: string): number[] {
  const buf = Buffer.from(b64, "base64");
  const out: number[] = [];
  for (let i = 0; i < buf.length; i += 4) out.push(buf.readFloatLE(i));
  return out;
}

export type EmbedUpstream = {
  name: string;
  maxBatch: number;
  embed: (input: string[], model: string, dimensions?: number) => Promise<number[][]>;
};

export function chunkArray<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

export async function normalizeEmbedBatch(
  inputs: string[],
  options: {
    dimensions?: number;
    upstream: EmbedUpstream;
    model: string;
    lock?: EmbedLock | null;
  },
): Promise<{ embeddings: number[][]; indices: number[] }> {
  const dimensions = options.dimensions;
  const indexed = inputs.map((text, i) => ({ text, i }));
  const nonEmpty = indexed.filter((x) => x.text.trim().length > 0);
  const batches = chunkArray(nonEmpty, options.upstream.maxBatch);
  const vectors = new Map<number, number[]>();

  for (const batch of batches) {
    const texts = batch.map((b) => b.text);
    const got = await options.upstream.embed(texts, options.model, dimensions);
    for (let j = 0; j < batch.length; j++) {
      let vec = got[j] ?? [];
      if (dimensions && vec.length > dimensions) vec = mrlSlice(vec, dimensions);
      else if (dimensions && vec.length === dimensions) vec = l2Normalize(vec);
      if (dimensions) assertDimensionFingerprint(options.lock ?? null, vec.length);
      vectors.set(batch[j].i, vec);
    }
  }

  const dim = dimensions ?? (vectors.values().next().value?.length ?? 0);
  const embeddings: number[][] = [];
  const indices: number[] = [];
  for (let i = 0; i < inputs.length; i++) {
    indices.push(i);
    embeddings.push(vectors.get(i) ?? new Array(dim).fill(0));
  }
  return { embeddings, indices };
}

export type EmbedServerOptions = {
  port: number;
  repoRoot: string;
  upstream: EmbedUpstream;
  defaultModel: string;
};

function readHttpBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c as Buffer));
    req.on("end", () => resolve(Buffer.concat(chunks).toString()));
    req.on("error", reject);
  });
}

export function createEmbedRequestHandler(opts: EmbedServerOptions) {
  return async (req: IncomingMessage, res: ServerResponse) => {
    if (req.method !== "POST" || !req.url?.startsWith("/v1/embeddings")) {
      res.writeHead(404);
      res.end();
      return;
    }
    let parsed: {
      input?: string | string[];
      model?: string;
      dimensions?: number;
      encoding_format?: string;
    };
    try {
      parsed = JSON.parse(await readHttpBody(req));
    } catch {
      res.writeHead(400);
      res.end("Invalid JSON");
      return;
    }
    const input = Array.isArray(parsed.input)
      ? parsed.input
      : parsed.input
        ? [parsed.input]
        : [];
    const lock = readEmbedLock(opts.repoRoot);
    try {
      const { embeddings } = await normalizeEmbedBatch(input, {
        dimensions: parsed.dimensions,
        upstream: opts.upstream,
        model: parsed.model ?? opts.defaultModel,
        lock,
      });
      if (parsed.dimensions && !lock) {
        writeEmbedLock(opts.repoRoot, {
          provider: opts.upstream.name,
          model: parsed.model ?? opts.defaultModel,
          dimension: parsed.dimensions,
        });
      }
      const data = embeddings.map((embedding, index) => {
        if (parsed.encoding_format === "base64") {
          return { object: "embedding", index, embedding: floatArrayToBase64(embedding) };
        }
        return { object: "embedding", index, embedding };
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ object: "list", data, model: parsed.model, usage: {} }));
    } catch (e) {
      res.writeHead(400);
      res.end(String(e));
    }
  };
}

export function startEmbedServer(opts: EmbedServerOptions): ReturnType<typeof createServer> {
  const server = createServer(createEmbedRequestHandler(opts));
  server.listen(opts.port, "127.0.0.1");
  return server;
}
