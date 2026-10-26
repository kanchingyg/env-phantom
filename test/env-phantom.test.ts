import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createServer } from "node:http";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  hijackStdoutForMcp,
  jsonRpcFrameLog,
  dispatchMcpMessage,
  setGuards,
  resetLoopBreaker,
  checkLoopBreaker,
  guardMutatingTool,
  windowsToWsl,
  wslToWindows,
  normalizeEmbedBatch,
  floatArrayToBase64,
  base64ToFloatArray,
  mrlSlice,
  assertDimensionFingerprint,
  readEmbedLock,
  writeEmbedLock,
  EMBED_LOCK,
  headTailTruncate,
  buildRecencyAnchor,
  anchorPromptTail,
  StreamToolJsonAbort,
  parseDirtyToolCall,
  applyReasoningContentPolicy,
  createReasoningState,
  sanitizeRequestBody,
  normalizeToolChoice,
  detectProvider,
} from "../src/bridge.js";
import {
  buildVaultFromEnv,
  phantomToken,
  encryptVaultPayload,
  decryptVaultPayload,
  saveVault,
  loadVault,
  VAULT_FILE,
} from "../src/vault.js";
import { phantomProcessEnv } from "../src/rewriter.js";
import { buildChildProcessEnv, isSafeParentEnvKey } from "../src/child-env.js";
import {
  createEdgeProxy,
  proxyRequest,
  proxyConnect,
  resetExfilLog,
  handlesConnectMethod,
} from "../src/proxy.js";

describe("edge proxy", () => {
  let allowedPort = 0;
  let receivedAuth = "";
  let allowedServer: ReturnType<typeof createServer>;

  beforeEach(async () => {
    resetExfilLog();
    receivedAuth = "";
    allowedServer = createServer((req, res) => {
      receivedAuth = req.headers.authorization ?? "";
      res.writeHead(200);
      res.end("ok");
    });
    await new Promise<void>((r) => allowedServer.listen(0, "127.0.0.1", r));
    const addr = allowedServer.address();
    allowedPort = typeof addr === "object" && addr ? addr.port : 0;
  });

  afterEach(() => {
    allowedServer.close();
  });

  it("keeps phantom in process.env and injects real secret only for allowed hosts", async () => {
    const secret = "sk_test_allowed_only";
    const vault = buildVaultFromEnv(
      { STRIPE_KEY: secret },
      { STRIPE_KEY: ["allowed.local"] },
    );
    const env = phantomProcessEnv(vault);
    expect(env.STRIPE_KEY).toMatch(/^phantom_/);
    expect(env.STRIPE_KEY).not.toBe(secret);

    const proxy = createEdgeProxy({
      vault,
      resolveUpstream: (host) => {
        if (host === "allowed.local") return { hostname: "127.0.0.1", port: allowedPort };
        return { hostname: host, port: 80 };
      },
    });
    await new Promise<void>((r) => proxy.listen(0, "127.0.0.1", r));
    const paddr = proxy.address();
    const proxyPort = typeof paddr === "object" && paddr ? paddr.port : 0;

    const ok = await proxyRequest(
      proxyPort,
      "allowed.local",
      "/",
      { authorization: env.STRIPE_KEY! },
    );
    expect(ok.status).toBe(200);
    expect(receivedAuth).toBe(secret);

    const blocked = await proxyRequest(proxyPort, "evil.local", "/", {
      authorization: env.STRIPE_KEY!,
    });
    expect(blocked.status).toBe(403);
    expect(blocked.body).toContain("403 Blocked by env-phantom");

    proxy.close();
  });

  it("handles CONNECT for allowlisted hosts", async () => {
    const vault = buildVaultFromEnv(
      { STRIPE_KEY: "sk_test" },
      { STRIPE_KEY: ["allowed.local"] },
    );
    const proxy = createEdgeProxy({
      vault,
      resolveUpstream: (host) => {
        if (host === "allowed.local") return { hostname: "127.0.0.1", port: allowedPort };
        return { hostname: host, port: 80 };
      },
    });
    await new Promise<void>((r) => proxy.listen(0, "127.0.0.1", r));
    const paddr = proxy.address();
    const proxyPort = typeof paddr === "object" && paddr ? paddr.port : 0;

    expect(handlesConnectMethod("CONNECT")).toBe(true);
    const tun = await proxyConnect(proxyPort, "allowed.local", allowedPort);
    expect(tun.statusLine).toContain("200");

    const blocked = await proxyConnect(proxyPort, "evil.local", 443);
    expect(blocked.statusLine).toContain("403");

    proxy.close();
  });
});

describe("vault encryption", () => {
  it("roundtrips AES-256-GCM and migrates plaintext on load", () => {
    const vault = buildVaultFromEnv({ API_KEY: "supersecret" });
    process.env.ENV_PHANTOM_VAULT_KEY = "test-vault-password";
    const enc = encryptVaultPayload(vault);
    const back = decryptVaultPayload(enc);
    expect(back.entries[0].secret).toBe("supersecret");
    expect(enc.ciphertext).not.toContain("supersecret");

    const dir = mkdtempSync(join(tmpdir(), "env-phantom-vault-"));
    writeFileSync(join(dir, VAULT_FILE), JSON.stringify(vault));
    const loaded = loadVault(dir);
    expect(loaded?.entries[0].phantom).toMatch(/^phantom_/);
    const onDisk = JSON.parse(readFileSync(join(dir, VAULT_FILE), "utf8"));
    expect(onDisk.version).toBe(2);
    expect(onDisk.ciphertext).toBeDefined();
    rmSync(dir, { recursive: true });
    delete process.env.ENV_PHANTOM_VAULT_KEY;
  });
});

describe("child env allowlist", () => {
  it("only copies allowlisted parent keys and keeps phantoms", () => {
    const vault = buildVaultFromEnv({ STRIPE_KEY: "sk_real" });
    const prev = process.env.STRAY_API_TOKEN;
    const prevDb = process.env.DATABASE_URL;
    const prevPath = process.env.PATH;
    process.env.STRAY_API_TOKEN = "leak-me";
    process.env.DATABASE_URL = "postgres://secret";
    if (!process.env.PATH) process.env.PATH = "/bin";
    const env = buildChildProcessEnv(vault);
    expect(env.STRIPE_KEY).toMatch(/^phantom_/);
    expect(env.STRAY_API_TOKEN).toBeUndefined();
    expect(env.DATABASE_URL).toBeUndefined();
    expect(env.PATH).toBe(process.env.PATH);
    expect(isSafeParentEnvKey("STRAY_API_TOKEN")).toBe(false);
    expect(isSafeParentEnvKey("DATABASE_URL")).toBe(false);
    if (prev === undefined) delete process.env.STRAY_API_TOKEN;
    else process.env.STRAY_API_TOKEN = prev;
    if (prevDb === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = prevDb;
    if (prevPath === undefined) delete process.env.PATH;
    else process.env.PATH = prevPath;
  });
});

describe("MCP JSON-RPC", () => {
  let stderrChunks: string[];

  beforeEach(() => {
    stderrChunks = [];
    jsonRpcFrameLog.length = 0;
    const nativeStderr = process.stderr.write.bind(process.stderr);
    hijackStdoutForMcp();
    process.stderr.write = ((chunk: unknown, ...args: unknown[]) => {
      stderrChunks.push(String(chunk));
      return nativeStderr(chunk as Buffer, ...(args as [BufferEncoding?, (err?: Error) => void?]));
    }) as typeof process.stderr.write;
  });

  it("stdio hijack keeps JSON-RPC clean", async () => {
    const tool = {
      name: "echo_path",
      description: "echo path",
      inputSchema: { type: "object", properties: {}, additionalProperties: true },
    };
    dispatchMcpMessage(
      { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
      { tools: [tool], handlers: {} },
    );
    dispatchMcpMessage(
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "echo_path", arguments: { path: "D:\\proj\\foo.ts" } },
      },
      {
        tools: [tool],
        pathToWsl: true,
        handlers: {
          echo_path: async (args) => {
            process.stdout.write("NOISE\n");
            return args;
          },
        },
      },
    );
    await new Promise((r) => setTimeout(r, 50));
    expect(stderrChunks.join("")).toContain("NOISE");
    const lastLine = jsonRpcFrameLog[jsonRpcFrameLog.length - 1].trim();
    const frame = JSON.parse(lastLine);
    expect(frame.result.content[0].text).toContain("/mnt/d/proj/foo.ts");
  });
});

describe("Blindaje 1", () => {
  beforeEach(() => {
    resetLoopBreaker();
    setGuards({ allowWrite: false, dryRun: false });
  });

  it("blocks mutating tools without allow-write", () => {
    const g = guardMutatingTool({
      name: "mask",
      description: "mask env",
      inputSchema: { type: "object", properties: {} },
      mutates: true,
    });
    expect(g.blocked).toBe(true);
  });

  it("loop breaker on third identical call", () => {
    expect(checkLoopBreaker("run_sandboxed", { cmd: "curl" })).toBeNull();
    expect(checkLoopBreaker("run_sandboxed", { cmd: "curl" })).toBeNull();
    expect(checkLoopBreaker("run_sandboxed", { cmd: "curl" })).toMatch(/LOOP_BREAKER/);
  });
});

describe("Blindaje 2", () => {
  it("head+tail truncation and recency anchor", () => {
    const long = "H".repeat(200) + "T".repeat(200);
    const out = headTailTruncate(long, 200);
    expect(out).toContain("TRUNCATED");
    const anchor = buildRecencyAnchor([{ name: "list_phantom_keys", summary: "List keys" }]);
    const anchored = anchorPromptTail("SYSTEM\nASSISTANT:", anchor);
    expect(anchored.indexOf(anchor)).toBeLessThan(anchored.lastIndexOf("ASSISTANT:"));
  });
});

describe("Blindaje 5", () => {
  it("reasoning_content policy", () => {
    let state = createReasoningState();
    const msgs = [
      { role: "user", content: "hi" },
      {
        role: "assistant",
        content: "ok",
        reasoning_content: "think",
        tool_calls: [{}],
      },
      { role: "tool", content: "{}" },
    ];
    const r1 = applyReasoningContentPolicy(msgs, state);
    expect(r1.messages[1].reasoning_content).toBe("think");
    state = r1.state;
    const msgs2 = [
      ...msgs,
      { role: "user", content: "next" },
      { role: "assistant", content: "done", reasoning_content: "old" },
    ];
    const r2 = applyReasoningContentPolicy(msgs2, state);
    expect(r2.messages[1].reasoning_content).toBeUndefined();
  });

  it("dirty-parser formats and stream abort", () => {
    const kimi =
      '<|tool_calls_section_begin|><|tool_call_begin|>functions.run:0<|tool_call_argument_begin|>{"target":"x"}<|tool_call_end|>';
    expect(parseDirtyToolCall(kimi)?.name).toBe("run");

    const glm =
      '<|tool_call_begin|>run_check<|tool_call_sep|>{"target":"a"}<|tool_call_end|>';
    expect(parseDirtyToolCall(glm)?.arguments.target).toBe("a");

    const qwen = "✿FUNCTION✿: run_check\n✿ARGS✿: {'target': 'z'}\n";
    expect(parseDirtyToolCall(qwen)?.name).toBe("run_check");

    const iq = "{'cmd': 'ls'}";
    expect(parseDirtyToolCall(iq)?.arguments).toEqual({ cmd: "ls" });

    const guard = new StreamToolJsonAbort();
    expect(guard.feed('<tool_call>{"name":"t","arguments":{')).toBe(false);
    expect(guard.feed("}}")).toBe(true);

    const body = sanitizeRequestBody(
      { temperature: 0.2, top_p: 0.9, model: "deepseek-reasoner" },
      "deepseek-reasoner",
    );
    expect(body.temperature).toBeUndefined();
    expect(normalizeToolChoice("required", detectProvider("https://dashscope.aliyuncs.com"))).toBe(
      "auto",
    );
  });
});

describe("Blindaje 3 embed", () => {
  it("batches, empty filter, base64, fingerprint", async () => {
    const calls: number[] = [];
    const upstream = {
      name: "dashscope",
      maxBatch: 10,
      embed: async (input: string[]) => {
        calls.push(input.length);
        return input.map(() => [1, 0, 0]);
      },
    };
    await normalizeEmbedBatch(Array.from({ length: 60 }, (_, i) => `t-${i}`), {
      upstream,
      model: "text-embedding-v3",
      dimensions: 3,
    });
    expect(calls.length).toBe(6);

    const upstream2 = {
      name: "test",
      maxBatch: 32,
      embed: async (input: string[]) => input.map(() => [0.5, 0.5]),
    };
    const { embeddings } = await normalizeEmbedBatch(["", "hello", "   "], {
      upstream: upstream2,
      model: "m",
      dimensions: 2,
    });
    expect(embeddings[0]).toEqual([0, 0]);

    const vec = [3, 4];
    expect(base64ToFloatArray(floatArrayToBase64(vec))[0]).toBeCloseTo(3);
    expect(Math.hypot(...mrlSlice([3, 4, 0], 2))).toBeCloseTo(1);

    expect(() => assertDimensionFingerprint({ provider: "x", model: "m", dimension: 1024 }, 768)).toThrow(
      /fingerprint/,
    );

    const dir = mkdtempSync(join(tmpdir(), "env-phantom-embed-"));
    writeEmbedLock(dir, { provider: "p", model: "m", dimension: 1024 });
    expect(readEmbedLock(dir)?.dimension).toBe(1024);
    expect(existsSync(join(dir, EMBED_LOCK))).toBe(true);
    rmSync(dir, { recursive: true });
  });
});

describe("paths", () => {
  it("windows and wsl", () => {
    expect(windowsToWsl("D:\\proj\\foo.ts")).toBe("/mnt/d/proj/foo.ts");
    expect(wslToWindows("/mnt/d/proj/foo.ts")).toBe("D:\\proj\\foo.ts");
  });

  it("phantom token stable", () => {
    const t = phantomToken("STRIPE_KEY", "sekret");
    expect(t.startsWith("phantom_")).toBe(true);
  });
});
