#!/usr/bin/env node
import { readFileSync, writeFileSync, existsSync, copyFileSync } from "node:fs";
import { join } from "node:path";
import { spawn } from "node:child_process";

import {
  setGuards,
  startMcpServer,
  truncateToolOutput,
  buildRecencyAnchor,
  anchorPromptTail,
  parseDirtyToolCall,
  type McpToolDef,
} from "./bridge.js";
import {
  buildVaultFromEnv,
  loadVault,
  saveVault,
  parseEnvFile,
  maskEnvLines,
  listPhantomKeysPublic,
} from "./vault.js";
import { buildChildProcessEnv } from "./child-env.js";
import {
  startEdgeProxy,
  getExfilLog,
  getExfilById,
  resetExfilLog,
} from "./proxy.js";
import { redactSecrets } from "./rewriter.js";
import { assertPathContained } from "./paths.js";
import { ensureLocalCa, CA_PEM_FILE } from "./mitm-ca.js";

const VERSION = "0.1.0";

function usage(): string {
  return `env-phantom v${VERSION}
  npx env-phantom mask <.env> [--allow-write] [--dry-run]
  npx env-phantom run -- <command...>
  npx env-phantom audit
  npx env-phantom --mcp [--allow-write] [--dry-run]`;
}

export async function cmdMask(argv: string[], cwd: string): Promise<number> {
  const allowWrite = argv.includes("--allow-write");
  const isDry = argv.includes("--dry-run");
  const file = argv.find((a) => !a.startsWith("--")) ?? ".env";
  const path = join(cwd, file);
  if (!existsSync(path)) {
    process.stderr.write(`Missing env file: ${file}\n`);
    return 2;
  }
  const raw = readFileSync(path, "utf8");
  const vars = parseEnvFile(raw);
  const vault = buildVaultFromEnv(vars);
  const masked = maskEnvLines(raw, vault);
  if (isDry) {
    process.stdout.write(masked + "\n");
    return 0;
  }
  if (!allowWrite) {
    process.stderr.write("Read-only: pass --allow-write to write masked .env and vault.\n");
    process.stdout.write(masked + "\n");
    return 0;
  }
  copyFileSync(path, `${path}.bak`);
  writeFileSync(path, masked);
  saveVault(cwd, vault);
  return 0;
}

function proxyExtraEnv(cwd: string, port: number): Record<string, string> {
  const extra: Record<string, string> = {
    HTTP_PROXY: `http://127.0.0.1:${port}`,
    HTTPS_PROXY: `http://127.0.0.1:${port}`,
  };
  const ca = ensureLocalCa(cwd);
  if (ca) {
    extra.NODE_EXTRA_CA_CERTS = join(cwd, CA_PEM_FILE);
  }
  return extra;
}

export async function cmdRun(argv: string[], cwd: string): Promise<number> {
  const dash = argv.indexOf("--");
  if (dash < 0 || dash === argv.length - 1) {
    process.stderr.write("Usage: env-phantom run -- <command>\n");
    return 2;
  }
  const cmd = argv.slice(dash + 1);
  const vault = loadVault(cwd);
  if (!vault) {
    process.stderr.write("No vault found. Run: env-phantom mask .env --allow-write\n");
    return 1;
  }
  resetExfilLog();
  const { server, port } = await startEdgeProxy({ vault, cwd });
  const env = buildChildProcessEnv(vault, proxyExtraEnv(cwd, port));

  return new Promise((resolve) => {
    const child = spawn(cmd[0], cmd.slice(1), {
      cwd,
      env,
      stdio: "inherit",
      shell: false,
    });
    child.on("exit", (code) => {
      server.close();
      resolve(code ?? 1);
    });
    child.on("error", () => {
      server.close();
      resolve(1);
    });
  });
}

export function cmdAudit(): number {
  const logs = getExfilLog();
  process.stdout.write(JSON.stringify(logs, null, 2) + "\n");
  return 0;
}

async function explainExfil(logId: string, model?: string): Promise<string> {
  const entry = getExfilById(logId);
  if (!entry) return `Unknown logId: ${logId}`;
  const vault = loadVault(process.cwd());
  const base = redactSecrets(
    `Blocked exfil attempt to ${entry.host}: ${entry.detail}`,
    vault ?? { version: 1, entries: [] },
  );
  const anchor = buildRecencyAnchor([
    { name: "explain_exfil_attempt", summary: "Summarize blocked outbound secret use" },
  ]);
  const prompt = anchorPromptTail(
    `SYSTEM: You audit proxy blocks.\nUSER: ${base}\nASSISTANT:`,
    anchor,
  );
  const modelId = model ?? "llama3.2";
  try {
    const res = await fetch("http://127.0.0.1:11434/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: modelId, prompt, stream: false }),
    });
    if (!res.ok) {
      return truncateToolOutput(
        `${base}\n(local model unavailable: HTTP ${res.status})`,
        4096,
      );
    }
    const j = (await res.json()) as { response?: string };
    const parsed = parseDirtyToolCall(j.response ?? "");
    if (parsed) return truncateToolOutput(JSON.stringify(parsed), 4096);
    return truncateToolOutput(j.response ?? base, 4096);
  } catch {
    return truncateToolOutput(`${base}\n(offline — no Ollama on :11434)`, 4096);
  }
}

function mcpTools(): McpToolDef[] {
  return [
    {
      name: "list_phantom_keys",
      description: "List phantom env keys and allowed hosts.",
      inputSchema: { type: "object", properties: {}, additionalProperties: false },
      annotations: { readOnlyHint: true },
    },
    {
      name: "run_sandboxed",
      description: "Run a command with phantom env and edge proxy.",
      inputSchema: {
        type: "object",
        properties: {
          argv: {
            type: "array",
            items: { type: "string" },
            description: "Command argv (executable first); preferred over cmd.",
          },
          cmd: { type: "string", description: "Deprecated: use argv instead." },
          cwd: { type: "string" },
        },
        additionalProperties: false,
      },
      annotations: { destructiveHint: true },
      mutates: true,
    },
    {
      name: "explain_exfil_attempt",
      description: "Explain a blocked exfiltration log entry.",
      inputSchema: {
        type: "object",
        properties: {
          logId: { type: "string" },
          model: { type: "string" },
        },
        required: ["logId"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true },
    },
  ];
}

function resolveSandboxArgv(args: Record<string, unknown>): string[] {
  if (Array.isArray(args.argv)) {
    const argv = args.argv.map((x) => String(x));
    if (!argv.length) throw new Error("argv must be a non-empty array");
    return argv;
  }
  const cmd = String(args.cmd ?? "");
  if (!cmd.trim()) throw new Error("argv or cmd required");
  return cmd.split(/\s+/).filter(Boolean);
}

function mcpHandlers(cwd: string): Record<string, (args: Record<string, unknown>) => Promise<unknown>> {
  return {
    list_phantom_keys: async () => {
      const vault = loadVault(cwd);
      if (!vault) return { keys: [], allowedHosts: [] };
      const keys = listPhantomKeysPublic(vault);
      return {
        keys,
        allowedHosts: [...new Set(keys.flatMap((k) => k.allowedHosts))],
      };
    },
    run_sandboxed: async (args) => {
      const parts = resolveSandboxArgv(args);
      const workdir = args.cwd ? assertPathContained(String(args.cwd), cwd) : cwd;
      const code = await cmdRun(["run", "--", ...parts], workdir);
      return { exitCode: code, blockedAttempts: getExfilLog().filter((l) => l.blocked) };
    },
    explain_exfil_attempt: async (args) => {
      const text = await explainExfil(String(args.logId), args.model ? String(args.model) : undefined);
      return { analysis: text };
    },
  };
}

export function runCli(argv: string[]): Promise<number> | number {
  const cwd = process.cwd();
  if (argv.includes("--mcp")) {
    setGuards({
      allowWrite: argv.includes("--allow-write"),
      dryRun: argv.includes("--dry-run"),
    });
    startMcpServer({
      name: "env-phantom",
      version: VERSION,
      tools: mcpTools(),
      handlers: mcpHandlers(cwd),
    });
    return 0;
  }
  if (argv.length === 0 || argv.includes("-h") || argv.includes("--help")) {
    process.stdout.write(usage() + "\n");
    return 0;
  }
  const cmd = argv[0];
  if (cmd === "mask") return cmdMask(argv.slice(1), cwd);
  if (cmd === "run") return cmdRun(argv.slice(1), cwd);
  if (cmd === "audit") return cmdAudit();
  process.stderr.write(usage() + "\n");
  return 2;
}

const isMain =
  process.argv[1]?.includes("cli") || process.argv[1]?.endsWith("env-phantom");

if (isMain) {
  const result = runCli(process.argv.slice(2));
  if (result instanceof Promise) {
    void result.then((code) => process.exit(code));
  } else {
    process.exit(result);
  }
}
