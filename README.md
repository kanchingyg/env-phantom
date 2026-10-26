# env-phantom

[![ci](https://github.com/kanchingyg/env-phantom/actions/workflows/ci.yml/badge.svg)](https://github.com/kanchingyg/env-phantom/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/env-phantom/latest?label=npm)](https://www.npmjs.com/package/env-phantom)
[![JSR](https://jsr.io/badges/@kanchingyg/env-phantom)](https://jsr.io/@kanchingyg/env-phantom)
[![JSR Score](https://jsr.io/badges/@kanchingyg/env-phantom/score)](https://jsr.io/@kanchingyg/env-phantom/score)
[![Runtime](https://img.shields.io/badge/runtime-Node_%7C_Bun_%7C_Deno-f9f1e1)](https://github.com/kanchingyg/env-phantom)
[![license](https://img.shields.io/github/license/kanchingyg/env-phantom)](https://github.com/kanchingyg/env-phantom/blob/HEAD/LICENSE)

**One line:** `npx env-phantom mask .env --allow-write && npx env-phantom run -- node app.js`

Child processes and coding agents see format-preserving `phantom_*` tokens in `process.env`. Real secrets are swapped in only inside the local edge HTTP proxy when the outbound `Host` matches your allowlist; everything else gets `403 Blocked by env-phantom`. `HTTPS_PROXY` uses HTTP `CONNECT` (tunnel or local TLS MITM for rewrite hosts). The vault is encrypted at rest (AES-256-GCM); set `ENV_PHANTOM_VAULT_KEY` or use the machine-derived fallback. `mask --allow-write` backs up `.env` to `.env.bak` first.

## Why not dotenvx / 1Password / Infisical?

Those tools decrypt secrets directly into the child process environment. Any dependency, coding agent, or `postinstall` script can read `process.env` and exfiltrate the real key. `env-phantom` never places the real secret value in the child environment.

## Install

[Bun](https://bun.sh) / [npm](https://www.npmjs.com/package/env-phantom):

```bash
bunx env-phantom mask .env --dry-run
npx env-phantom mask .env --dry-run

# or install in your project / globally
bun add -d env-phantom
npm i -D env-phantom
```

[JSR](https://jsr.io/@kanchingyg/env-phantom):

```bash
bunx jsr add @kanchingyg/env-phantom
npx jsr add @kanchingyg/env-phantom
```

## CLI

| Command | Purpose |
| --- | --- |
| `mask .env` | Print masked env (`--dry-run` / `--allow-write` to persist + vault) |
| `run -- <cmd>` | Run command with phantom env + local proxy |
| `audit` | Print blocked exfiltration attempts |
| `--mcp` | Start MCP server over stdio |

## Ollama (optional)

For `explain_exfil_attempt`, run Ollama on port `11434`. Cloud OpenAI-compatible endpoints used for embeddings can sit behind the same phantom vault pattern via `HTTP_PROXY`.

## MCP Tools Reference

| Tool | Mutates | Description |
| --- | --- | --- |
| `list_phantom_keys` | `false` | List phantom env keys and merged allowlisted hosts (no secret values). |
| `run_sandboxed` | `true` | Run `argv` under phantom env + edge proxy (`--allow-write`; optional `cwd` under sandbox root). |
| `explain_exfil_attempt` | `false` | Summarize a blocked exfiltration log entry (`logId`; optional local `model`). |

Masking `.env` is CLI-only (`mask`); use `npx env-phantom audit` for blocked outbound attempts.

## Editor and Agent Integration

### Cursor (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "env-phantom": {
      "command": "npx",
      "args": ["-y", "env-phantom", "--mcp"]
    }
  }
}
```

### Claude Code CLI

```bash
claude mcp add env-phantom -- npx -y env-phantom --mcp
```

### Programmatic Usage (JSR / TypeScript)

```ts
import * as bridge from "jsr:@kanchingyg/env-phantom/bridge";
```

## Runtime Safety and Guardrails

- **Stdio frame isolation**: `--mcp` keeps JSON-RPC on `stdout` clean (logs go to `stderr`).
- **Read-only default**: `run_sandboxed` needs `--allow-write`; `--dry-run` blocks mutating tools.
- **Loop breaker**: Identical MCP tool calls halt after three repeats.
- **Path containment**: `mask` and MCP `cwd` must stay under the process working directory.
- **Edge proxy**: Non-allowlisted hosts get `403` when a request carries a phantom token.

## License

[MIT](./LICENSE)
