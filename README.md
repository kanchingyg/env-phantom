# env-phantom

[![ci](https://github.com/kanchingyg/env-phantom/actions/workflows/ci.yml/badge.svg)](https://github.com/kanchingyg/env-phantom/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/env-phantom)](https://www.npmjs.com/package/env-phantom)
[![JSR](https://jsr.io/badges/@kanchingyg/env-phantom)](https://jsr.io/@kanchingyg/env-phantom)
[![Bun](https://img.shields.io/badge/runtime-Node_%7C_Bun-f9f1e1)](https://github.com/kanchingyg/env-phantom)
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

## MCP setup

Add to `.cursor/mcp.json` or Claude Code MCP config:

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

## Ollama (optional)

For `explain_exfil_attempt`, run Ollama on port `11434`. Cloud OpenAI-compatible endpoints used for embeddings can sit behind the same phantom vault pattern via `HTTP_PROXY`.

## License

[MIT](./LICENSE)
