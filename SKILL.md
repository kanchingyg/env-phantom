---
name: env-phantom
description: Mask .env secrets as phantom tokens; real keys inject only at TLS edge for allowlisted hosts.
---

# env-phantom

Use when agents or scripts must not see real API keys in `process.env`, but outbound calls to trusted APIs still need real credentials.

## Quick start

```bash
npx env-phantom mask .env --allow-write
npx env-phantom run -- node app.js
npx env-phantom audit
```

## MCP (Cursor / Claude Code / Kilo Code)

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

Tools: `list_phantom_keys`, `run_sandboxed`, `explain_exfil_attempt`.

Pass `--allow-write` on the MCP command only when the agent may rewrite `.env` or run sandboxed shells.

## Local models

`explain_exfil_attempt` prefers Ollama at `http://127.0.0.1:11434` for offline audit; falls back to a truncated log summary when offline.
