import type { Vault } from "./vault.js";
import { buildChildProcessEnv } from "./child-env.js";

/** @deprecated Use buildChildProcessEnv — does not pass full parent env. */
export function phantomProcessEnv(
  vault: Vault,
  extra: Record<string, string> = {},
): Record<string, string> {
  return buildChildProcessEnv(vault, extra);
}

export function replacePhantomsInString(text: string, vault: Vault): string {
  let out = text;
  for (const entry of vault.entries) {
    if (out.includes(entry.phantom)) {
      out = out.split(entry.phantom).join(entry.secret);
    }
  }
  return out;
}

export function replaceSecretsWithPhantoms(text: string, vault: Vault): string {
  let out = text;
  for (const entry of vault.entries) {
    if (out.includes(entry.secret)) {
      out = out.split(entry.secret).join(entry.phantom);
    }
  }
  return out;
}

/** Blindaje 6: never leak real secrets in logs or MCP responses. */
export function redactSecrets(text: string, vault: Vault): string {
  let out = text;
  for (const entry of vault.entries) {
    out = out.split(entry.secret).join("[REDACTED]");
  }
  return out;
}
