import type { Vault } from "./vault.js";

/** Safe keys copied from the parent process into sandboxed children. */
const SAFE_ENV_EXACT = new Set([
  "PATH",
  "PATHEXT",
  "HOME",
  "USERPROFILE",
  "HOMEDRIVE",
  "HOMEPATH",
  "TEMP",
  "TMP",
  "TMPDIR",
  "SystemRoot",
  "WINDIR",
  "COMSPEC",
  "OS",
  "PROCESSOR_ARCHITECTURE",
  "PROCESSOR_IDENTIFIER",
  "NUMBER_OF_PROCESSORS",
  "USER",
  "USERNAME",
  "LOGNAME",
  "SHELL",
  "TERM",
  "COLORTERM",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "PWD",
  "OLDPWD",
  "APPDATA",
  "LOCALAPPDATA",
  "PROGRAMFILES",
  "PROGRAMFILES(X86)",
  "PROGRAMDATA",
  "PUBLIC",
  "SYSTEMDRIVE",
  "NODE_OPTIONS",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
  "ALL_PROXY",
  "NODE_EXTRA_CA_CERTS",
  "ENV_PHANTOM_PATH_WSL",
  "ENV_PHANTOM_VAULT_KEY",
]);

const SAFE_PREFIXES = ["npm_", "NPM_", "BUN_", "VITEST_", "NODE_"];

export function isSafeParentEnvKey(key: string): boolean {
  if (SAFE_ENV_EXACT.has(key)) return true;
  return SAFE_PREFIXES.some((p) => key.startsWith(p));
}

/**
 * Child environment: true allowlist of parent keys + phantom values for vault keys + extras.
 * Never copies the full parent process.env (DATABASE_URL and similar stay out).
 */
export function buildChildProcessEnv(
  vault: Vault,
  extra: Record<string, string> = {},
): Record<string, string> {
  const out: Record<string, string> = {};

  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined) continue;
    if (!isSafeParentEnvKey(k)) continue;
    out[k] = v;
  }

  for (const entry of vault.entries) {
    out[entry.envKey] = entry.phantom;
  }

  for (const [k, v] of Object.entries(extra)) {
    out[k] = v;
  }

  return out;
}
