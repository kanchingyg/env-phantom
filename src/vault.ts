import {
  createHash,
  scryptSync,
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { machineDerivedVaultFallback } from "./mitm-ca.js";

export const VAULT_FILE = ".env-phantom-vault.json";

const CIPHER = "aes-256-gcm";
const KEY_LEN = 32;
const IV_LEN = 16;
const SALT_LEN = 32;

export type VaultEntry = {
  envKey: string;
  phantom: string;
  secret: string;
  allowedHosts: string[];
};

export type Vault = {
  version: 1;
  entries: VaultEntry[];
};

export type EncryptedVaultFile = {
  version: 2;
  format: "aes-256-gcm";
  salt: string;
  iv: string;
  authTag: string;
  ciphertext: string;
};

export function resolveVaultPassword(): string {
  const fromEnv = process.env.ENV_PHANTOM_VAULT_KEY;
  if (fromEnv && fromEnv.length > 0) return fromEnv;
  return machineDerivedVaultFallback();
}

function deriveKey(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, KEY_LEN);
}

export function encryptVaultPayload(vault: Vault, password?: string): EncryptedVaultFile {
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const key = deriveKey(password ?? resolveVaultPassword(), salt);
  const cipher = createCipheriv(CIPHER, key, iv);
  const plaintext = JSON.stringify(vault);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    version: 2,
    format: "aes-256-gcm",
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    ciphertext: enc.toString("base64"),
  };
}

export function decryptVaultPayload(file: EncryptedVaultFile, password?: string): Vault {
  const salt = Buffer.from(file.salt, "base64");
  const iv = Buffer.from(file.iv, "base64");
  const authTag = Buffer.from(file.authTag, "base64");
  const ciphertext = Buffer.from(file.ciphertext, "base64");
  const key = deriveKey(password ?? resolveVaultPassword(), salt);
  const decipher = createDecipheriv(CIPHER, key, iv);
  decipher.setAuthTag(authTag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  return JSON.parse(plain) as Vault;
}

function isPlainVault(parsed: unknown): parsed is Vault {
  if (!parsed || typeof parsed !== "object") return false;
  const v = parsed as Vault;
  return v.version === 1 && Array.isArray(v.entries);
}

function isEncryptedVault(parsed: unknown): parsed is EncryptedVaultFile {
  if (!parsed || typeof parsed !== "object") return false;
  const v = parsed as EncryptedVaultFile;
  return v.version === 2 && v.format === "aes-256-gcm" && typeof v.ciphertext === "string";
}

export function phantomToken(envKey: string, secret: string): string {
  const h = createHash("sha256").update(secret).digest("hex").slice(0, 8);
  const slug = envKey.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
  return `phantom_${slug || "key"}_${h}`;
}

export function parseEnvFile(content: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq < 1) continue;
    const key = trimmed.slice(0, eq).trim();
    let val = trimmed.slice(eq + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    out[key] = val;
  }
  return out;
}

export function defaultHostsForKey(key: string): string[] {
  const k = key.toUpperCase();
  if (k.includes("STRIPE")) return ["api.stripe.com", "allowed.local"];
  if (k.includes("OPENAI")) return ["api.openai.com", "allowed.local"];
  if (k.includes("ANTHROPIC")) return ["api.anthropic.com", "allowed.local"];
  return ["allowed.local", "127.0.0.1", "localhost"];
}

export function buildVaultFromEnv(
  vars: Record<string, string>,
  hostMap?: Record<string, string[]>,
): Vault {
  const entries: VaultEntry[] = [];
  for (const [envKey, secret] of Object.entries(vars)) {
    if (!secret || secret.startsWith("phantom_")) continue;
    entries.push({
      envKey,
      secret,
      phantom: phantomToken(envKey, secret),
      allowedHosts: hostMap?.[envKey] ?? defaultHostsForKey(envKey),
    });
  }
  return { version: 1, entries };
}

export function maskEnvLines(content: string, vault: Vault): string {
  const lines = content.split(/\r?\n/);
  return lines
    .map((line) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) return line;
      const eq = trimmed.indexOf("=");
      if (eq < 1) return line;
      const key = trimmed.slice(0, eq).trim();
      const entry = vault.entries.find((e) => e.envKey === key);
      if (!entry) return line;
      return `${key}=${entry.phantom}`;
    })
    .join("\n");
}

export function loadVault(cwd: string): Vault | null {
  const p = join(cwd, VAULT_FILE);
  if (!existsSync(p)) return null;
  const raw = readFileSync(p, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  if (isEncryptedVault(parsed)) {
    return decryptVaultPayload(parsed);
  }
  if (isPlainVault(parsed)) {
    saveVault(cwd, parsed);
    return parsed;
  }
  return null;
}

export function saveVault(cwd: string, vault: Vault): void {
  const encrypted = encryptVaultPayload(vault);
  writeFileSync(join(cwd, VAULT_FILE), JSON.stringify(encrypted, null, 2), { mode: 0o600 });
}

export function listPhantomKeysPublic(vault: Vault): Array<{
  envKey: string;
  phantom: string;
  allowedHosts: string[];
}> {
  return vault.entries.map((e) => ({
    envKey: e.envKey,
    phantom: e.phantom,
    allowedHosts: e.allowedHosts,
  }));
}
