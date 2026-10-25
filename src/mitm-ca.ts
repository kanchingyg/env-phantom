import { generateKeyPairSync, createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { hostname, userInfo } from "node:os";

export const CA_PEM_FILE = ".env-phantom-ca.pem";

function vaultDir(cwd: string): string {
  const dir = join(cwd, ".env-phantom");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

export function machineDerivedVaultFallback(): string {
  return createHash("sha256")
    .update(`${hostname()}|${userInfo().username}|env-phantom`)
    .digest("hex");
}

export type CaMaterial = {
  caPem: string;
  caKeyPem: string;
  caPath: string;
};

let cachedCa: CaMaterial | null = null;

function openssl(args: string[]): void {
  execFileSync("openssl", args, { stdio: "pipe" });
}

/**
 * Local CA for TLS MITM on rewrite allowlist hosts.
 * RSA keys from node:crypto; X.509 via openssl (see README if openssl is missing).
 */
export function ensureLocalCa(cwd: string): CaMaterial | null {
  if (cachedCa) return cachedCa;
  const dir = vaultDir(cwd);
  const caPath = join(cwd, CA_PEM_FILE);
  const keyPath = join(dir, "ca-key.pem");

  if (existsSync(caPath) && existsSync(keyPath)) {
    cachedCa = {
      caPem: readFileSync(caPath, "utf8"),
      caKeyPem: readFileSync(keyPath, "utf8"),
      caPath,
    };
    return cachedCa;
  }

  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const caKeyPem = privateKey as string;
  writeFileSync(keyPath, caKeyPem, { mode: 0o600 });

  try {
    openssl([
      "req",
      "-new",
      "-x509",
      "-key",
      keyPath,
      "-out",
      caPath,
      "-days",
      "825",
      "-subj",
      "/CN=env-phantom-local-ca",
      "-nodes",
    ]);
  } catch {
    return null;
  }

  cachedCa = {
    caPem: readFileSync(caPath, "utf8"),
    caKeyPem,
    caPath,
  };
  return cachedCa;
}

export function issueHostCert(
  ca: CaMaterial,
  host: string,
  cwd: string,
): { certPem: string; keyPem: string } | null {
  const dir = vaultDir(cwd);
  const hostKeyPath = join(dir, `host-${host.replace(/[^a-z0-9.-]/gi, "_")}.key`);
  const hostCsrPath = join(dir, `host-${host.replace(/[^a-z0-9.-]/gi, "_")}.csr`);
  const hostCertPath = join(dir, `host-${host.replace(/[^a-z0-9.-]/gi, "_")}.crt`);
  const caKeyPath = join(dir, "ca-key.pem");

  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const keyPem = privateKey as string;
  writeFileSync(hostKeyPath, keyPem, { mode: 0o600 });

  try {
    openssl([
      "req",
      "-new",
      "-key",
      hostKeyPath,
      "-out",
      hostCsrPath,
      "-subj",
      `/CN=${host}`,
      "-nodes",
    ]);
    openssl([
      "x509",
      "-req",
      "-in",
      hostCsrPath,
      "-CA",
      ca.caPath,
      "-CAkey",
      caKeyPath,
      "-CAcreateserial",
      "-out",
      hostCertPath,
      "-days",
      "30",
    ]);
  } catch {
    return null;
  }

  return {
    certPem: readFileSync(hostCertPath, "utf8"),
    keyPem,
  };
}
