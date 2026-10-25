import {
  createServer,
  request as httpRequest,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { connect as netConnect, type Socket } from "node:net";
import tls from "node:tls";
import type { Vault } from "./vault.js";
import { replacePhantomsInString } from "./rewriter.js";
import { redactSecrets } from "./rewriter.js";
import { ensureLocalCa, issueHostCert } from "./mitm-ca.js";

export type UpstreamTarget = { hostname: string; port: number };

export type EdgeProxyOptions = {
  vault: Vault;
  cwd?: string;
  resolveUpstream?: (host: string, port: number) => UpstreamTarget;
};

export type ExfilLogEntry = {
  id: string;
  at: string;
  host: string;
  method: string;
  path: string;
  blocked: boolean;
  detail: string;
};

let exfilLog: ExfilLogEntry[] = [];
let logSeq = 0;

export function resetExfilLog(): void {
  exfilLog = [];
  logSeq = 0;
}

export function getExfilLog(): ExfilLogEntry[] {
  return [...exfilLog];
}

export function getExfilById(id: string): ExfilLogEntry | undefined {
  return exfilLog.find((e) => e.id === id);
}

function pushLog(entry: Omit<ExfilLogEntry, "id" | "at">): string {
  const id = `log_${++logSeq}`;
  exfilLog.push({ id, at: new Date().toISOString(), ...entry });
  return id;
}

export function handlesConnectMethod(method: string | undefined): boolean {
  return method === "CONNECT";
}

export function hostAllowed(vault: Vault, host: string): boolean {
  const h = host.toLowerCase().split(":")[0];
  return vault.entries.some((e) =>
    e.allowedHosts.some((a) => a.toLowerCase() === h),
  );
}

/** HTTPS MITM rewrite only on standard TLS ports; other ports use CONNECT tunnel. */
export function hostNeedsRewrite(vault: Vault, host: string, port: number): boolean {
  if (port !== 443 && port !== 8443) return false;
  return hostAllowed(vault, host);
}

function rewriteHeaders(
  headers: Record<string, string | string[] | undefined>,
  vault: Vault,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined) continue;
    const raw = Array.isArray(v) ? v.join(", ") : v;
    out[k] = replacePhantomsInString(raw, vault);
  }
  return out;
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c as Buffer));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function parseConnectTarget(url: string | undefined): { host: string; port: number } | null {
  if (!url) return null;
  const trimmed = url.trim();
  const colon = trimmed.lastIndexOf(":");
  if (colon <= 0) return { host: trimmed.toLowerCase(), port: 443 };
  const host = trimmed.slice(0, colon).toLowerCase();
  const port = parseInt(trimmed.slice(colon + 1), 10);
  if (!host || Number.isNaN(port)) return null;
  return { host, port };
}

function tunnelSockets(clientSocket: Socket, upstream: Socket): void {
  clientSocket.setTimeout(0);
  upstream.setTimeout(0);
  clientSocket.pipe(upstream);
  upstream.pipe(clientSocket);
  clientSocket.on("error", () => upstream.destroy());
  upstream.on("error", () => clientSocket.destroy());
}

function connectPassthrough(
  clientSocket: Socket,
  hostname: string,
  port: number,
  resolve: (host: string, port: number) => UpstreamTarget,
): void {
  const upstream = resolve(hostname, port);
  const server = netConnect(upstream.port, upstream.hostname, () => {
    tunnelSockets(clientSocket, server);
  });
  server.on("error", () => clientSocket.destroy());
}

function mitmTlsRelay(
  clientSocket: Socket,
  host: string,
  port: number,
  creds: { certPem: string; keyPem: string },
  vault: Vault,
  resolve: (host: string, port: number) => UpstreamTarget,
): void {
  const tlsServer = new tls.TLSSocket(clientSocket, {
    isServer: true,
    key: creds.keyPem,
    cert: creds.certPem,
  });

  let buffered = Buffer.alloc(0);
  const onData = (chunk: Buffer) => {
    buffered = Buffer.concat([buffered, chunk]);
    const headerEnd = buffered.indexOf("\r\n\r\n");
    if (headerEnd < 0) return;
    tlsServer.off("data", onData);
    const head = buffered.subarray(0, headerEnd).toString("utf8");
    const rest = buffered.subarray(headerEnd + 4);
    const lines = head.split("\r\n");
    const [reqLine, ...headerLines] = lines;
    const parts = reqLine?.split(" ") ?? [];
    const method = parts[0] ?? "GET";
    const path = parts[1] ?? "/";
    const headers: Record<string, string> = {};
    for (const line of headerLines) {
      const idx = line.indexOf(":");
      if (idx < 1) continue;
      headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
    }
    const rewritten = rewriteHeaders(headers, vault);
    const upstreamTarget = resolve(host, port);
    const upstreamTls = tls.connect(
      {
        host: upstreamTarget.hostname,
        port: upstreamTarget.port,
        servername: host,
      },
      () => {
        const hdrLines = Object.entries(rewritten).map(([k, v]) => `${k}: ${v}`);
        const reqHead = [reqLine ? replacePhantomsInString(reqLine, vault) : `${method} ${path} HTTP/1.1`, ...hdrLines, "", ""].join(
          "\r\n",
        );
        upstreamTls.write(reqHead);
        if (rest.length) upstreamTls.write(rest);
        tlsServer.pipe(upstreamTls);
        upstreamTls.pipe(tlsServer);
      },
    );
    upstreamTls.on("error", () => tlsServer.destroy());
    tlsServer.on("error", () => upstreamTls.destroy());
  };
  tlsServer.on("data", onData);
  tlsServer.on("error", () => clientSocket.destroy());
}

async function handleHttp(
  clientReq: IncomingMessage,
  clientRes: ServerResponse,
  opts: EdgeProxyOptions,
): Promise<void> {
  const hostHeader = clientReq.headers.host ?? "";
  const host = hostHeader.split(":")[0];
  const port = parseInt(hostHeader.split(":")[1] ?? "80", 10);

  if (!host || !hostAllowed(opts.vault, host)) {
    const detail = `Host ${host || "(missing)"} not in allowlist`;
    pushLog({
      host: host || "unknown",
      method: clientReq.method ?? "GET",
      path: clientReq.url ?? "/",
      blocked: true,
      detail,
    });
    clientRes.writeHead(403, { "Content-Type": "text/plain" });
    clientRes.end("403 Blocked by env-phantom");
    return;
  }

  const body = await readBody(clientReq);
  const bodyStr = replacePhantomsInString(body.toString("utf8"), opts.vault);
  const headers = rewriteHeaders(clientReq.headers, opts.vault);
  const resolve = opts.resolveUpstream ?? ((h, p) => ({ hostname: h, port: p }));
  const upstream = resolve(host, port);

  const path = clientReq.url ?? "/";
  const fwd = httpRequest(
    {
      hostname: upstream.hostname,
      port: upstream.port,
      method: clientReq.method,
      path,
      headers: { ...headers, host: hostHeader },
    },
    (upRes) => {
      clientRes.writeHead(upRes.statusCode ?? 502, upRes.headers);
      upRes.pipe(clientRes);
    },
  );
  fwd.on("error", (err) => {
    clientRes.writeHead(502);
    clientRes.end(redactSecrets(String(err), opts.vault));
  });
  fwd.write(bodyStr);
  fwd.end();
}

function handleConnectSocket(
  clientReq: IncomingMessage,
  clientSocket: Socket,
  opts: EdgeProxyOptions,
): void {
  const target = parseConnectTarget(clientReq.url);
  const host = target?.host ?? "";
  const port = target?.port ?? 443;

  if (!target || !hostAllowed(opts.vault, host)) {
    const detail = `CONNECT host ${host || "(missing)"} not in allowlist`;
    pushLog({
      host: host || "unknown",
      method: "CONNECT",
      path: clientReq.url ?? "",
      blocked: true,
      detail,
    });
    clientSocket.write("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\n403 Blocked by env-phantom");
    clientSocket.destroy();
    return;
  }

  pushLog({
    host,
    method: "CONNECT",
    path: clientReq.url ?? "",
    blocked: false,
    detail: hostNeedsRewrite(opts.vault, host, port) ? "CONNECT (rewrite path)" : "CONNECT tunnel",
  });

  const resolve = opts.resolveUpstream ?? ((h, p) => ({ hostname: h, port: p }));

  const startTunnel = () => {
    connectPassthrough(clientSocket, host, port, resolve);
  };

  if (hostNeedsRewrite(opts.vault, host, port)) {
    const cwd = opts.cwd ?? process.cwd();
    const ca = ensureLocalCa(cwd);
    const hostMat = ca ? issueHostCert(ca, host, cwd) : null;
    if (ca && hostMat) {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      void mitmTlsRelay(clientSocket, host, port, hostMat, opts.vault, resolve);
      return;
    }
  }

  clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
  startTunnel();
}

export function createEdgeProxy(opts: EdgeProxyOptions): Server {
  const server = createServer((clientReq, clientRes) => {
    if (handlesConnectMethod(clientReq.method)) {
      return;
    }
    void handleHttp(clientReq, clientRes, opts);
  });
  server.on("connect", (clientReq, clientSocket) => {
    handleConnectSocket(clientReq, clientSocket as Socket, opts);
  });
  return server;
}

export async function startEdgeProxy(
  opts: EdgeProxyOptions,
): Promise<{ server: Server; port: number; url: string }> {
  const server = createEdgeProxy({ ...opts, cwd: opts.cwd ?? process.cwd() });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  return { server, port, url: `http://127.0.0.1:${port}` };
}

export async function proxyRequest(
  proxyPort: number,
  targetHost: string,
  path: string,
  headers: Record<string, string>,
  body?: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: "127.0.0.1",
        port: proxyPort,
        method: "GET",
        path,
        headers: { ...headers, host: targetHost },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c as Buffer));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
          }),
        );
      },
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

export async function proxyConnect(
  proxyPort: number,
  targetHost: string,
  targetPort: number,
): Promise<{ statusLine: string }> {
  return new Promise((resolve, reject) => {
    const socket = netConnect(proxyPort, "127.0.0.1", () => {
      socket.write(
        `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\nProxy-Connection: keep-alive\r\n\r\n`,
      );
    });
    let data = "";
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("CONNECT timed out"));
    }, 4000);
    socket.on("data", (chunk) => {
      data += chunk.toString("utf8");
      if (data.includes("\r\n\r\n")) {
        clearTimeout(timer);
        const statusLine = data.split("\r\n")[0] ?? "";
        socket.destroy();
        resolve({ statusLine });
      }
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}
