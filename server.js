import { createServer } from "node:http";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ProxyAgent } from "undici";

const __dirname = dirname(fileURLToPath(import.meta.url));
const dataDir = resolve(__dirname, "data");
const credentialsFile = resolve(dataDir, "accounts.json");
const publicDir = resolve(__dirname, "public");
mkdirSync(dataDir, { recursive: true });

const worker = await import("./worker.js");
const handler = worker.default;
const sessions = new Map();
const authFlows = new Map();
const startedAt = Date.now();
const adminPassword = process.env.ADMIN_PASSWORD || randomBytes(12).toString("base64url");
if (!process.env.ADMIN_PASSWORD) console.log(`[webui] generated admin password: ${adminPassword}`);

function hash(value) { return createHash("sha256").update(value).digest(); }
function equalsSecret(a, b) {
  const left = hash(String(a || ""));
  const right = hash(String(b || ""));
  return timingSafeEqual(left, right);
}
function json(res, status, payload, headers = {}) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers });
  res.end(JSON.stringify(payload));
}
function parseCookies(req) {
  return Object.fromEntries(String(req.headers.cookie || "").split(";").map(v => v.trim()).filter(Boolean).map(v => {
    const at = v.indexOf("=");
    return [decodeURIComponent(v.slice(0, at)), decodeURIComponent(v.slice(at + 1))];
  }));
}
function authenticated(req) {
  const token = parseCookies(req).fb_admin;
  const session = token && sessions.get(token);
  return Boolean(session && session.expiresAt > Date.now());
}
async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1024 * 1024) throw new Error("body too large");
    chunks.push(chunk);
  }
  return chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {};
}
function loadStore() {
  if (!existsSync(credentialsFile)) return { accounts: {}, settings: { strategy: "session-affinity", maxRetries: 2 } };
  try { return JSON.parse(readFileSync(credentialsFile, "utf8")); }
  catch { return { accounts: {}, settings: { strategy: "session-affinity", maxRetries: 2 } }; }
}
function saveStore(store) {
  writeFileSync(credentialsFile, JSON.stringify(store, null, 2), { mode: 0o600 });
}
function normalizeProxyUrl(value) {
  const proxyUrl = String(value || "").trim();
  if (!proxyUrl) return "";
  const parsed = new URL(proxyUrl);
  if (!["http:", "https:", "socks5:", "socks5h:"].includes(parsed.protocol)) {
    throw new Error("仅支持 http://、https://、socks5:// 或 socks5h:// 代理");
  }
  if (!parsed.hostname || !parsed.port) throw new Error("代理地址必须包含主机和端口");
  return proxyUrl;
}
async function testProxy(proxyUrl) {
  const normalized = normalizeProxyUrl(proxyUrl);
  if (!normalized) return { ok: false, error: "请先填写代理地址" };
  const startedAt = Date.now();
  try {
    const dispatcher = new ProxyAgent(normalized);
    const response = await fetch("https://www.codebuff.com/", {
      dispatcher,
      redirect: "manual",
      signal: AbortSignal.timeout(20000),
    });
    await dispatcher.close();
    return { ok: response.status >= 200 && response.status < 500, status: response.status, latencyMs: Date.now() - startedAt };
  } catch (error) {
    return { ok: false, error: error.cause?.message || error.message, latencyMs: Date.now() - startedAt };
  }
}
function maskToken(token) {
  if (!token) return "";
  return token.length > 12 ? `${token.slice(0, 5)}••••${token.slice(-5)}` : "••••••••";
}
function accountList(store = loadStore()) {
  return Object.entries(store.accounts || {}).map(([id, account]) => ({
    id, email: account.email || id, name: account.name || "", enabled: account.enabled !== false,
    proxyUrl: account.proxyUrl ? account.proxyUrl.replace(/:\/\/([^:@]+):([^@]+)@/, "://$1:••••@") : "",
    hasProxy: Boolean(account.proxyUrl), token: maskToken(account.authToken), credits: account.credits ?? null,
    createdAt: account.createdAt || null, lastUsedAt: account.lastUsedAt || null,
  }));
}
function buildRuntimeEnv() {
  const store = loadStore();
  const enabled = Object.values(store.accounts || {}).filter(a => a.enabled !== false && a.authToken);
  return {
    FREEBUFF_TOKEN: enabled.map(a => a.authToken.trim()).join(","),
    FREEBUFF_ACCOUNTS: JSON.stringify(enabled.map(a => ({ token: a.authToken.trim(), proxyUrl: a.proxyUrl || "", id: a.id || a.email || "" }))),
    FREEBUFF_API_KEY: process.env.FREEBUFF_API_KEY || "freebuff-default-key",
    FREEBUFF_DEBUG: process.env.FREEBUFF_DEBUG || "false",
    CODEBUFF_API: process.env.CODEBUFF_API || "",
    RELAY_KEY: process.env.RELAY_KEY || "",
  };
}
function fingerprint() { return `codebuff-cli-${randomBytes(6).toString("base64url").slice(0, 8)}`; }
async function startAuthorization() {
  const fingerprintId = fingerprint();
  const response = await fetch("https://www.codebuff.com/api/auth/cli/code", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ fingerprintId }),
    signal: AbortSignal.timeout(15000),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data?.error || `authorization failed (${response.status})`);
  const flowId = randomBytes(16).toString("hex");
  authFlows.set(flowId, { fingerprintId, fingerprintHash: data.fingerprintHash, expiresAt: data.expiresAt, createdAt: Date.now() });
  return { flowId, url: data.url || data.authUrl || data.loginUrl, expiresAt: data.expiresAt };
}
async function pollAuthorization(flowId) {
  const flow = authFlows.get(flowId);
  if (!flow) return { status: "expired" };
  const statusUrl = new URL("https://www.codebuff.com/api/auth/cli/status");
  statusUrl.searchParams.set("fingerprintId", flow.fingerprintId);
  statusUrl.searchParams.set("fingerprintHash", flow.fingerprintHash);
  statusUrl.searchParams.set("expiresAt", String(flow.expiresAt));
  const response = await fetch(statusUrl, {
    method: "GET",
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(15000),
  });
  if (response.status === 401) return { status: "pending" };
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data?.error || `authorization polling failed (${response.status})`);
  if (!data.user?.authToken) return { status: "pending" };
  const user = data.user;
  const store = loadStore();
  const id = String(user.email || user.id || randomBytes(6).toString("hex"));
  store.accounts[id] = { ...store.accounts[id], ...user, id, enabled: true, createdAt: store.accounts[id]?.createdAt || new Date().toISOString() };
  saveStore(store);
  authFlows.delete(flowId);
  return { status: "complete", account: accountList(store).find(account => account.id === id) };
}
function serveStatic(pathname, res) {
  const requested = pathname === "/" ? "index.html" : pathname.replace(/^\//, "");
  const file = resolve(publicDir, requested);
  if (!file.startsWith(publicDir) || !existsSync(file)) return false;
  const type = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml" }[extname(file)] || "application/octet-stream";
  res.writeHead(200, { "content-type": type, "cache-control": requested === "index.html" ? "no-cache" : "public, max-age=3600" });
  res.end(readFileSync(file));
  return true;
}

const port = Number.parseInt(process.env.PORT || "8787", 10);
const host = process.env.HOST || "0.0.0.0";
const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  try {
    if (req.method === "POST" && url.pathname === "/admin/api/login") {
      const body = await readBody(req);
      if (!equalsSecret(body.password, adminPassword)) return json(res, 401, { error: "密码错误" });
      const token = randomBytes(32).toString("base64url");
      sessions.set(token, { expiresAt: Date.now() + 12 * 60 * 60 * 1000 });
      return json(res, 200, { ok: true }, { "set-cookie": `fb_admin=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200${process.env.COOKIE_SECURE === "true" ? "; Secure" : ""}` });
    }
    if (req.method === "POST" && url.pathname === "/admin/api/logout") {
      const token = parseCookies(req).fb_admin;
      if (token) sessions.delete(token);
      return json(res, 200, { ok: true }, { "set-cookie": "fb_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" });
    }
    if (url.pathname.startsWith("/admin/api/") && !authenticated(req)) return json(res, 401, { error: "unauthorized" });
    if (req.method === "GET" && url.pathname === "/admin/api/status") {
      const store = loadStore();
      return json(res, 200, { uptime: Math.floor((Date.now() - startedAt) / 1000), accounts: accountList(store), settings: store.settings || {}, apiBase: "/v1" });
    }
    if (req.method === "POST" && url.pathname === "/admin/api/authorize") return json(res, 200, await startAuthorization());
    if (req.method === "GET" && url.pathname.startsWith("/admin/api/authorize/")) return json(res, 200, await pollAuthorization(url.pathname.split("/").pop()));
    if (req.method === "PATCH" && url.pathname.startsWith("/admin/api/accounts/")) {
      const id = decodeURIComponent(url.pathname.slice("/admin/api/accounts/".length));
      const body = await readBody(req);
      const store = loadStore();
      if (!store.accounts?.[id]) return json(res, 404, { error: "account not found" });
      for (const key of ["name", "enabled"]) if (key in body) store.accounts[id][key] = body[key];
      if ("proxyUrl" in body) store.accounts[id].proxyUrl = normalizeProxyUrl(body.proxyUrl);
      saveStore(store);
      return json(res, 200, { account: accountList(store).find(account => account.id === id) });
    }
    if (req.method === "POST" && url.pathname.startsWith("/admin/api/accounts/") && url.pathname.endsWith("/test-proxy")) {
      const id = decodeURIComponent(url.pathname.slice("/admin/api/accounts/".length, -"/test-proxy".length));
      const store = loadStore();
      if (!store.accounts?.[id]) return json(res, 404, { error: "account not found" });
      const body = await readBody(req);
      return json(res, 200, await testProxy(body.proxyUrl ?? store.accounts[id].proxyUrl));
    }
    if (req.method === "DELETE" && url.pathname.startsWith("/admin/api/accounts/")) {
      const id = decodeURIComponent(url.pathname.slice("/admin/api/accounts/".length));
      const store = loadStore();
      delete store.accounts?.[id];
      saveStore(store);
      return json(res, 200, { ok: true });
    }
    if (req.method === "PUT" && url.pathname === "/admin/api/settings") {
      const store = loadStore();
      store.settings = { ...(store.settings || {}), ...(await readBody(req)) };
      saveStore(store);
      return json(res, 200, { settings: store.settings });
    }
    if (url.pathname === "/" || url.pathname.startsWith("/assets/") || url.pathname === "/app.js" || url.pathname === "/styles.css") {
      if (serveStatic(url.pathname, res)) return;
    }
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);
    const request = new Request(url, { method: req.method, headers: new Headers(req.headers), body: body.length ? body : null });
    const response = await handler.fetch(request, buildRuntimeEnv());
    res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
    if (response.body) {
      const reader = response.body.getReader();
      while (true) { const { done, value } = await reader.read(); if (done) break; if (value) res.write(Buffer.from(value)); }
    }
    if (!res.writableEnded) res.end();
  } catch (error) {
    console.error("[server]", error);
    if (!res.headersSent) json(res, 500, { error: error.message || "internal error" });
    else if (!res.writableEnded) res.end();
  }
});
server.listen(port, host, () => console.log(`[server] listening on ${host}:${port}`));
