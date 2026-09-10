// Shared thin-client API helper for the Sovereign panel. Plain ES module:
// no framework, no bundler, no build step. It is loaded with a strict CSP
// (script-src 'self'), so every script is an external file served by the
// server's embedded asset handler.
//
//   CSRF   — the server sets a non-HttpOnly __Host-csrf cookie (double
//            submit); we echo it in X-CSRF-Token on unsafe methods.
//   ETag   — GETs send If-None-Match and record the response ETag so a 304
//            can be handled without a body.
//   Errors — problem+json responses become ApiError; 401 redirects to login,
//            403/429 surface to the caller (429 carries Retry-After).
//   Retry  — invite redemption and backup run/restore POSTs carry a fresh
//            Idempotency-Key so a replay cannot double-apply.

const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const CSRF_COOKIE = "__Host-csrf";
const CSRF_HEADER = "X-CSRF-Token";

// POST endpoints the server marks Idempotent (api.Route.Idempotent).
const IDEMPOTENT_PATHS = new Set([
  "/api/v1/auth/invite/redeem",
  "/api/v1/admin/backup/runs",
  "/api/v1/admin/backup/restores",
]);

// etags remembers the last ETag per request path for conditional GETs.
const etags = new Map();

/** ApiError normalizes any non-2xx response (problem+json or not). */
export class ApiError extends Error {
  constructor(status, problem, body, retryAfter) {
    super((problem && (problem.title || problem.detail)) || `HTTP ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.problem = problem || null;
    this.body = body;
    this.retryAfter = retryAfter || null;
  }
}

function readCookie(name) {
  const prefix = name + "=";
  for (const part of document.cookie.split(";")) {
    const cookie = part.trim();
    if (cookie.startsWith(prefix)) {
      return decodeURIComponent(cookie.slice(prefix.length));
    }
  }
  return null;
}

function idempotencyKey() {
  if (globalThis.crypto && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function isIdempotent(method, path) {
  return method === "POST" && IDEMPOTENT_PATHS.has(path.split("?")[0]);
}

function isProblem(contentType) {
  return typeof contentType === "string" && contentType.includes("application/problem+json");
}

async function readPayload(res) {
  if (res.status === 204 || res.status === 304) return null;
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("json")) {
    return res.json().catch(() => null);
  }
  return res.text().catch(() => null);
}

function redirectToLogin() {
  const next = encodeURIComponent(location.pathname + location.search);
  location.assign(`/login?next=${next}`);
}

async function request(method, path, body, opts = {}) {
  const headers = new Headers(opts.headers);
  const isForm = body instanceof FormData;
  if (body !== undefined && body !== null && !isForm && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (UNSAFE.has(method)) {
    const token = readCookie(CSRF_COOKIE);
    if (token) headers.set(CSRF_HEADER, token);
  }
  if (method === "GET") {
    const tag = etags.get(path);
    if (tag) headers.set("If-None-Match", tag);
  }
  if (isIdempotent(method, path) && !headers.has("Idempotency-Key")) {
    headers.set("Idempotency-Key", idempotencyKey());
  }

  let payload;
  if (body === undefined || body === null || isForm || typeof body === "string") {
    payload = body;
  } else {
    payload = JSON.stringify(body);
  }

  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: payload,
  });

  const etag = res.headers.get("ETag");
  if (method === "GET" && etag) etags.set(path, etag);
  if (res.status === 304) {
    return { status: 304, data: null, etag: etag || etags.get(path) || null };
  }

  const data = await readPayload(res);
  const problem = isProblem(res.headers.get("content-type")) ? data : null;
  if (res.status === 401) {
    redirectToLogin();
    throw new ApiError(401, problem, data);
  }
  if (res.status === 403) {
    throw new ApiError(403, problem, data);
  }
  if (res.status === 429) {
    throw new ApiError(429, problem, data, res.headers.get("Retry-After"));
  }
  if (!res.ok) {
    throw new ApiError(res.status, problem, data);
  }
  return { status: res.status, data, etag: etag || null };
}

/** api.get/post/put/patch/delete are the thin client's whole surface. */
export const api = {
  get: (path, opts) => request("GET", path, undefined, opts),
  post: (path, body, opts) => request("POST", path, body, opts),
  put: (path, body, opts) => request("PUT", path, body, opts),
  patch: (path, body, opts) => request("PATCH", path, body, opts),
  delete: (path, opts) => request("DELETE", path, undefined, opts),
};

export default api;
