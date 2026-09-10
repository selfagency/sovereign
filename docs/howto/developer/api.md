---
title: "Call the REST API"
weight: 20
---

# How to call the REST API

> **Goal:** make authenticated requests to the Sovereign control plane from a
> script, integration, or custom client.
> **Status:** shipped — the API is the authoritative control-plane surface
> (see [ADR 0003](../../explanation/design-decisions/0003-identity-host-control-plane.md)).
> **You'll need:** a Sovereign account (for self endpoints) or an
> instance-admin account (for `admin:*` endpoints), and a way to make HTTP
> requests. The full wire contract is
> [openapi/sovereign.v1.yaml](../../../openapi/sovereign.v1.yaml); the
> [reference page](../../reference/api/control-plane.md) summarizes it.

## Base URL

The API lives **only on the identity host**:

```text
https://id.<domain>/api/v1
```

Tenant is derived from the authenticated principal, never from the `Host`
header or a body field.

## Authentication — bearer vs cookie

Exactly **one** credential per request. Sending both a bearer token and the
session cookie is rejected with `400`.

| Credential | For | How |
|:-----------|:----|:----|
| **Bearer** | Programmatic clients (scripts, CI, integrations) | `Authorization: Bearer <token>` |
| **Cookie** | Browser sessions | `Cookie: session=<opaque-token>` (HttpOnly; set by the server) |

Bearer tokens are created two ways:

* `POST /api/v1/me/tokens` — self-issued, scope-subset selection, **show-once**
  (the raw token is returned exactly once; capture it).
* `POST /api/v1/auth/invite/redeem` — exchange a one-time invite token for a
  session (programmatic invite redemption).

Bearer tokens must carry the `sovereign-api` audience
([ADR 0010](../../explanation/design-decisions/0010-audience-separation.md)).
A token minted for another audience (e.g. a data-plane token) is rejected.

```bash
# Create a token (show-once) — then use it:
curl https://id.example.com/api/v1/me \
  -H "Authorization: Bearer <token>"
```

## CSRF — cookie principals only

Cookie-authenticated requests that mutate state (POST/PUT/PATCH/DELETE) must
prove they are same-origin:

1. The server sets a non-HttpOnly `__Host-csrf` cookie (double-submit).
2. Echo its value in the `X-CSRF-Token` header.
3. The server also enforces `Origin`/`Sec-Fetch-Site`; a `cross-site`
   `Sec-Fetch-Site` is rejected with `403`.

Bearer requests are **exempt** — no CSRF header needed. No-JS HTML forms
submit the token in a hidden `csrf_token` field instead of the header
(synchronizer-token; see
[ADR 0009](../../explanation/design-decisions/0009-no-js-fallback.md)).

```bash
# Read the CSRF cookie, then echo it on the mutation:
TOKEN=$(curl -s -c jar https://id.example.com/api/v1/auth/session -o /dev/null \
  && awk '$6 == "__Host-csrf" {print $7}' jar)
curl -X POST https://id.example.com/api/v1/me/tos \
  -b jar -H "X-CSRF-Token: $TOKEN"
```

## Idempotency-Key

POSTs with genuine external side effects **require** an `Idempotency-Key`
header: invite redemption, user creation, invite sending, backup runs, and
backup restores. Keys are retained 24 h; a replay with the same key returns
the original response and does **not** repeat the side effect (e.g. no second
email). Generate a fresh UUID per logical operation and reuse it on retries.

```bash
curl -X POST https://id.example.com/api/v1/admin/backup/runs \
  -H "Authorization: Bearer <admin-token>" \
  -H "Idempotency-Key: $(uuidgen)"
```

## Errors — RFC 9457 problem+json

Every non-2xx response is `application/problem+json` with a stable `type`
URI under `/problems/`, a `title`, `status`, optional `detail` and
`instance`, and an `errors[]` array on `validation-failed` (422). See the
[reference page](../../reference/api/control-plane.md#errors) for the full
table. Key rules:

* `401` — missing/invalid credential.
* `403` — insufficient scope, or non-admin on an `admin:*` route.
* `404` — missing resource; also used for cross-tenant resources (no
  enumeration oracle).
* `429` — rate limited; honor `Retry-After`.

```json
{
  "type": "https://id.example.com/problems/insufficient-scope",
  "title": "Insufficient Scope",
  "status": 403,
  "instance": "/api/v1/admin/users"
}
```

## ETag / conditional GET

Single-resource GETs return an `ETag`. Send it back in `If-None-Match`; an
unchanged resource answers `304` with no body. There is **no** mandatory
`If-Match` on writes.

```bash
ETAG=$(curl -sI https://id.example.com/api/v1/me/profile \
  -H "Authorization: Bearer <token>" | awk -F': ' 'tolower($1)=="etag" {print $2}' | tr -d '\r')
curl -s -o /dev/null -w '%{http_code}\n' https://id.example.com/api/v1/me/profile \
  -H "Authorization: Bearer <token>" -H "If-None-Match: $ETAG"   # 304
```

## Rate limits

Per-IP token bucket (no per-principal buckets). On `429` the response carries
`Retry-After` and `RateLimit-*` headers. Back off, do not hammer.

## The shared `api.js` client

The thin clients (`web/panel`, `web/admin`) use one shared ES module,
`internal/web/shared/api.js`, which handles all of the above for you:

* reads the `__Host-csrf` cookie and sends `X-CSRF-Token` on unsafe methods;
* normalizes problem+json into an `ApiError` (`status`, `problem`,
  `retryAfter`);
* tracks ETags per path and sends `If-None-Match` on GETs (handles `304`);
* generates an `Idempotency-Key` for the idempotent POST paths;
* redirects to login on `401`.

```js
import { api } from "/web/shared/api.js";

const { data } = await api.get("/api/v1/me/onboarding");
await api.post("/api/v1/me/tos");
const { data: token } = await api.post("/api/v1/me/tokens",
  { name: "ci", scopes: ["self:read"] });
```

It is a plain ES module — no framework, no build step — and is safe to reuse
in your own client as long as you serve it from the same origin (the API
denies CORS by default; allowlist via `api.cors_origins` config if you must
call cross-origin).

## See also

* [Control-plane API reference](../../reference/api/control-plane.md) — every
  endpoint, scope, and error.
* [ADR 0005](../../explanation/design-decisions/0005-rfc9457-problem-details.md) ·
  [ADR 0008](../../explanation/design-decisions/0008-browser-programmatic-auth-split.md) ·
  [ADR 0010](../../explanation/design-decisions/0010-audience-separation.md).
