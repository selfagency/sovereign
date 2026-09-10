---
title: "Control plane (REST API)"
weight: 60
---

# Control plane — `/api/v1`

The versioned JSON REST API for every control-plane operation: identity,
profile, keys, proofs, credentials, sessions, tokens, export, and the
instance-admin surface. It is served **only on the identity host**
(`https://id.<domain>/api/v1`) — see [ADR 0003](../../explanation/design-decisions/0003-identity-host-control-plane.md).

> **Source of truth:** `openapi/sovereign.v1.yaml`. The route set in
> `internal/api/router.go` is kept in parity with the spec in both directions
> by the OpenAPI drift test (see [ADR 0007](../../explanation/design-decisions/0007-openapi-source-of-truth.md)).
> This page is a hand-curated summary; the spec is the authoritative wire
> contract.

## Conventions

* **Base URL:** `https://id.<domain>/api/v1`. Versioning is by URL path major
  version; additive within `v1`, breaking changes move to `v2` alongside.
* **JSON:** `application/json; charset=utf-8` for requests and responses,
  `snake_case` field names, RFC 3339 UTC timestamps (always `Z`-suffixed).
  Avatar uploads use `multipart/form-data`; no-JS form POSTs use
  `application/x-www-form-urlencoded` with a hidden `csrf_token` field.
* **Auth:** exactly one of a bearer token or the session cookie per request —
  sending both is rejected with `400` (see
  [ADR 0008](../../explanation/design-decisions/0008-browser-programmatic-auth-split.md)).
  Bearer tokens must carry the `sovereign-api` audience
  ([ADR 0010](../../explanation/design-decisions/0010-audience-separation.md)).
* **CSRF:** cookie-authenticated unsafe methods (POST/PUT/PATCH/DELETE) must
  send the double-submit token from the `__Host-csrf` cookie in the
  `X-CSRF-Token` header (or the `csrf_token` form field for form-encoded
  POSTs). Bearer requests are exempt.
* **Errors:** RFC 9457 Problem Details (`application/problem+json`). See
  [Errors](#errors) below.
* **Idempotency:** POSTs with genuine external side effects require an
  `Idempotency-Key` header; a replay within 24 h returns the original
  response. See [Idempotency](#idempotency).
* **Concurrency:** single-resource GETs return an `ETag`; send
  `If-None-Match` to get `304`. There is **no** mandatory `If-Match` on
  writes (single-user server, no concurrent-writer contention).
* **Rate limits:** per-IP token bucket; `429` carries `Retry-After` and
  `RateLimit-*` headers.
* **Body limits:** 64 KiB JSON by default, 2 MiB for avatar uploads → `413`.
* **Caching:** authenticated responses are `no-store`; public reads are
  `public, max-age=60`. All responses set `X-Content-Type-Options: nosniff`
  and `Vary: Origin, Authorization, Cookie`.
* **CORS:** denied by default; allowlisted only via `api.cors_origins`
  config. Never `*` alongside credentials.

## Errors

Every non-2xx response is an RFC 9457 problem document:

```json
{
  "type": "https://<domain>/problems/validation-failed",
  "title": "Validation Failed",
  "status": 422,
  "detail": "request body failed validation",
  "instance": "/api/v1/me/profile",
  "errors": [
    { "field": "bio", "code": "too_long", "detail": "bio exceeds 500 characters" }
  ]
}
```

| Problem type | Status | When |
|:-------------|:-------|:-----|
| `invalid-request` | 400 | Malformed request, ambiguous credentials (bearer + cookie), bad body |
| `validation-failed` | 422 | Field-level validation errors (`errors[]` of `{field, code, detail}`) |
| `unauthenticated` | 401 | Missing or invalid credential |
| `insufficient-scope` | 403 | Valid credential lacking the required scope |
| `forbidden` | 403 | Authenticated principal denied (e.g. non-admin on an `admin:*` route) |
| `not-found` | 404 | Missing resource — also used for cross-tenant resources (no enumeration oracle) |
| `conflict` | 409 | State conflict (duplicate, last passkey, used invite token) |
| `precondition-required` | 428 | Missing required precondition |
| `precondition-failed` | 412 | Stale precondition |
| `payload-too-large` | 413 | Body exceeds the per-route limit |
| `rate-limited` | 429 | Per-IP rate limit exceeded (`Retry-After` header set) |
| `not-implemented` | 501 | Recognized but not yet implemented |
| `internal` | 500 | Unexpected server failure |

## Meta & health (anonymous)

| Method | Path | Purpose |
|:-------|:-----|:--------|
| `GET` | `/api/v1/meta/capabilities` | Machine-readable wired features (`Capabilities` object) |
| `GET` | `/api/v1/meta/version` | Build version (`{"version": "..."}`) |
| `GET` | `/api/v1/health` | Liveness probe (`{"status": "ok"|"degraded"}`) |
| `GET` | `/api/v1/ready` | Readiness probe (`{"status": "ok"|"degraded"}`) |
| `GET` | `/api/v1/openapi.json` | The embedded OpenAPI 3.1 spec |

```bash
curl https://id.example.com/api/v1/meta/capabilities
curl https://id.example.com/api/v1/health
```

## Auth & sessions

| Method | Path | Auth | Purpose |
|:-------|:-----|:-----|:--------|
| `POST` | `/api/v1/auth/invite/redeem` | bearer (invite token in body) | Exchange a one-time invite token for a session. **Idempotency-Key required.** |
| `GET` | `/api/v1/auth/session` | bearer or cookie · `self` | Current principal, tenant, scopes, onboarding state |
| `DELETE` | `/api/v1/auth/session` | bearer or cookie · `self` | Revoke the current session |
| `POST` | `/api/v1/auth/session/refresh` | bearer or cookie · `self` | Sliding renewal of the current session |
| `POST` | `/api/v1/auth/webauthn/register/begin` | bearer or cookie · `self` | Begin passkey registration (session-derived user) |
| `POST` | `/api/v1/auth/webauthn/register/finish` | bearer or cookie · `self` | Finish passkey registration |
| `POST` | `/api/v1/auth/webauthn/login/begin` | anonymous | Begin passkey login (uniform response for unknown handles) |
| `POST` | `/api/v1/auth/webauthn/login/finish` | anonymous | Finish passkey login → session |
| `GET` | `/invite/{token}` | anonymous (browser) | Redeem a magic link into a session cookie, `303` → `/panel` |

`POST /auth/invite/redeem` is the programmatic counterpart of the browser
magic link: it takes `{"token": "..."}` and returns a `Session`. The browser
entry point `GET /invite/{token}` is **anonymous** (exempt from the authn
middleware), mints a server-side session cookie, and redirects to the panel;
the token-in-URL Referer/access-log leak is acknowledged under the project's
PII discipline.

```bash
curl -X POST https://id.example.com/api/v1/auth/invite/redeem \
  -H "Authorization: Bearer <invite-token>" \
  -H "Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{"token": "<invite-token>"}'
```

## Self — `/me/*`

All self routes accept bearer or cookie auth and require the listed scope.
`GET` routes time out at 5 s; mutations at 10 s.

| Method | Path | Scope | Purpose |
|:-------|:-----|:------|:--------|
| `GET` | `/me` | `self:read` | Current principal identity |
| `PATCH` | `/me` | `self:write` | Update display name / email |
| `DELETE` | `/me` | `account:delete` | **Request** account deletion (admin approval follows; `202`) |
| `GET` | `/me/onboarding` | `self:read` | Onboarding state (`tos_accepted`, `has_passkey`, `has_profile`, `complete`) |
| `POST` | `/me/tos` | `self:write` | Accept the Terms of Service |
| `GET` | `/me/export` | `export:read` | Full data export (user, profile, links, keys, proofs) |
| `GET` | `/me/profile` | `profile:read` | Your profile page |
| `PUT` | `/me/profile` | `profile:write` | Create or fully replace the profile page |
| `DELETE` | `/me/profile` | `profile:write` | Delete the profile page (cascades to links) |
| `POST` | `/me/profile:publish` | `profile:publish` | Publish the profile page |
| `POST` | `/me/profile:unpublish` | `profile:publish` | Unpublish the profile page |
| `PUT` | `/me/profile/avatar` | `profile:write` | Upload avatar (`multipart/form-data`, 2 MiB limit) |
| `GET` | `/me/profile/links` | `profile:read` | List profile links in display order |
| `POST` | `/me/profile/links` | `profile:write` | Add a profile link |
| `PATCH` | `/me/profile/links/{id}` | `profile:write` | Update a profile link |
| `DELETE` | `/me/profile/links/{id}` | `profile:write` | Delete a profile link |
| `POST` | `/me/profile/links:reorder` | `profile:write` | Reorder profile links (`{"ids": [...]}`) |
| `GET` | `/me/keys` | `keys:read` | List your public keys |
| `POST` | `/me/keys` | `keys:write` | Register a public key (SSH/PGP; private-key material rejected) |
| `GET` | `/me/keys/{id}` | `keys:read` | Get one public key |
| `DELETE` | `/me/keys/{id}` | `keys:write` | Delete a public key |
| `POST` | `/me/keys/{id}/revoke` | `keys:write` | Revoke a public key |
| `GET` | `/me/proofs` | `proofs:read` | List your proof claims |
| `POST` | `/me/proofs` | `proofs:write` | Create a proof claim |
| `GET` | `/me/proofs/{id}` | `proofs:read` | Get one proof claim |
| `DELETE` | `/me/proofs/{id}` | `proofs:write` | Delete a proof claim |
| `POST` | `/me/proofs/{id}/verify` | `proofs:verify` | Run Keyoxide-style verification (SSRF-guarded) |
| `GET` | `/me/sessions` | `sessions:read` | List your active sessions |
| `DELETE` | `/me/sessions/{id}` | `sessions:revoke` | Revoke one session |
| `DELETE` | `/me/sessions` | `sessions:revoke` | Revoke all of your sessions |
| `GET` | `/me/tokens` | `tokens:read` | List programmatic API tokens (metadata only) |
| `POST` | `/me/tokens` | `tokens:write` | Create a programmatic token — **show-once**: the raw token is returned exactly once |
| `DELETE` | `/me/tokens/{family_id}` | `tokens:revoke` | Revoke a token family |
| `GET` | `/me/credentials` | `credentials:read` | List your WebAuthn credentials (no key material) |
| `DELETE` | `/me/credentials/{id}` | `credentials:write` | Delete a passkey (`409` when it is the last one) |

```bash
# Create a programmatic token (show-once — capture the raw value).
curl -X POST https://id.example.com/api/v1/me/tokens \
  -H "Authorization: Bearer <session-or-token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "ci", "scopes": ["self:read", "profile:read"]}'
```

## Admin — `/admin/*`

All admin routes accept bearer or cookie auth, require an `admin:*` scope
**and** `IsAdmin` on the user record (belt and braces). Non-admins get `403`.
Lists use `?limit=1..200&offset=` and return the envelope
`{"data": [...], "offset": N, "limit": N, "total": N}`.

### Tenants

| Method | Path | Scope | Purpose |
|:-------|:-----|:------|:--------|
| `GET` | `/admin/tenants` | `admin:tenants:read` | List tenants (paged) |
| `POST` | `/admin/tenants` | `admin:tenants:write` | Create a tenant |
| `GET` | `/admin/tenants/{id}` | `admin:tenants:read` | Get a tenant |
| `DELETE` | `/admin/tenants/{id}` | `admin:tenants:write` | Delete a tenant |

### Users & invites

| Method | Path | Scope | Purpose |
|:-------|:-----|:------|:--------|
| `GET` | `/admin/users` | `admin:users:read` | List all users across tenants (paged) |
| `POST` | `/admin/users` | `admin:users:write` | Create a user and send an invite. **Idempotency-Key required** (one email). |
| `GET` | `/admin/users/{id}` | `admin:users:read` | Get a user |
| `PATCH` | `/admin/users/{id}` | `admin:users:write` | Update a user (admin flag, email, display name) |
| `DELETE` | `/admin/users/{id}` | `admin:users:write` | Delete a user and all data |
| `POST` | `/admin/users/{id}/invites` | `admin:users:write` | Create and send an invite. **Idempotency-Key required.** |
| `GET` | `/admin/users/{id}/credentials` | `admin:users:read` | List a user's passkeys |
| `POST` | `/admin/users/{id}/sessions:revoke` | `admin:users:write` | Revoke all sessions for a user |

### OIDC clients

| Method | Path | Scope | Purpose |
|:-------|:-----|:------|:--------|
| `GET` | `/admin/clients` | `admin:clients:read` | List OIDC clients |
| `POST` | `/admin/clients` | `admin:clients:write` | Create a client — secret is **show-once** |
| `GET` | `/admin/clients/{id}` | `admin:clients:read` | Get a client |
| `DELETE` | `/admin/clients/{id}` | `admin:clients:write` | Delete a client |
| `POST` | `/admin/clients/{id}/secret/rotate` | `admin:clients:write` | Rotate the client secret — **show-once** |

### Backups

| Method | Path | Scope | Purpose |
|:-------|:-----|:------|:--------|
| `GET` | `/admin/backup/config` | `admin:backup:read` | Get backup config |
| `PUT` | `/admin/backup/config` | `admin:backup:write` | Update backup config (persists, drives the scheduler) |
| `GET` | `/admin/backup/runs` | `admin:backup:read` | List backup runs (paged) |
| `POST` | `/admin/backup/runs` | `admin:backup:write` | Trigger a run. **Idempotency-Key required.** Long-running. |
| `GET` | `/admin/backup/runs/{id}` | `admin:backup:read` | Get a run |
| `GET` | `/admin/backup/restores` | `admin:backup:read` | List restores (paged) |
| `POST` | `/admin/backup/restores` | `admin:backup:write` | Trigger a restore (`{"source_key": "...", "confirm": true}`). **Idempotency-Key required.** Long-running. |

### Moderation

| Method | Path | Scope | Purpose |
|:-------|:-----|:------|:--------|
| `GET` | `/admin/moderation/takedowns` | `admin:moderation:read` | List takedowns (paged) |
| `POST` | `/admin/moderation/takedowns` | `admin:moderation:write` | Create a takedown |
| `GET` | `/admin/moderation/takedowns/{id}` | `admin:moderation:read` | Get a takedown |
| `DELETE` | `/admin/moderation/takedowns/{id}` | `admin:moderation:write` | Lift a takedown |

### Audit

| Method | Path | Scope | Purpose |
|:-------|:-----|:------|:--------|
| `GET` | `/admin/audit` | `admin:audit:read` | Instance audit log (paged; real `actor` field) |

### Deletion requests

| Method | Path | Scope | Purpose |
|:-------|:-----|:------|:--------|
| `GET` | `/admin/deletion-requests` | `admin:users:read` | List pending deletion requests (paged) |
| `POST` | `/admin/deletion-requests/{id}/approve` | `admin:users:write` | Approve — cascades the deletion |
| `POST` | `/admin/deletion-requests/{id}/reject` | `admin:users:write` | Reject — no-op |

### IPFS pins

| Method | Path | Scope | Purpose |
|:-------|:-----|:------|:--------|
| `GET` | `/admin/ipfs/pins` | `admin:ipfs:read` | List pinned CIDs |
| `POST` | `/admin/ipfs/pins` | `admin:ipfs:write` | Add a pin by CID (non-panicking CID validation; **no** Idempotency-Key) |
| `GET` | `/admin/ipfs/pins/{cid}` | `admin:ipfs:read` | Get pin status |

### Terms of Service & system

| Method | Path | Scope | Purpose |
|:-------|:-----|:------|:--------|
| `GET` | `/admin/tos` | `admin:system:read` | Latest ToS document |
| `PUT` | `/admin/tos` | `admin:system:write` | Publish a new ToS version |
| `GET` | `/admin/system/info` | `admin:system:read` | Config summary (secrets redacted), wired features, scheduler status |

## Public mirrors — `/api/v1/public/*`

Anonymous, tenant-scoped mirrors of the public data-plane surfaces. They
resolve the tenant from the request host.

| Method | Path | Purpose |
|:-------|:-----|:--------|
| `GET` | `/api/v1/public/profile` | Published profile page (`404` when unpublished — no enumeration) |
| `GET` | `/api/v1/public/keys` | Active public keys (revoked keys excluded) |
| `GET` | `/api/v1/public/proofs` | Verified proof claims (pending/failed excluded) |

## Idempotency

`Idempotency-Key` is **required** on POSTs with genuine external side
effects: `POST /auth/invite/redeem`, `POST /admin/users`,
`POST /admin/users/{id}/invites`, `POST /admin/backup/runs`,
`POST /admin/backup/restores`. Keys are retained for 24 h; a replay with the
same key returns the original response, and the side effect (e.g. the invite
email) runs only on first execution. IPFS pinning is a natural no-op and
carries no key.

```bash
curl -X POST https://id.example.com/api/v1/admin/backup/runs \
  -H "Authorization: Bearer <admin-token>" \
  -H "Idempotency-Key: $(uuidgen)"
```

## See also

* [Developer how-to: calling the API](../../howto/developer/api.md) — worked
  examples with `curl` and the shared `api.js` client.
* [User how-to: the panel](../../howto/user/panel.md) and
  [Admin how-to: the console](../../howto/admin/console.md).
* [ADR 0003](../../explanation/design-decisions/0003-identity-host-control-plane.md) ·
  [ADR 0005](../../explanation/design-decisions/0005-rfc9457-problem-details.md) ·
  [ADR 0007](../../explanation/design-decisions/0007-openapi-source-of-truth.md) ·
  [ADR 0008](../../explanation/design-decisions/0008-browser-programmatic-auth-split.md) ·
  [ADR 0010](../../explanation/design-decisions/0010-audience-separation.md).
