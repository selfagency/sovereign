# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Pre-1.0 notice.** Sovereign is in early development (`0.x`). Breaking
> changes may ship in any minor release. Each breaking change is called out
> explicitly under **Changed** with a migration note.

## [Unreleased]

### Added

* Documentation site (Hugo + Geekdoc) under `docs/`, with a
  documentation-as-code CI gate (`task docs-verify`) that lints Markdown,
  checks links, builds the site, and verifies that every capability the
  README marks "Shipped" has a live route and a backing test.
* Root `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, and this changelog.
* **Control-plane REST API (`/api/v1`)** on the identity host
  (`https://id.<domain>/api/v1`): meta/health, auth & sessions, self
  (`/me/*`), instance-admin (`/admin/*`), and public mirrors
  (`/api/v1/public/*`). Hand-written OpenAPI 3.1 spec
  (`openapi/sovereign.v1.yaml`) is the source of truth, enforced by a
  bidirectional drift test. See the
  [API reference](docs/reference/api/control-plane.md).
* **Thin clients:** the user panel (`internal/web/panel`) and the admin
  console (`internal/web/admin`) are static clients over the API, sharing
  `internal/web/shared/api.js`, with vendored `simple.css` and a strict CSP
  (no external origins, no inline scripts).
* **No-JS fallback** (`internal/legacyforms`): ToS acceptance and profile
  editing work without JavaScript via form-POST adapters with a hidden
  `csrf_token` field.
* **Programmatic API tokens:** `POST /api/v1/me/tokens` issues bearer tokens
  with a scope subset; the raw token is **show-once** (returned exactly
  once).
* **Deletion-request flow:** `DELETE /api/v1/me` now creates a pending
  deletion request (`202`); admins approve or reject it via
  `POST /api/v1/admin/deletion-requests/{id}/approve|reject`.
* **Anonymous session-mint:** `GET /invite/{token}` redeems a magic link
  into a server-side session cookie and redirects to the panel.
* **Docs:** control-plane API reference, user/admin/developer how-tos, and
  ADRs D-1..D-9 (see the
  [design-decisions index](docs/explanation/design-decisions/_index.md)).

### Changed

* **Capability status (truthful docs):** the README capability table now
  distinguishes **Shipped** (implemented, wired into the running server, and
  covered by a backing test) from **Not wired** (package-complete and
  unit-tested in isolation, but not mounted on the live server). The following
  are **not** wired and must not be relied on over HTTP: `internal/setup`
  (first-run setup), `internal/licenses` (license reporting), `internal/keys`
  (key parsing/fingerprinting), `internal/protocols/chatfederation` (Matrix/
  XMPP localpart normalization), ActivityPub HTTP-signature verification,
  `solid.WACChecker` (Web Access Control is not enforced), `backup.Scheduler` +
  destinations (scheduled backup/restore), `ipfspin.NewPSAClient`
  (pinning-service API mode), and `moderation.ToSGate` (ToS enforcement). The
  atproto PDS is mounted at `/xrpc/` but with a nil Backend/RepoFactory/
  SigningKey, so it is non-functional as wired. The admin backup config form
  (`/admin/backup`) is mounted but its Apply callback is a no-op.
* **BREAKING (project identity):** renamed the project from
  `hypernext-identity` to **Sovereign**. Module path is
  `github.com/selfagency/sovereign`; binary is `cmd/sovereign`.
* **BREAKING (configuration):** the environment-variable prefix is now
  `SOVEREIGN_` (e.g. `SOVEREIGN_STORAGE_BACKEND`), and the config file flag
  is `SOVEREIGN_CONFIG` / `--config`. Update any deployment environment
  accordingly. See [Environment variable reference](docs/reference/environment.md).
* **BREAKING (strict config):** startup now fails on unknown or removed
  config keys. Operators MUST remove the following keys from `config.yml`
  (or startup aborts):
  * `identity_host`
  * `sqlite.mode` and `sqlite.single.path` (the whole `sqlite:` block)
  * `tls.*` (all keys under `tls:`)
  * `atproto.*` (all keys under `atproto:`)
  * `backup.*` (all keys under `backup:`)
  `ipfs.enabled` remains a valid key and is wired (gates the admin
  `/ipfs/pin` broker); do not remove it.
* **BREAKING (client-secret invalidation):** all existing plaintext client
  secrets are invalidated on upgrade. Operators MUST re-register each
  affected client via `sovereign clients set-secret <id>` (prints a new
  secret once — capture it). Affected client IDs are logged at WARN during
  migration.
* **Refresh-token grace:** existing refresh tokens survive the upgrade
  (grace). New tokens carry a 30-day expiry and rotation/reuse detection.
  No operator action is required for existing sessions. Clients MUST use
  single-flight refresh semantics (one in-flight refresh per token; retry
  only on a confirmed network error). Family revocation on reuse is
  intended (RFC 9700).
* **BREAKING (strict config additions):** two new config keys are read and
  validated:
  * `auth.session.dual_read` (bool, default `true`) — accept both legacy
    JWT session cookies and new server-side session rows during the
    migration window. An explicit `false` is preserved; only the absent key
    defaults to `true`.
  * `api.cors_origins` (list of strings, default empty) — CORS allowlist
    for cross-origin browser access to the API. Deny-by-default; never `*`
    alongside credentials.
  Unknown keys still abort startup; add these keys to `config.yml` as
  needed (see the [configuration reference](docs/reference/configuration.md)).
* **BREAKING (session dual-read window):** the session cookie (name
  `session`) is now format-sniffed: legacy JWT cookies are accepted only
  while `auth.session.dual_read` is `true`, and a request carrying both the
  JWT and opaque shapes is rejected (`400`). **Operator migration:** keep
  `auth.session.dual_read: true` for one release so existing sessions
  survive, then flip it to `false` and drop the old JWT cookies. After the
  flip, legacy JWT cookies are rejected.
* **BREAKING (audience separation, D-8):** bearer tokens on `/api/v1` must
  carry the `sovereign-api` audience. Tokens minted for data-plane
  audiences (`sovereign-rs`, `sovereign-solid`, `sovereign-atproto`) are
  rejected on the control plane. Re-issue any programmatic token that was
  minted without the control-plane audience.
* **BREAKING (CSRF on cookie unsafe methods):** cookie-authenticated
  POST/PUT/PATCH/DELETE requests must send the double-submit token from the
  `__Host-csrf` cookie in the `X-CSRF-Token` header (or the hidden
  `csrf_token` field for `application/x-www-form-urlencoded` no-JS forms).
  Bearer (programmatic) requests are exempt. Scripted clients that used the
  session cookie must switch to bearer auth or send the CSRF header.
* **BREAKING (invite redemption):** `GET /invite/{token}` now mints a
  server-side session cookie (opaque, revocable) instead of a JWT cookie.
  The token is single-use and persisted only as a hash; token-in-URL
  Referer/access-log leaks are acknowledged under the project's PII
  discipline.
* **BREAKING (decommissioned HTTP layers):** the server-rendered panel
  templates (`internal/server/panel.go`) and the admin HTML handlers
  (`internal/admin/users.go`, `internal/admin/backup.go`) are removed.
  `/panel` and `/admin/*` are now thin static clients over `/api/v1` (plus
  the no-JS `legacyforms` fallback for ToS and profile). Any script that
  scraped the old HTML forms must call the API instead.
* **BREAKING (account deletion):** `DELETE /api/v1/me` no longer deletes
  immediately — it creates a pending deletion request that an instance
  admin must approve. Approving cascades the deletion; rejecting is a
  no-op.

### Fixed

* Race in the in-memory auth store (`auth.MemoryStore`) — now concurrency-safe
  and covered by race tests.
* Refresh tokens are stored hashed; access tokens are signed and short-lived.
* Versioned SQLite schema migrations and the `accounts` table.
* Tenant storage is prefix-isolated with path-traversal rejection.
* Ownership-based ACLs for tenant resources.

## Release notes

Release notes for each tagged version are published on the
[GitHub releases page](https://github.com/selfagency/sovereign/releases).

[Unreleased]: https://github.com/selfagency/sovereign/compare/HEAD
