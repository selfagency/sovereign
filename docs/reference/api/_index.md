---
title: "HTTP API"
weight: 40
---

# HTTP API reference

Sovereign's HTTP surface. This section documents **only the live, mounted
routes** — the protocol prefixes wired in `internal/server/server.go` plus
the identity-host endpoints (OIDC, WebAuthn, admin). Endpoints that exist as
Go packages but are not mounted (IndieAuth) are **not** documented here as if
they were callable; they are listed on the
[status page](../../explanation/status.md).

All tenant-scoped routes pass through tenant middleware: the request `Host`
resolves to a tenant, and the tenant's storage is prefix-isolated. Unknown
hosts are rejected.

## Live routes

| Prefix | Protocol / purpose | Auth | Detail |
|:-------|:-------------------|:-----|:-------|
| `/rs/` | remoteStorage read/write | bearer token | [remotestorage](remotestorage.md) |
| `/solid/` | Solid LDP + WebID + ACL | token (subject) | [solid](solid.md) |
| `/xrpc/` | atproto XRPC reads | varies | [atproto](atproto.md) |
| `/.well-known/webfinger` | WebFinger lookup | none | [discovery](discovery.md) |
| `/.well-known/nodeinfo` | NodeInfo advertisement | none | [discovery](discovery.md) |
| `/profile/` | content-negotiated profile | none | [discovery](discovery.md) |
| `/keys` | public SSH/PGP keys | none | [keys-and-proofs](keys-and-proofs.md) |
| `/.well-known/openpgpkey/` | OpenPGP WKD lookup | none | [keys-and-proofs](keys-and-proofs.md) |
| `/.well-known/proofs` | Keyoxide-style identity proofs | none | [keys-and-proofs](keys-and-proofs.md) |
| `/api/v1/` | control plane (identity host only) | bearer or cookie | [control-plane](control-plane.md) |

## Conventions

* **Errors** are returned with a non-2xx status and a short plain-text or
  JSON body. 4xx means the client is wrong (unknown host, bad token, missing
  resource); 5xx means the server is at fault.
* **Tenant isolation:** a request to `alice.example.com` can never read or
  write `bob.example.com` data. This is enforced at the storage layer
  (prefixing) and covered by e2e tests.
* **Content negotiation:** `/profile/` selects a representation from the
  `Accept` header (HTML h-card, ActivityStreams actor, or DID document).

## Identity host (`id.<domain>`)

The identity host serves the OIDC provider, WebAuthn passkey endpoints, the
control-plane REST API, and the admin surface. These are documented on the
[status page](../../explanation/status.md) and in the
[admin how-to](../../howto/admin/_index.md).

| Prefix | Protocol / purpose | Auth |
|:-------|:-------------------|:-----|
| `/.well-known/openid-configuration` | OIDC discovery | none |
| `/authorize`, `/token`, `/userinfo`, `/keys` | OIDC provider | varies |
| `/webauthn/register|login/{begin,finish}` | WebAuthn passkeys | session |
| `/api/v1/` | control-plane REST API | bearer or cookie | [control-plane](control-plane.md) |
| `/panel/`, `/admin/` | thin clients (user panel, admin console) | session cookie |
| `/panel/tos`, `/panel/profile` | no-JS fallback forms | session cookie + CSRF |
| `/admin/moderation/takedown` | legacy moderation route | admin bearer token |
| `/invite/{token}` | magic-link redemption | none (mints session) |

## Not yet mounted

The following are implemented and unit-tested as packages, but have **no
mounted route** and are therefore unreachable over HTTP today. Do not build
against them yet.

| Subsystem | Package | What is missing |
|:----------|:--------|:----------------|
| IndieAuth | `internal/protocols/indieauth` | not wired |

These are documented (with their planned shapes) once they are mounted. See
the [status page](../../explanation/status.md) for the wiring plan.
