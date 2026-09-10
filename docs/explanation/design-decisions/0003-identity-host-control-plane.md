---
title: "ADR 0003: Control plane lives only on the identity host"
weight: 3
---

# ADR 0003: Control plane lives only on the identity host

* **Status:** Accepted
* **Date:** 2026-09
* **Reference:** [REST plan D-1](../../plan/20260828-rest-api/context_envelope.json) — implemented in `internal/api/router.go` and the server assembly in `internal/server/server.go`.

## Context

Sovereign is multi-tenant: many tenants (handles like `alice.example.com`)
share one server, and the data-plane routes (`/rs/`, `/solid/`, `/xrpc/`,
`/.well-known/*`, `/profile/`) resolve the tenant from the request `Host`.
The control plane — identity, profile, keys, proofs, sessions, tokens, and
the admin surface — must not inherit that model: deriving the tenant from
`Host` or a body field is spoofable and ambiguous, and mounting the same
control plane on every tenant subdomain would multiply the attack surface and
leak tenant existence.

The identity host (`id.<domain>`) already hosts the OIDC provider and
WebAuthn endpoints, so it is the natural home for the control plane.

## Decision

The control-plane REST API (`/api/v1`) is mounted **only on the identity
host** (`https://id.<domain>/api/v1`). The tenant is derived from the
authenticated principal, never from the `Host` header or a body field.
Anonymous public mirrors (`/api/v1/public/*`) resolve the tenant from the
request host, exactly like the data-plane routes.

## Alternatives considered

* **Mount the API on every tenant subdomain** — rejected: duplicates the
  surface, makes tenant-from-Host ambiguity a security property, and leaks
  tenant existence on unauthenticated routes.
* **Derive the tenant from a body field** — rejected: client-supplied
  tenant/account IDs are untrusted until checked against the authenticated
  principal (see `AGENTS.md` "Tenant-scoping").

## Consequences

* **Good:** one authoritative control-plane surface; tenant isolation is a
  property of the authenticated principal, not of routing; the identity host
  already carries the auth infrastructure the API needs.
* **Cost:** the API is unreachable on tenant subdomains by design; a
  programmatic client must always target `id.<domain>`.
* **Rule for contributors:** no `/api/v1` route may derive the tenant from
  `Host` or a request body field; tenant-scoped handlers must use the
  authenticated principal.
