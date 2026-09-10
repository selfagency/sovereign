---
title: "ADR 0005: RFC 9457 problem+json errors"
weight: 5
---

# ADR 0005: RFC 9457 problem+json errors

* **Status:** Accepted
* **Date:** 2026-09
* **Reference:** [REST plan D-3](../../plan/20260828-rest-api/context_envelope.json) — implemented in `internal/api/problem/problem.go`.

## Context

The control plane needs one error contract that is machine-readable (clients
can branch on it), stable across versions (URIs do not change), and
consistent with the project's fail-closed posture. Ad-hoc plain-text or
ad-hoc JSON error bodies drift between handlers and force clients to
string-match.

## Decision

Every non-2xx response is an RFC 9457 Problem Details document
(`application/problem+json`) with a stable `type` URI under
`https://<domain>/problems/`, a `title`, `status`, optional `detail` and
`instance`, and an `errors[]` array of `{field, code, detail}` on
`validation-failed` (422). The registry lives in `internal/api/problem` and
is the only place problems are constructed. Status discipline: never `500`
for a client error; `403` for scope/role failure; `404` (not `403`) for
cross-tenant resources so the API is not a tenant-enumeration oracle.

## Alternatives considered

* **Plain-text error bodies** — rejected: not machine-readable, no stable
  type identity.
* **A bespoke JSON error envelope** — rejected: reinventing RFC 9457 with no
  ecosystem tooling.

## Consequences

* **Good:** one typed, version-stable error contract; `errors[]` gives
  field-level validation feedback; `instance` carries the request ID for
  log correlation.
* **Cost:** clients must parse `application/problem+json`; the `type` URI
  domain is substituted at deployment.
* **Rule for contributors:** handlers never write ad-hoc error bodies; they
  return a `*problem.Problem` from the registry, and the problem+json mapper
  in the middleware chain serializes it.
