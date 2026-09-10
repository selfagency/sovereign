---
title: "ADR 0004: Stdlib routing with Go 1.22+ ServeMux patterns"
weight: 4
---

# ADR 0004: Stdlib routing with Go 1.22+ ServeMux patterns

* **Status:** Accepted
* **Date:** 2026-09
* **Reference:** [REST plan D-2](../../plan/20260828-rest-api/context_envelope.json) — implemented in `internal/api/router.go` (`mux.HandleFunc(r.Method+" "+r.Path, ...)`).

## Context

The control plane has a fixed, table-driven route set (~60 endpoints) with
per-route scope and timeout metadata. The project's dependency discipline
(see [ADR 0001](0001-single-binary-sqlite.md)) favors the standard library
where it suffices, and Go 1.22+ `net/http.ServeMux` supports method patterns
(`"GET /path"`) and `{wildcard}` path parameters natively.

## Decision

Routing uses the stdlib `net/http.ServeMux` with Go 1.22+ method patterns.
The route table in `internal/api/router.go` is the single source of truth:
each `Route` declares method, path, required scope, per-route timeout, and
flags (anonymous, long-running, idempotent), and the mux is built from it.
No router framework is used.

## Alternatives considered

* **A router framework (chi, gorilla/mux)** — rejected: a dependency for a
  need the stdlib now covers; the route table already carries the metadata a
  framework would add.
* **A hand-rolled router** — rejected: reinventing `ServeMux` for no benefit.

## Consequences

* **Good:** zero routing dependencies; method + wildcard patterns are
  first-class; the route table doubles as the middleware's route metadata
  (scope, timeout, idempotency) so the mux and the middleware can never
  diverge.
* **Cost:** no framework middleware chaining sugar — the middleware chain is
  hand-assembled in `internal/api/middleware/chain.go`.
* **Rule for contributors:** no router framework dependency is added; new
  endpoints are rows in the route table, not ad-hoc `HandleFunc` calls.
