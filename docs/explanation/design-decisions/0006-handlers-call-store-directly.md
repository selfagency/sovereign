---
title: "ADR 0006: Handlers call the store directly (revised — no core/* layer)"
weight: 6
---

# ADR 0006: Handlers call the store directly (revised — no `core/*` layer)

* **Status:** Accepted (revises the earlier plan for an `internal/core/*`
  service layer)
* **Date:** 2026-09
* **Reference:** [REST plan D-4 (REVISED)](../../plan/20260828-rest-api/context_envelope.json) — implemented across `internal/api/v1/*` and `internal/store`.

## Context

The original REST plan proposed an `internal/core/*` layer between HTTP
handlers and the store. Review (C1) found it was indirection without a
benefit: the store already owns persistence and business logic, and a
parallel service layer would duplicate it, dilute coverage, and add a place
for logic to drift. The project's coverage gate (80% aggregate, store ≥90%)
concentrates coverage where the logic lives.

## Decision

Handlers call the store **directly**: parse the request → call the store →
encode the response. There is **no** `internal/core/*` layer. The store is
`net/http`-free. Thin orchestration exists **only** where a handler must
coordinate across stores or subsystems: backup config → scheduler, proof
verification wiring, and capabilities derivation.

### Adopted simplifications (C1–C6)

| # | Simplification | Effect |
|:--|:---------------|:-------|
| C1 | Drop `core/*` | Handlers call the store directly; no service layer. |
| C2 | Coarse scopes | `self`, `profile`, `keys`, `proofs`, `sessions`, `tokens`, `credentials`, `export`, `account`, and `admin:*` (tenants/users/clients/backup/moderation/audit/ipfs/system); read/write implied by a small explicit `scopeImplies` table (e.g. `profile:write` implies `profile:read`). |
| C3 | No `If-Match` | ETag on GET only; no mandatory `If-Match` on PUT/PATCH/DELETE (single-user server, no concurrent-writer contention). |
| C4 | Offset/limit admin lists | Admin lists paginate with `?limit=&offset=` and return `{"data": [...], "offset", "limit", "total"}`; only the genuinely unbounded audit log uses an opaque cursor. |
| C5 | Per-IP rate limit | Token bucket keyed by IP only; no per-principal buckets. |
| C6 | No IPFS idempotency | IPFS pinning is a natural no-op; no `Idempotency-Key` on pin routes. |

## Alternatives considered

* **`internal/core/*` service layer** — rejected: duplicated store logic,
  diluted coverage, extra indirection (C1).
* **Fat handlers with business logic inline** — rejected: business logic in
  HTTP code is untestable without a server and violates the thin-handler
  rule.

## Consequences

* **Good:** coverage concentrates in `internal/store`; handlers are thin
  (parse → call → encode) and cheap to test; cross-store orchestration is
  explicit and lives in `internal/wiring` and the few adapters that need it.
* **Cost:** any logic that spans stores must be placed deliberately (in the
  store or a wiring adapter), not assumed to exist in a service layer.
* **Rule for contributors:** the store stays `net/http`-free; handlers stay
  thin; do not reintroduce a service layer without a demonstrated need.
