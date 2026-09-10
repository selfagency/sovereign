---
title: "ADR 0010: Audience separation per surface (sovereign-api vs data planes)"
weight: 10
---

# ADR 0010: Audience separation per surface (`sovereign-api` vs data planes)

* **Status:** Accepted
* **Date:** 2026-09
* **Reference:** [REST plan D-8](../../plan/20260828-rest-api/context_envelope.json) — implemented in `internal/api/middleware/authn.go` (`apiAudience = "sovereign-api"`).

## Context

One signing key issues access tokens for several HTTP surfaces: the
control-plane REST API, remoteStorage, Solid, and atproto. A token minted
for one surface must not be accepted by another — otherwise a leaked
data-plane token grants control-plane access, and vice versa. The OIDC
clients that mint tokens need a way to declare which surface they target.

## Decision

Each surface has its **own audience**:

| Surface | Audience |
|:--------|:---------|
| Control-plane REST API | `sovereign-api` |
| remoteStorage | `sovereign-rs` |
| Solid | `sovereign-solid` |
| atproto | `sovereign-atproto` |

The control plane validates the `sovereign-api` audience on every bearer
token and rejects tokens carrying any other audience. OIDC clients declare
their audience, so a client configured for a data plane cannot mint
control-plane tokens.

## Alternatives considered

* **One shared audience** — rejected: token confusion across surfaces; a
  token for `/rs/` would work on `/api/v1`.
* **A unique audience per client** — rejected: unmanageable at the
  validation layer; the surface is the right granularity.

## Consequences

* **Good:** token scope is isolated by surface; a leaked data-plane token
  cannot touch the control plane; the audience is machine-checkable.
* **Cost:** a client that needs both surfaces must mint (or hold) tokens for
  each audience; the control plane's audience is fixed, not configurable.
* **Rule for contributors:** the control plane always validates
  `sovereign-api`; new surfaces must mint their own audience rather than
  reuse an existing one.
