---
title: "ADR 0007: OpenAPI spec is the source of truth, enforced by a drift test"
weight: 7
---

# ADR 0007: OpenAPI spec is the source of truth, enforced by a drift test

* **Status:** Accepted
* **Date:** 2026-09
* **Reference:** [REST plan D-5](../../plan/20260828-rest-api/context_envelope.json) — implemented in `openapi/sovereign.v1.yaml` and `internal/api/openapi_drift_test.go`.

## Context

The control plane is a machine contract: clients, the thin clients, and the
documentation all depend on the route set staying stable. Without a check,
the route table in `internal/api/router.go` and the spec
(`openapi/sovereign.v1.yaml`) drift apart silently — endpoints appear in one
and not the other, and the docs lie.

## Decision

The **hand-written OpenAPI 3.1 spec is the source of truth** for the wire
contract. A bidirectional drift test (using `kin-openapi`, a test-only
dependency) asserts route-set ↔ spec parity **both ways**: every route in the
table exists in the spec, and every path/operation in the spec exists in the
route table. The spec is embedded and served at `GET /api/v1/openapi.json`.

## Alternatives considered

* **Generate the spec from Go code** — rejected: loses hand-written
  descriptions and examples; the spec is a documentation artifact, not a
  byproduct.
* **Generate handlers from the spec** — rejected: adds a codegen toolchain
  and fights the direct-to-store handler style ([ADR 0006](0006-handlers-call-store-directly.md)).

## Consequences

* **Good:** the contract is machine-checked in CI; a route added to one side
  without the other fails the build; the served `openapi.json` is always
  current.
* **Cost:** one test-only dependency (`kin-openapi`); every endpoint change
  touches two files.
* **Rule for contributors:** any change to the route table must update
  `openapi/sovereign.v1.yaml` in the same change, and vice versa — the drift
  test enforces it.
