---
title: "Design decisions"
weight: 10
---

# Design decisions

Short Architecture Decision Records (ADRs) for consequential, hard-to-reverse
choices. Each ADR records the context, the decision, the alternatives
considered, and the consequences.

> **Status: scaffold.** ADRs are added as decisions are made and ratified.

## ADR index

| ADR | Title | Status |
|:----|:------|:-------|
| 0001 | [Single Go binary, pure-Go SQLite, no CGO](0001-single-binary-sqlite.md) | Accepted |
| 0002 | [Shared object bucket with tenant prefixes](0002-shared-bucket-tenant-prefixes.md) | Accepted |
| 0003 | [Control plane lives only on the identity host](0003-identity-host-control-plane.md) | Accepted |
| 0004 | [Stdlib routing with Go 1.22+ ServeMux patterns](0004-stdlib-routing.md) | Accepted |
| 0005 | [RFC 9457 problem+json errors](0005-rfc9457-problem-details.md) | Accepted |
| 0006 | [Handlers call the store directly (revised — no core/* layer)](0006-handlers-call-store-directly.md) | Accepted |
| 0007 | [OpenAPI spec is the source of truth, enforced by a drift test](0007-openapi-source-of-truth.md) | Accepted |
| 0008 | [Browser and programmatic auth are separate (cookie vs bearer)](0008-browser-programmatic-auth-split.md) | Accepted |
| 0009 | [No-JS fallback for ToS and profile (legacyforms)](0009-no-js-fallback.md) | Accepted |
| 0010 | [Audience separation per surface (sovereign-api vs data planes)](0010-audience-separation.md) | Accepted |
| 0011 | [Vendored CSS and a strict CSP](0011-vendored-css-strict-csp.md) | Accepted |
