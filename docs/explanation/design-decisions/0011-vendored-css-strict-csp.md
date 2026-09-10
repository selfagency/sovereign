---
title: "ADR 0011: Vendored CSS and a strict CSP"
weight: 11
---

# ADR 0011: Vendored CSS and a strict CSP

* **Status:** Accepted
* **Date:** 2026-09
* **Reference:** [REST plan D-9](../../plan/20260828-rest-api/context_envelope.json) — implemented in `internal/web/embed.go` and `internal/web/shared/simple.css`.

## Context

The thin clients (`web/panel`, `web/admin`) are served by the same binary
that serves the API. Loading styles or scripts from a CDN would (a) add an
external origin the server does not control, (b) force a CSP exception, and
(c) break the fully self-contained, offline-capable deployment story
([ADR 0001](0001-single-binary-sqlite.md)). The project also has no JS build
toolchain, so the CSS must be committed, not compiled.

## Decision

The `simple.css` stylesheet is **vendored** into the repo
(`internal/web/shared/simple.css`) and embedded via `go:embed`. The thin
clients are served with a **strict CSP**: `default-src 'none'`;
`script-src 'self'`; `connect-src 'self'`; no external origins; no inline
`<script>` — every script is an external ES module served by the server's
embedded asset handler.

## Alternatives considered

* **CDN-hosted CSS** — rejected: external origin, CSP hole, offline breakage.
* **Inline styles/scripts** — rejected: violates the strict CSP and the
  no-inline-script rule.
* **A CSS build step** — rejected: adds a toolchain the project explicitly
  excludes.

## Consequences

* **Good:** no external origins anywhere in the page; a strong, testable CSP;
  the binary stays self-contained; CSS updates are ordinary repo changes.
* **Cost:** CSS is vendored and must be updated in-repo; the CSP forbids
  inline scripts, so all client code must be external modules.
* **Rule for contributors:** the CSP never allows external origins; no inline
  `<script>`; new client assets are embedded via `go:embed` and served by the
  asset handler.
