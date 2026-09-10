---
title: "Developer how-to"
weight: 30
---

# Developer how-to guides

Guides for people **building on or contributing to** Sovereign. These assume
a Go toolchain and familiarity with the repo conventions in
[AGENTS.md](https://github.com/selfagency/sovereign/blob/main/AGENTS.md).

## Available now

* **[Build, test & extend](build-test-extend.md)** — the contributor workflow:
  `task` checks, the three test tiers, and the honest path from "package
  exists" to "shipped, mounted feature."
* **[Documentation authoring policy](documentation.md)** — the contract for
  doc changes, the Shipped/Partial/Planned labels, and the `docs-verify`
  gates.
* **[Call the REST API](api.md)** — authenticate (bearer vs cookie, CSRF),
  handle problem+json errors, use `Idempotency-Key` and ETags, and reuse the
  shared `api.js` client.

## Reference

* [Configuration](../../reference/configuration.md) ·
  [Environment](../../reference/environment.md) ·
  [CLI](../../reference/cli.md) ·
  [HTTP API](../../reference/api/_index.md)
* [Architecture](../../explanation/architecture.md) and the
  [design decisions](../../explanation/design-decisions/_index.md)

## Planned

| Guide | Lands with |
|:------|:-----------|
| Write a migration | the next accounts/schema change |
| Add a new protocol endpoint | the next wired protocol (see build-test-extend § "Extend") |
