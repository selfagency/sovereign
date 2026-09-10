---
title: "ADR 0008: Browser and programmatic auth are separate (cookie vs bearer)"
weight: 8
---

# ADR 0008: Browser and programmatic auth are separate (cookie vs bearer)

* **Status:** Accepted
* **Date:** 2026-09
* **Reference:** [REST plan D-6](../../plan/20260828-rest-api/context_envelope.json) — implemented in `internal/api/middleware/authn.go` and `internal/api/middleware/csrf.go`.

## Context

The control plane serves two very different clients. A browser needs a
session it cannot exfiltrate (HttpOnly cookie) and CSRF protection on
state-changing requests. A script or integration needs a credential it can
store and send in an `Authorization` header, without CSRF ceremony. Mixing
the two weakens both: cookie auth on scripts forces CSRF on non-browser
clients, and bearer auth in a browser invites token theft from JS.

## Decision

Authentication is split by client type and is **mutually exclusive per
request**:

* **Browser:** an HttpOnly `session` cookie (opaque server-side session row,
  with a config-gated dual-read window for legacy JWT cookies) plus
  double-submit CSRF (`__Host-csrf` cookie echoed in `X-CSRF-Token`) and
  `Origin`/`Sec-Fetch-Site` enforcement on unsafe methods.
* **Programmatic:** `Authorization: Bearer <token>` only. Bearer requests are
  exempt from CSRF.
* A request carrying **both** a bearer header and a session cookie is
  rejected with `400` — never guessed.

## Alternatives considered

* **Cookie auth for everything** — rejected: forces CSRF on scripted
  clients and leaks the session to any JS on the page.
* **Bearer auth for everything** — rejected: no browser session UX, and a
  bearer token in a cookie or `localStorage` is a theft target.

## Consequences

* **Good:** each path is hardened for its threat model; CSRF applies only
  where it is needed; the `400` on mixed credentials removes ambiguity.
* **Cost:** clients must pick one credential type and stick to it; the
  browser path carries CSRF ceremony.
* **Rule for contributors:** bearer + cookie together is always `400`; CSRF
  is enforced only for cookie principals on unsafe methods; bearer tokens
  never bypass scope authorization.
