---
title: "ADR 0009: No-JS fallback for ToS and profile (legacyforms)"
weight: 9
---

# ADR 0009: No-JS fallback for ToS and profile (`legacyforms`)

* **Status:** Accepted
* **Date:** 2026-09
* **Reference:** [REST plan D-7](../../plan/20260828-rest-api/context_envelope.json) — implemented in `internal/legacyforms/legacyforms.go`.

## Context

The user panel is a JavaScript thin client, and onboarding (ToS acceptance,
then passkey setup, then profile) is the one flow every user must complete.
A user with JavaScript disabled — assistive tech, hardened browsers, or a
broken script — must still be able to accept the ToS and set a profile, or
they are locked out of their account. WebAuthn passkey registration is
inherently JS-only and is not part of the fallback.

## Decision

`internal/legacyforms` serves plain form-POST adapters over the store at
`/panel/tos` and `/panel/profile` (303-redirect back to `/panel`). Every
rendered form carries a hidden `csrf_token` field whose value matches the
`__Host-csrf` cookie; the CSRF middleware performs the synchronizer-token
check on form-encoded POSTs, and the adapter mints the cookie on GET when it
is absent. WebAuthn stays JS-only.

## Alternatives considered

* **Drop the no-JS path** — rejected: locks out users who cannot run JS;
  ToS acceptance is a legal gate, not an optional feature.
* **Keep the full server-rendered panel** — rejected: defeats the
  thin-client goal and duplicates the whole surface.

## Consequences

* **Good:** onboarding works without JavaScript; the fallback is two small
  templates, not a parallel panel; CSRF protection is preserved through the
  hidden field.
* **Cost:** two server-rendered forms to maintain alongside the thin client;
  the fallback covers only ToS and profile, not keys/proofs/sessions/tokens.
* **Rule for contributors:** no-JS forms must carry the hidden `csrf_token`
  field and be mounted behind the CSRF middleware; WebAuthn remains JS-only.
