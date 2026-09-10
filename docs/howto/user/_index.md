---
title: "User how-to"
weight: 20
---

# User how-to guides

Guides for people who **have an account** on a Sovereign server run by
someone else.

## Available now

* **[Use the user panel](panel.md)** — sign in with your invite link, accept
  the Terms of Service, register a passkey, and manage your profile, keys,
  proofs, passkeys, sessions, tokens, export, and deletion request.

> The panel is a thin client over the
> [control-plane API](../../reference/api/control-plane.md), served at
> `https://id.<domain>/panel`. Sign-in is live on the identity host (see the
> [status page](../../explanation/status.md)).

## Available without sign-in (public data)

These endpoints serve a tenant's **public** data and need no account session —
you can read them with a browser or `curl` today:

* **Public keys** — `https://<you>.<domain>/keys`, `<handle>.keys`,
  `<handle>.gpg`. See [keys & proofs](../../reference/api/keys-and-proofs.md).
* **Identity proofs** — `https://<you>.<domain>/.well-known/proofs`.
* **Profile** — `https://<you>.<domain>/profile/` (content-negotiated).
* **API mirrors** — `https://id.<domain>/api/v1/public/{profile,keys,proofs}`.
