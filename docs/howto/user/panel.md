---
title: "Use the user panel"
weight: 10
---

# How to use the user panel

> **Goal:** sign in to your Sovereign account and manage your profile, keys,
> proofs, passkeys, sessions, tokens, and data.
> **Status:** shipped — the panel is a thin client over the
> [control-plane API](../../reference/api/control-plane.md), served at
> `https://id.<domain>/panel`.
> **You'll need:** an account on a Sovereign server (your administrator sends
> you an invite email) and a browser with JavaScript enabled. Passkey
> registration is JS-only; ToS acceptance and profile editing also work
> without JavaScript (see [If it goes wrong](#if-it-goes-wrong)).

## Steps

1. **Open your invite link.** Your administrator creates your account and an
   invite email arrives with a magic link:

   ```text
   https://id.example.com/invite/<token>
   ```

   Opening it redeems the one-time token, signs you in (a session cookie is
   set), and redirects you to the panel. The token works once.

2. **Accept the Terms of Service.** The first screen shows the current ToS.
   Accept to continue. Without JavaScript, use the plain form at
   `/panel/tos`.

3. **Register a passkey.** The panel asks you to create a passkey (WebAuthn).
   This is your sign-in credential for future visits — you can add more later
   under **Passkeys**. You cannot delete your last passkey.

4. **Fill in your profile.** Set your display name, bio, and avatar, and add
   links (up to 32, reorderable). Toggle **publish** to make the profile
   visible on your public page (`https://<you>.<domain>/profile/`). Without
   JavaScript, use the plain form at `/panel/profile`.

5. **Add public keys.** Under **Keys**, register your SSH and/or PGP public
   keys. They are served publicly at `/keys` for verification. Private-key
   material is rejected — never paste a private key.

6. **Add and verify proofs.** Under **Proofs**, create Keyoxide-style proof
   claims (e.g. a link to a social profile) and run **verify** to check them.
   Verified proofs appear on your public proofs page.

7. **Manage passkeys.** Under **Passkeys**, list and delete your WebAuthn
   credentials. Deleting the last one is refused (`409`).

8. **Manage sessions.** Under **Sessions**, see every active session (with
   last-seen) and revoke individual sessions or all of them — useful when a
   device is lost.

9. **Create API tokens.** Under **Tokens**, create programmatic API tokens
   for scripts and integrations. Pick a name and the scopes to grant. The raw
   token is shown **exactly once** — copy it immediately; it is never served
   again. Revoke a token family at any time.

10. **Export your data.** Under **Account**, request a full export (identity,
    profile, links, keys, proofs) as JSON.

11. **Request deletion.** Under **Account**, request account deletion. This
    does **not** delete immediately: it creates a pending request that your
    administrator must approve. Until then your account stays active.

## If it goes wrong

| Symptom | Likely cause | Fix |
|:--------|:-------------|:----|
| Invite link says not found / conflict | Token already used or expired | Ask your administrator for a new invite |
| "This panel requires JavaScript" | JS disabled | ToS and profile still work at `/panel/tos` and `/panel/profile`; everything else needs JS |
| Cannot delete a passkey | It is your last credential | Register another passkey first |
| Token not shown after creation | You navigated away | Create a new token; the old one is gone for good |
| `429` errors | Per-IP rate limit | Wait for `Retry-After` and retry |

## See also

* [Control-plane API reference](../../reference/api/control-plane.md) — the
  endpoints the panel calls.
* [Admin how-to: the console](../../howto/admin/console.md) — what your
  administrator can see and do.
