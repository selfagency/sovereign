---
title: "Use the admin console"
weight: 20
---

# How to use the admin console

> **Goal:** operate a Sovereign instance from the browser: tenants, users and
> invites, OIDC clients, backups, moderation, audit, IPFS pins, ToS, and
> deletion requests.
> **Status:** shipped — the console is a thin client over the
> [control-plane API](../../reference/api/control-plane.md), served at
> `https://id.<domain>/admin`.
> **You'll need:** an account with the instance-admin flag. The first user
> created on a fresh install is the instance admin; admins can grant the flag
> to others. JavaScript is required.

## Steps

Sign in at `https://id.<domain>/admin` (same session as the user panel). The
console has one view per section, listed in the navigation bar.

1. **Dashboard.** Overview of the instance: wired features, scheduler status,
   and the latest backup state (from `GET /admin/system/info`).

2. **Tenants.** List, create, and delete tenants. A tenant is a handle
   (`alice.example.com`) with its own isolated storage. Deleting a tenant is
   destructive — it removes the tenant and its data.

3. **Users.** List all users across tenants, create users (this sends the
   invite email), edit a user (including granting/revoking the admin flag),
   delete a user, view a user's passkeys, and revoke a user's sessions.
   Creating a user or sending an invite is idempotent — a retry does not send
   a second email.

4. **Clients.** Manage OIDC clients. Creating a client or rotating its secret
   shows the new secret **exactly once** — copy it immediately. Rotating
   invalidates the old secret; update any application that uses it.

5. **Backups.** View and edit the backup config (schedule, destination,
   prefix), trigger a backup run, list runs, and trigger a restore. Runs and
   restores are long-running and idempotent — a retry with the same key does
   not double-run. A restore requires `confirm: true` and is destructive.

6. **Moderation.** Create takedowns (resource + reason), list them, and lift
   them. Takedowns are recorded in the audit log with the acting admin.

7. **Audit.** Browse the instance audit log: every state-changing admin
   action and security-relevant self action, with the real actor.

8. **IPFS pins.** List pinned CIDs, add a pin by CID, and check pin status.
   Only available when `ipfs.enabled` is set; the server is a broker client
   to a Kubo RPC — there is no embedded node.

9. **Terms of Service.** View the current ToS and publish a new version.
   Publishing a new version forces users to re-accept on their next login.

10. **Deletion requests.** Review pending account-deletion requests.
    **Approve** cascades the deletion (the user and all their data are
    removed); **reject** is a no-op that leaves the account active.

## If it goes wrong

| Symptom | Likely cause | Fix |
|:--------|:-------------|:----|
| `403` on an admin view | Your account is not an instance admin | Have an admin grant the flag |
| Secret not shown after create/rotate | You navigated away | Rotate again; the old secret is invalidated |
| Backup run stuck | Long-running operation | Poll `GET /admin/backup/runs/{id}`; it is exempt from the default per-route timeout |
| `429` errors | Per-IP rate limit | Wait for `Retry-After` and retry |

## See also

* [Control-plane API reference](../../reference/api/control-plane.md) — the
  endpoints the console calls.
* [Install Sovereign](install.md) — first-time setup, including how the first
  admin is created.
* [User how-to: the panel](../../howto/user/panel.md) — what your users see.
