---
title: "AT Protocol (XRPC)"
weight: 30
---

# AT Protocol (`/xrpc/`)

A **small subset** of atproto XRPC reads, served from the tenant store.
Verified against `internal/protocols/atproto/xrpc_server.go`.

> **Status: Partial.** The public reads (`resolveHandle`, `getProfile`) are
> live. The data-plane methods (`createRecord`, `getRecord`, `uploadBlob`,
> `sync.getBlob`, `sync.getRepo`, `createSession`) are **disabled** at the
> router and return `501 MethodNotImplemented`: the PDS is mounted with nil
> Backend/RepoFactory/SigningKey, and wiring them without an authn+scope+
> tenant gate would expose unauthenticated cross-tenant writes and unbounded
> uploads (security audit A1-A4). They will be enabled by Step 7 of the
> steps5-8-hardening plan, wired WITH authentication, scope checks, tenant
> binding, and a body cap.

## Base URL

```text
https://<tenant>.<domain>/xrpc/<method>
```

## Methods

### `com.atproto.identity.resolveHandle`

Resolve a handle to its DID.

```http
GET /xrpc/com.atproto.identity.resolveHandle?handle=alice.example.com
```

| Query param | Required | Purpose |
|:------------|:---------|:--------|
| `handle` | yes | The handle to resolve. |

Responses:

| Status | Body | When |
|:-------|:-----|:------|
| `200` | `{"did": "did:plc:…"}` | Handle found. If the tenant has no DID, falls back to `did:web:<handle>`. |
| `400` | `InvalidRequest` | Missing `handle`. |
| `404` | `HandleNotFound` | No tenant with that handle. |

### `app.bsky.actor.getProfile`

Return a minimal actor profile.

```http
GET /xrpc/app.bsky.actor.getProfile?actor=alice.example.com
```

| Query param | Required | Purpose |
|:------------|:---------|:--------|
| `actor` | yes | A handle (a `did:` value is treated best-effort as the lookup key). |

Responses:

| Status | Body | When |
|:-------|:-----|:------|
| `200` | `{"did","handle","displayName"}` | Actor found. `displayName` currently mirrors the handle. |
| `400` | `InvalidRequest` | Missing `actor`. |
| `404` | `ActorNotFound` | No tenant with that handle. |

### `com.atproto.repo.createRecord`

> **Disabled** — returns `501 MethodNotImplemented` (see status above).

Write a record to the repo and commit it.

```http
POST /xrpc/com.atproto.repo.createRecord
```

Body: `{"repo":"<did>","collection":"<nsid>","record":{…}}`

| Status | Body | When |
|:-------|:-----|:------|
| `501` | `MethodNotImplemented` | Always (data plane disabled). |

### `com.atproto.repo.getRecord`

> **Disabled** — returns `501 MethodNotImplemented` (see status above).

Read a record back from the repo.

```http
GET /xrpc/com.atproto.repo.getRecord?repo=<did>&collection=<nsid>&rkey=<rkey>
```

| Status | Body | When |
|:-------|:-----|:------|
| `501` | `MethodNotImplemented` | Always (data plane disabled). |

### `com.atproto.repo.uploadBlob`

> **Disabled** — returns `501 MethodNotImplemented` (see status above).

Store a blob (content-addressed by SHA-256).

```http
POST /xrpc/com.atproto.repo.uploadBlob
```

| Status | Body | When |
|:-------|:-----|:------|
| `501` | `MethodNotImplemented` | Always (data plane disabled). |

### `com.atproto.sync.getBlob`

> **Disabled** — returns `501 MethodNotImplemented` (see status above).

Fetch a stored blob by CID.

```http
GET /xrpc/com.atproto.sync.getBlob?did=<did>&cid=<cid>
```

| Status | Body | When |
|:-------|:-----|:------|
| `501` | `MethodNotImplemented` | Always (data plane disabled). |

### `com.atproto.sync.getRepo`

> **Disabled** — returns `501 MethodNotImplemented` (see status above).

Export the repo as a CAR (v1).

```http
GET /xrpc/com.atproto.sync.getRepo?did=<did>
```

| Status | Body | When |
|:-------|:-----|:------|
| `501` | `MethodNotImplemented` | Always (data plane disabled). |

### `com.atproto.server.createSession`

> **Disabled** — returns `501 MethodNotImplemented` (see status above).

Mint an atproto session from a passkey-authenticated access token.

```http
POST /xrpc/com.atproto.server.createSession
```

Body: `{"accessJwt":"<validated access token>"}`

| Status | Body | When |
|:-------|:-----|:------|
| `501` | `MethodNotImplemented` | Always (data plane disabled). |
