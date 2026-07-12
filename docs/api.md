# HTTP API Reference

`y2qd` speaks HTTP, or HTTPS when `[server.tls]` is enabled (rustls, optionally restricted to the X25519MLKEM768 post-quantum hybrid key exchange, with optional mutual TLS). All routes use `application/json` for structured request and response bodies. Object PUT/GET payloads are raw bytes with `application/octet-stream`. Errors are JSON.

For machine-readable schemas: `/api-docs/openapi.json`. Interactive UI: `/swagger-ui/`. (Both require `server.unauthenticated_metrics = true`; see [Observability endpoints](#observability-endpoints).)

## Authentication

All non-auth routes (and `auth/logout` and `auth/password`) require:

```
Authorization: Bearer <token>
```

Tokens are issued by `POST /api/v1/auth/login`. They are 43-character URL-safe base64 strings (32 random bytes, no padding). They expire after `auth.default_ttl_seconds` (default 1 hour) unless a different `ttl_seconds` is requested at login time, capped by `auth.max_ttl_seconds`.

A daemon restart invalidates every token.

## Authorization

Authentication answers *who* is calling; authorization answers *what they may do*. y2q enforces two layers (both active when `[auth] enforce_authorization = true`, the default). Access is modelled as a set of **verb capabilities** - read, write, admin - and the effective set for any action is the *intersection* of the caller's global-role ceiling and their per-bucket relationship.

### Capabilities

| Verb | Allows |
|---|---|
| `read` | `GET`/`HEAD` objects, list objects, search, read bucket config |
| `write` | `PUT`/`DELETE` objects and `PATCH` tags |
| `admin` | delete the bucket, edit its config, manage its ACL |

`write` normally implies `read`, but the `writeonly` levels below grant write *without* read (a drop-box).

### Global roles

Every user has one global role - an account-wide ceiling applied on top of bucket grants. Change it with `PUT /api/v1/users/{user}/role` (admin only). The first-run `root` user is `admin`.

| Role | Bucket reach | Capabilities | Admin endpoints |
|---|---|---|---|
| `admin` | all buckets | read + write + admin | all (read + write) |
| `user` | owned / granted | governed by the bucket grant | none |
| `readonly` | owned / granted | read only | none |
| `writeonly` | owned / granted | write/delete only, never read | none |
| `auditor` | **all buckets** | read only | read only (user list, rebuild status, lock list, any ACL) |
| `disabled` | none | none - every request rejected, login refused | none |

A role *caps* what a user can do even on buckets they own: a `readonly` owner can read their own bucket but not write it; a `writeonly` owner can write but not read.

### Per-bucket ownership and ACL

Each bucket has an **owner** (full control) and an optional **ACL** mapping other users to a grant level: `read`, `write`, `writeonly` (write without read), or `admin`. Admins act on every bucket; auditors can read every bucket.

**New buckets are private to their creator.** A `PUT /{bucket}/` or the first object `PUT` into a non-existent bucket makes the caller its owner (only if their role permits writing). Until they grant access, only they (and admins/auditors) can see it.

**Existence is hidden.** A bucket you have *no* relationship to is indistinguishable from one that does not exist: it is omitted from `GET /` and search results, and any direct operation on it returns **404** - never 403. **403** is returned only when you can already see the bucket but lack the verb for the action (because of your grant level, your role ceiling, or both).

**Legacy buckets** (created before ownership existed, so with no recorded owner) are accessible only to admins/auditors until an admin assigns an owner via `PUT /api/v1/buckets/{bucket}/acl`.

When `enforce_authorization = false`, all of the above is skipped and every authenticated user has full access (single-user / migration mode).

## Error model

Every error response carries this body:

```json
{ "error": "human-readable message" }
```

Status codes follow the table in each endpoint section. A few semantics worth knowing up front:

- **401** uses `WWW-Authenticate: Bearer` for auth errors.
- **429** on login can come from two independent layers: a per-source-IP rate limit (a handful of requests per few seconds, checked first, before any credential work) or the per-username lockout described below. The lockout response sets `Retry-After: <seconds>`; the IP rate limit's 429 does not carry a body worth parsing.
- **`401 invalid credentials`** is returned identically whether the username doesn't exist or the password is wrong. By design - probing user existence isn't possible.
- **`500 decryption failed`** and **`500 object format error`** are deliberately generic. They cover both genuine corruption and adversarial probing.

## Auth and users

### `POST /api/v1/auth/login`

Authenticate a user and mint a session token.

**Request:**
```json
{
  "username": "alice",
  "password": "...",
  "ttl_seconds": 3600
}
```

`ttl_seconds` is optional. Omit to get `auth.default_ttl_seconds`. Values above `auth.max_ttl_seconds` are rejected.

**Response (200):**
```json
{
  "token": "abc...xyz",
  "expires_at": 1715003600,
  "username": "alice"
}
```

`expires_at` is seconds since the Unix epoch.

**Status codes:**

| Code | Meaning |
|---|---|
| 200 | Logged in |
| 400 | `ttl_seconds` out of range or malformed username |
| 401 | Invalid credentials (user-doesn't-exist and wrong-password are indistinguishable) |
| 429 | Per-source-IP rate limit exceeded (checked first, before credentials), or account locked out after repeated failures - the latter sets `Retry-After` |

**Example:**
```sh
curl -s -X POST https://y2qd.example/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"hunter2"}' | jq
```

### `POST /api/v1/auth/refresh`

Trade a valid token for a fresh one with the default TTL. The old token is revoked.

**Request:** none (uses the Bearer token).

**Response (200):** same shape as login.

**Status codes:**

| Code | Meaning |
|---|---|
| 200 | New token issued |
| 401 | Token missing, invalid, or expired |

### `POST /api/v1/auth/logout`

Revoke the caller's current token.

**Request:** none.

**Response (204):** empty.

| Code | Meaning |
|---|---|
| 204 | Logged out |
| 401 | Token missing or invalid |

### `POST /api/v1/auth/password`

Change the caller's password. Re-wraps the SK under the new password using the *current* `[crypto.argon2]` parameters.

**Request:**
```json
{
  "current": "...",
  "new": "..."
}
```

**Response (204):** empty.

| Code | Meaning |
|---|---|
| 204 | Password changed |
| 401 | Current password did not verify, or token invalid |

### `PUT /api/v1/users/add`

Create a new user. **Admin only.** The SK is wrapped under the new user's password from the in-memory copy.

**Request:**
```json
{
  "username": "bob",
  "password": "...",
  "role": "user"
}
```

Username: `[A-Za-z0-9_.-]+`, max 64 bytes, case-sensitive. `role` is optional (defaults to `"user"`) and is one of `admin`, `user`, `readonly`, `writeonly`, `auditor`, `disabled` - see [Authorization](#authorization).

**Response (201):** empty.

| Code | Meaning |
|---|---|
| 201 | User created |
| 400 | Invalid username or empty password |
| 401 | Token missing or invalid |
| 403 | Caller is not an admin |
| 409 | Username already exists |

### `GET /api/v1/users`

List all users. **Admin or auditor.** Returns no cryptographic material.

**Response (200):**
```json
{
  "users": [
    {
      "username": "alice",
      "created_at": 1715000000000000000,
      "last_login": 1715002500000000000,
      "role": "admin"
    },
    {
      "username": "bob",
      "created_at": 1715001000000000000,
      "last_login": null,
      "role": "user"
    }
  ]
}
```

Timestamps are nanoseconds since the Unix epoch. `last_login` is `null` if the user has never logged in.

| Code | Meaning |
|---|---|
| 200 | User list |
| 401 | Token missing or invalid |
| 403 | Caller is not an admin |

### `DELETE /api/v1/users/{user}`

Remove a user. **Admin only.** Other users keep their wrapped SK copies and continue to work. Refuses to delete the last remaining user, or the last remaining admin.

**Response (204):** empty.

| Code | Meaning |
|---|---|
| 204 | Deleted |
| 401 | Token missing or invalid |
| 403 | Caller is not an admin |
| 404 | User not found |
| 409 | Cannot delete the last user, or the last admin |

### `PUT /api/v1/users/{user}/role`

Change a user's global role. **Admin only.** Takes effect immediately - the target's existing sessions are revoked, so a demotion or `disabled` applies without waiting for session expiry. Refuses to demote the only remaining admin.

**Request:**
```json
{ "role": "readonly" }
```

`role` is one of `admin`, `user`, `readonly`, `writeonly`, `auditor`, `disabled`.

**Response (204):** empty.

| Code | Meaning |
|---|---|
| 204 | Role updated |
| 400 | Unknown role |
| 401 | Token missing or invalid |
| 403 | Caller is not an admin |
| 404 | User not found |
| 409 | Would demote the last remaining admin |

## Objects

Object paths take the form `/{bucket}/{key}`. Keys may contain `/` characters and are matched by a greedy tail pattern - `/photos/2024/05/cat.jpg` is bucket `photos`, key `2024/05/cat.jpg`.

Bucket names: ASCII alphanumeric plus `-` and `_`. The case-insensitive name `api` is reserved.
Keys: up to 1024 bytes, no null bytes, non-empty.

### `PUT /{bucket}/{key}`

Store an object. The body is encrypted (envelope + ML-KEM-768 + AES-256-GCM) and written to disk.

**Request:**
- Body: raw bytes, any Content-Type. Up to `server.max_body_bytes` (default 256 MiB), or less if the bucket has a `quota_bytes` limit with less headroom remaining. Enforced as the body streams in - regardless of whether `Content-Length` is sent (chunked transfer encoding has none).
- Headers (optional):

| Header | Values | Default | Effect |
|---|---|---|---|
| `X-Y2Q-Sync` | `durable`, `best-effort` | `durable` | `durable` fsyncs the object file and parent directory before responding (crash-safe); `best-effort` skips the fsyncs and queues the write for asynchronous flushing. |
| `X-Y2Q-<label>` | any UTF-8 string | - | Attach a custom label. Repeatable. The `X-Y2Q-` prefix is stripped and the name is lowercased before storage. |

Reserved label names (rejected case-insensitively): `Created`, `Modified`, `Checksum-GxHash`. These conflict with auto-generated headers on GET/HEAD.

**Response:** empty body. 201 for first write, 200 for overwrite.

| Code | Meaning |
|---|---|
| 200 | Existing object replaced |
| 201 | Object created |
| 400 | Invalid bucket, key, label, or `X-Y2Q-Sync` value |
| 401 | Token missing or invalid |
| 409 | Object is currently locked (a PUT to this key is already in progress, or a stale lock is present) |
| 413 | Body exceeds `server.max_body_bytes`, or would exceed the bucket's `quota_bytes` |
| 500 | Encryption or storage failure |

**Example:**
```sh
curl -X PUT https://y2qd.example/photos/2024/cat.jpg \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Y2Q-Owner: alice" \
  -H "X-Y2Q-Album: vacation" \
  --data-binary @cat.jpg
```

### `GET /{bucket}/{key}`

Retrieve and decrypt an object.

**Request headers (optional):**

| Header | Effect |
|---|---|
| `Range: bytes=N-M` | Closed inclusive byte range over the plaintext. Only the covering ciphertext chunks are read and decrypted (206). The range must be well-formed (`N <= M`) and lie within the object, else 416. |

**Response (200):** raw object bytes, `Content-Type: application/octet-stream`. The full set of metadata headers from `HEAD` is also present.

**Response (206):** the requested byte range, with `Content-Range: bytes N-M/<size>`.

| Code | Meaning |
|---|---|
| 200 | Full object |
| 206 | Partial Content (Range) |
| 400 | Invalid bucket or key |
| 401 | Token missing or invalid |
| 404 | Not found |
| 409 | Object locked |
| 416 | Range not satisfiable (inverted or out of bounds); `Content-Range: bytes */<size>` |
| 500 | Decryption or storage failure (intentionally generic message) |

### `HEAD /{bucket}/{key}`

Metadata only - no body.

**Response (200):** empty body. Metadata is exposed as headers:

| Header | Always present | Value |
|---|---|---|
| `Content-Length` | yes | Plaintext size in bytes |
| `Content-Type` | yes | `application/octet-stream` |
| `X-Y2Q-Size` | yes | Plaintext size in bytes (mirrors `Content-Length`) |
| `X-Y2Q-Created` | yes | Nanoseconds since Unix epoch when first written |
| `X-Y2Q-Modified` | yes | Nanoseconds since Unix epoch when last overwritten |
| `X-Y2Q-Checksum-GxHash` | yes | 8-byte gxhash64 digest of the plaintext, standard base64 (12 chars). Non-cryptographic; for accidental-corruption detection, not tamper detection |
| `X-Y2Q-Cipher-Size` | yes | On-disk envelope size in bytes |
| `X-Y2Q-Cipher-Checksum` | yes | 8-byte XXH3-64 checksum of the on-disk envelope, base64 (12 chars). Non-cryptographic, same as `X-Y2Q-Checksum-GxHash` above - for corruption/replica-divergence detection, not tamper detection (the per-chunk AEAD tag is what authenticates the envelope) |
| `X-Y2Q-Kem-Alg` | yes | `ml-kem-768` |
| `X-Y2Q-Aead-Alg` | yes | `aes-256-gcm` |
| `X-Y2Q-Envelope-Version` | yes | `2` (chunked; the only supported format) |
| `X-Y2Q-<label>` | per-object | Each custom label attached on PUT, echoed back lowercased |

| Code | Meaning |
|---|---|
| 200 | Object exists |
| 400 | Invalid bucket or key |
| 401 | Token missing or invalid |
| 404 | Not found |
| 500 | Storage failure |

### `DELETE /{bucket}/{key}`

Remove an object. Idempotent on the metadata index, but 404s if the object never existed.

**Response (204):** empty.

| Code | Meaning |
|---|---|
| 204 | Deleted |
| 400 | Invalid bucket or key |
| 401 | Token missing or invalid |
| 404 | Not found |
| 500 | Storage failure |

## Buckets

### `PUT /{bucket}/`

Create a bucket explicitly. With authorization enforced, the caller becomes the bucket **owner** (only if their role permits writing). Creating an object in a non-existent bucket creates the bucket implicitly the same way (and the object `PUT` itself returns 201).

**Response (200):** `{ "bucket": "archive", "created": true }` - `created` is `false` if the bucket already existed.

| Code | Meaning |
|---|---|
| 200 | Bucket created (`created: true`) or already present (`created: false`) |
| 400 | Invalid bucket name (or reserved name `api`) |
| 401 | Token missing or invalid |
| 403 | Caller's role does not permit creating buckets |

### `DELETE /{bucket}/`

Remove a bucket and all of its objects. Requires the `admin` capability on the bucket (owner or global admin).

**Response (200):** `{ "bucket": "archive", "objects_removed": 42 }`.

| Code | Meaning |
|---|---|
| 200 | Bucket removed (object count reported) |
| 401 | Token missing or invalid |
| 403 | Caller lacks admin on the bucket |
| 404 | Bucket not found (or not visible to the caller) |

### `GET /api/v1/buckets/{bucket}/config`

Read a bucket's configuration (size quota, recorded default-SSE marker, owner reference). Requires `read` on the bucket.

### `PUT /api/v1/buckets/{bucket}/config`

Set a bucket's configuration. Requires `admin` on the bucket. Owner and ACL are **not** settable here - use the ACL endpoint, so this endpoint cannot be used to escalate privileges. The CLI wrappers are `y2q quota set|info|clear` and `y2q encrypt set|info|clear`.

| Code | Meaning |
|---|---|
| 200 | Config read or updated |
| 400 | Invalid config body |
| 401 | Token missing or invalid |
| 403 | Caller lacks the required capability |
| 404 | Bucket not found (or not visible to the caller) |

## Listing

### `GET /`

List every bucket that contains at least one object.

**Response (200):**
```json
{ "buckets": ["alice-stuff", "photos", "weeklies"] }
```

Sorted ascending.

| Code | Meaning |
|---|---|
| 200 | OK |
| 401 | Token missing or invalid |
| 500 | Index or storage failure |

### `GET /{bucket}/`

List objects in a bucket, paginated.

**Query parameters:**

| Name | Type | Default | Notes |
|---|---|---|---|
| `prefix` | string | - | Only return keys with this prefix |
| `after` | string | - | Pagination cursor - return keys strictly greater than this |
| `limit` | integer | 1000 | Page size. Capped at 10 000. |

**Response (200):**
```json
{
  "items": [
    {
      "created":          1715000000000000000,
      "modified":         1715000000000000000,
      "size":             12345,
      "checksum_gxhash":  "<b64 8-byte gxhash64, 12 chars>",
      "bucket":           "photos",
      "key":              "2024/05/cat.jpg",
      "url_path":         "photos/2024/05/cat.jpg",
      "labels":           [["owner", "alice"], ["album", "vacation"]],
      "cipher_size":      13477,
      "cipher_checksum":  "<b64>",
      "kem_alg":          "ml-kem-768",
      "aead_alg":         "aes-256-gcm",
      "envelope_version": 2
    }
  ],
  "next": "2024/05/cat.jpg"
}
```

`next` is the last key returned, or `null` if this is the final page. Pass it back as `after` to fetch the next page.

| Code | Meaning |
|---|---|
| 200 | Page returned |
| 400 | Invalid bucket |
| 401 | Token missing or invalid |
| 500 | Index or storage failure |

**Pagination loop:**
```sh
cursor=""
while :; do
  page=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "https://y2qd.example/photos/?limit=1000${cursor:+&after=$cursor}")
  echo "$page" | jq -c '.items[] | {key, size}'
  cursor=$(echo "$page" | jq -r '.next // empty')
  [ -z "$cursor" ] && break
done
```

### `GET /api/v1/search`

Find objects whose labels satisfy a boolean query. Results are sorted by
`(bucket, key)` and paginated like `GET /{bucket}/`.

**Query parameters:**

| Name | Type | Default | Notes |
|---|---|---|---|
| `q` | string | *(required)* | Label query (see below) |
| `bucket` | string | all buckets | Restrict the search to one bucket |
| `prefix` | string | - | Only return keys with this prefix |
| `after` | string | - | Opaque pagination cursor from a previous `next` |
| `limit` | integer | 1000 | Page size. Capped at 10 000. |

**Query language.** A leaf condition is `name OP value`, where `value` may be
bare or `"quoted"`:

| Operator | Meaning |
|---|---|
| `name == value` | label present and value equal |
| `name != value` | NOT (present and equal) - also true when the label is absent |
| `name =~ value`  | value matches the regex `value` |
| `name ^= value`  | value starts with `value` |
| `name $= value`  | value ends with `value` |

Leaves combine with `and` / `&&`, `or` / `||`, `not` / `!`, and parentheses.
Precedence, lowest to highest: `or` < `and` < `not`. Example:
`env == prod and (tier =~ "web.*" or not region $= -dev)`

See [search.md](search.md) for the complete query-language reference: value
quoting, missing-label semantics, regex behavior, tokenization rules, and a
formal grammar.

**Response (200):** identical shape to `GET /{bucket}/` (an `items` array of
object metadata plus an opaque `next` cursor).

| Code | Meaning |
|---|---|
| 200 | Page returned |
| 400 | Invalid query (parse error or bad regex) or invalid bucket |
| 401 | Token missing or invalid |
| 500 | Index or storage failure |

```sh
curl -s -H "Authorization: Bearer $TOKEN" \
  --get "https://y2qd.example/api/v1/search" \
  --data-urlencode 'q=env == prod and tier != test' \
  --data-urlencode 'bucket=photos'
```

CLI equivalent (`alias/` searches all buckets):
```sh
y2q search myalias/photos --query 'env == prod and tier != test'
y2q search myalias/ --query 'name ^= "log-" or env =~ "prod|stage"'
```

## Access control (ACL)

Manage a bucket's owner and per-user grants. See [Authorization](#authorization) for the model. Viewing (`GET`) is allowed for the bucket owner, a global admin, or an auditor (who may view any bucket's ACL). Editing (`PUT`) requires the bucket owner or a global admin; transferring ownership additionally requires being the current owner or a global admin. Owner/ACL are deliberately *not* settable through the generic `PUT /api/v1/buckets/{bucket}/config` body, so that endpoint cannot be used to escalate privileges.

### `GET /api/v1/buckets/{bucket}/acl`

**Response (200):**
```json
{
  "owner": "alice",
  "grants": { "bob": "read", "carol": "write" }
}
```

`owner` is `null` only for an unclaimed legacy bucket. `grants` maps username → `"read"` | `"write"` | `"writeonly"` | `"admin"`; the owner is never listed (they have implicit full control).

| Code | Meaning |
|---|---|
| 200 | Owner and ACL |
| 401 | Token missing or invalid |
| 403 | Caller is not the owner / a global admin |
| 404 | Bucket not found (or not visible to the caller) |

### `PUT /api/v1/buckets/{bucket}/acl`

Replace the ACL, and optionally transfer ownership by setting `owner`. The body fully replaces the existing `grants`.

**Request:**
```json
{
  "owner": "alice",
  "grants": { "bob": "write" }
}
```

A new `owner` must be an existing user; grantees are not checked for existence (a grant to an unknown user is inert, and validating it would leak which usernames exist). Granting to the current owner is rejected as redundant. **Response (200)** echoes the stored owner and ACL.

| Code | Meaning |
|---|---|
| 200 | Updated owner and ACL |
| 400 | Unknown grantee, empty username, or redundant owner grant |
| 401 | Token missing or invalid |
| 403 | Caller may not manage this ACL, or may not transfer ownership |
| 404 | Bucket not found (or not visible to the caller) |

CLI equivalents:
```sh
y2q admin acl get myalias photos
y2q admin acl grant myalias photos bob write
y2q admin acl revoke myalias photos bob
y2q admin acl chown myalias photos alice
```

## Admin

Mutating admin endpoints (rebuild **start**, lock **clear**, all user management) require the `admin` role. Read-only admin endpoints (rebuild **status**, lock **list**, trace, user list) are also open to the `auditor` role. Non-admins get **403**.

### `POST /api/v1/rebuild`

Start a metadata index rebuild in the background. Fire-and-forget. **Admin only.**

**Response (202):**
```json
{ "status": "running" }
```

| Code | Meaning |
|---|---|
| 202 | Rebuild started |
| 401 | Token missing or invalid |
| 409 | A rebuild is already in progress |
| 500 | Storage failure |

### `GET /api/v1/rebuild`

Poll rebuild state.

**Response (200):**
```json
{ "state": "idle" }
{ "state": "running", "percent": 73 }
{ "state": "completed" }
{ "state": "failed", "reason": "<short description>" }
```

`percent` is present only when running. `reason` is present only when failed.

| Code | Meaning |
|---|---|
| 200 | OK |
| 401 | Token missing or invalid |

### `GET /api/v1/locks`

List currently active in-flight write locks (PUTs in progress) whose acquisition time is older than the cutoff. Because locks are in-memory, this endpoint shows live state - there are no on-disk lock files.

**Query parameters:**

| Name | Required | Format |
|---|---|---|
| `older_than` | yes | `<n>{s\|m\|h\|d\|w}` (relative, e.g. `30m`, `2d`) or a bare Unix-seconds integer |

**Response (200):**
```json
[
  {
    "bucket":              "photos",
    "key":                 "2024/05/cat.jpg",
    "locked_since_nanos":  1715000000000000000,
    "age_seconds":         1834
  }
]
```

`key` is the original object key. An empty list is the normal case - locks only appear here for PUTs that are taking unusually long.

| Code | Meaning |
|---|---|
| 200 | List (possibly empty) |
| 400 | Missing or malformed `older_than` |
| 401 | Token missing or invalid |
| 500 | Storage failure |

### `DELETE /api/v1/locks`

Force-release every active lock older than `older_than`. Use carefully - releasing a lock that belongs to a genuinely in-flight PUT may leave the object in a partially written state. Same query parameters as the GET.

**Response (200):**
```json
{ "removed": 1 }
```

| Code | Meaning |
|---|---|
| 200 | Locks released (count reported) |
| 400 | Missing or malformed `older_than` |
| 401 | Token missing or invalid |
| 500 | Storage failure |

### `GET /api/v1/trace`

Server-sent-events stream of every request the daemon handles, in real time. **Admin or auditor.** Each event carries timestamp, method, path, status, latency, and request/response sizes. The server has no overhead when no trace client is connected. The CLI wrapper is `y2q admin trace <alias> [--errors]`.

| Code | Meaning |
|---|---|
| 200 | SSE stream opened (`text/event-stream`) |
| 401 | Token missing or invalid |
| 403 | Caller is not an admin or auditor |

## Cluster endpoints

Present only when `[cluster] enabled = true`. Admin-authed operator endpoints:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/cluster/status` | Membership, leader, committed epoch, per-node status |
| `POST` | `/api/v1/cluster/join` | Admit this contact node's caller-specified peer into the cluster |
| `POST` | `/api/v1/cluster/migrate` | Online migration: distribute (import) or collect (export) objects between a single node and the cluster |

Peer-only, shared-secret/mTLS-authed and epoch-fenced `/internal/v1/*` routes (Raft RPC, CRAQ prepare/read/describe/version, backfill, health) are documented in [clustering.md](clustering.md) and are not for client use.

## Observability endpoints

| Route | Purpose |
|---|---|
| `GET /metrics/prometheus` | Prometheus scrape format |
| `GET /metrics/dashboard` | Interactive in-browser metrics dashboard |
| `GET /swagger-ui/` | Interactive API documentation |
| `GET /api-docs/openapi.json` | Raw OpenAPI 3 document |

These are served **only** when `[server] unauthenticated_metrics = true`, and then without a Bearer token. With the default `false` they are not registered at all (no auth-gated variant) - the daemon logs that they are disabled at startup.

## Status code summary

| Code | When you'll see it |
|---|---|
| 200 | Successful read or overwrite |
| 201 | New object or user created |
| 202 | Rebuild kicked off |
| 204 | Successful mutation with no body (logout, password change, delete) |
| 206 | Partial Content (Range) |
| 400 | Bad bucket name, key, label, request body, or query parameter |
| 401 | Auth missing/invalid, or login credentials wrong |
| 403 | Authenticated but not permitted - not an admin, or lacks the bucket permission for this action (on a bucket you can see) |
| 404 | Object or user not found; also a bucket you have no permission on (existence is hidden) |
| 409 | Conflict - object locked, rebuild already running, username taken, last-user/last-admin deletion |
| 413 | PUT body exceeds `server.max_body_bytes` or the bucket's `quota_bytes` |
| 416 | `Range` not satisfiable (inverted or out of bounds) |
| 429 | Login: per-source-IP rate limit, or per-username lockout - see `Retry-After` |
| 500 | Internal failure: encryption, decryption, index, or storage |
| 503 | `KeystoreUnavailable` - daemon has no SK in memory (idle-dropped). Log in to install it. |

## Source

- [crates/y2qd/src/handlers/](../crates/y2qd/src/handlers/) - object, listing, and admin handlers
- [crates/y2qd/src/auth/handlers.rs](../crates/y2qd/src/auth/handlers.rs) - auth and user handlers
- [crates/y2qd/src/error.rs](../crates/y2qd/src/error.rs) - AppError → status mapping
- [crates/y2qd/src/auth/error.rs](../crates/y2qd/src/auth/error.rs) - AuthError → status mapping
