# HTTP API Reference

`y2qd` speaks HTTP, or HTTPS when `[server.tls]` is enabled (rustls, optionally restricted to the X25519MLKEM768 post-quantum hybrid key exchange, with optional mutual TLS). All routes use `application/json` for structured request and response bodies. Object PUT/GET payloads are raw bytes with `application/octet-stream`. Errors are JSON.

For machine-readable schemas: `/api-docs/openapi.json`. (Requires `server.unauthenticated_metrics = true`; see [Observability endpoints](#observability-endpoints).)

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
| `admin` | buckets this persona holds a sealed grant for; may create new buckets | read + write + admin on those buckets | all (read + write) |
| `user` | owned / granted, and only the persona that holds the sealed grant | governed by the bucket grant | none |
| `readonly` | owned / granted, same grant rule | read only | none |
| `writeonly` | owned / granted, same grant rule | write/delete only, never read | none |
| `auditor` | buckets this persona holds a sealed grant for | read only | read only (user list, rebuild status, lock list) |
| `disabled` | none | none - every request rejected, login refused | none |

A role *caps* what a user can do even on buckets they own: a `readonly` owner can read their own bucket but not write it; a `writeonly` owner can write but not read. A global `admin` or `auditor` role does **not** see every bucket name. No sealed grant means the bucket is omitted from `GET /` and search, and direct access is 404.

### Per-bucket ownership and ACL

Each bucket has an **owner** (full control) and an optional **ACL** mapping other users to a grant level: `read`, `write`, `writeonly` (write without read), or `admin`. An admin or auditor sees a bucket only when *that persona* holds a sealed grant for it. Holding the grant keeps the role ceiling (admin: full, auditor: read); it is not a pass to every other bucket.

**New buckets are private to the persona that created them.** A `PUT /{bucket}/` or the first object `PUT` into a non-existent bucket makes the caller its owner (only if their role permits writing) and seals the epoch-0 key to that persona. Until someone with a grant shares it, no other persona — including other global admins and the owner's own duress slots — can see it.

**Existence is hidden.** A bucket this persona cannot decrypt is indistinguishable from one that does not exist: it is omitted from `GET /`, search, and S3 listings, and GET/HEAD/PUT/DELETE/ACL return **404** - never 403. That includes a global admin or auditor with no sealed grant, and it includes write and delete, not only read. **403** is returned only when the persona can already see the bucket but lacks the verb (grant level, role ceiling, or both). The exception is an ACL relationship of exactly `writeonly`: write and delete stay allowed with no sealed secret (a drop box), and a read is **403** because that caller was given the bucket.

**Legacy buckets** (no recorded owner and no sealed grant) are hidden from everyone while authorization is enforced, including admins. There is no break-glass path that lists them or assigns an owner without a grant.

When `enforce_authorization = false`, all of the above is skipped and every authenticated user has full access (single-user / migration mode). The global-role short-circuit stays in that mode.

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

Trade a valid token for a fresh one with the default TTL. The old token is revoked. Only up to `auth.max_refreshes` times per token - `0` (default) disables refresh entirely, so the first attempt on any token is rejected. A token past its limit is not revoked; it keeps authenticating normally for every other endpoint until it naturally expires.

**Request:** none (uses the Bearer token).

**Response (200):** same shape as login.

**Status codes:**

| Code | Meaning |
|---|---|
| 200 | New token issued |
| 401 | Token missing, invalid, or expired |
| 403 | Refresh limit (`auth.max_refreshes`) exceeded for this token |

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

### `POST /api/v1/s3/credentials`

Mint a temporary S3 SigV4 credential bound to the caller's current session. Reachable on both the native listener (`[server]`) and the S3 listener (`[s3]`) - registered identically on each. See [S3 gateway](#s3-gateway) below for how the credential is used.

**Request:**
```json
{ "ttl_seconds": 3600 }
```

`ttl_seconds` is optional (defaults to `[s3] default_credential_ttl_seconds`) and is always clamped to `min(requested, session.expires_at)` - a credential can never outlive the session that minted it.

**Response (200):**
```json
{
  "access_key_id": "Y2Q...",
  "secret_access_key": "...",
  "region": "y2q",
  "expires_at": 1715003600,
  "session_expires_at": 1715003600
}
```

`secret_access_key` is returned exactly once and is not recoverable afterwards - losing it means minting a new credential. `expires_at` and `session_expires_at` are Unix seconds; `expires_at` is never later than `session_expires_at`.

| Code | Meaning |
|---|---|
| 200 | Credential minted |
| 400 | `ttl_seconds` out of range |
| 401 | Token missing or invalid |

### `GET /api/v1/s3/credentials`

List the caller's own live S3 credentials. Never returns a secret.

**Response (200):**
```json
{
  "credentials": [
    { "access_key_id": "Y2Q...", "created_at": 1715000000, "expires_at": 1715003600 }
  ]
}
```

| Code | Meaning |
|---|---|
| 200 | Credential list (possibly empty) |
| 401 | Token missing or invalid |

### `DELETE /api/v1/s3/credentials/{access_key_id}`

Revoke one of the caller's own S3 credentials.

**Response (204):** empty.

| Code | Meaning |
|---|---|
| 204 | Credential revoked |
| 401 | Token missing or invalid |
| 403 | Unknown access key id, or one owned by a different session - identical response for both, so the endpoint cannot be used to enumerate other sessions' access key ids |

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
| `X-Y2Q-Envelope-Version` | yes | `4` for any object written by the current daemon, or `3` for a legacy object written before the authenticated-final-chunk-marker change (both remain readable) - see [architecture.md#v4-authenticated-final-chunk-marker](architecture.md#v4-authenticated-final-chunk-marker) |
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
      "envelope_version": 4
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

Manage a bucket's owner and per-user grants. See [Authorization](#authorization) for the model. Viewing (`GET`) requires the bucket admin capability, or a global admin/auditor persona that holds a sealed grant on that bucket — a global role with no grant gets **404**, not the ACL. Editing (`PUT`) requires the bucket admin capability (owner, bucket-admin grantee, or a global admin who holds a grant); transferring ownership additionally requires being the current owner or a global admin who can already see the bucket. Owner/ACL are deliberately *not* settable through the generic `PUT /api/v1/buckets/{bucket}/config` body, so that endpoint cannot be used to escalate privileges.

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

## S3 gateway

Optional **second listener** (`[s3] enabled = true`, off by default, default port 9000) speaking AWS SigV4/S3 REST semantics, running alongside the native API documented above. It shares the same storage/authorization/encryption stack - `authz::authorize_bucket`, `bucket_keys::resolve_read_key`/`resolve_write_key`, `cipher::*` - so a bucket's grants, existence-hiding, and encryption are identical on both surfaces. Full design and security properties: [architecture.md#s3-gateway](architecture.md#s3-gateway), [../SECURITY.md#s3-gateway](../SECURITY.md#s3-gateway).

### Getting a credential

There is no password authentication on this listener at all. Mint a temporary access key id / secret access key pair via `POST /api/v1/s3/credentials` (documented under [Auth and users](#post-apiv1s3credentials) above; reachable on either listener) using an existing Bearer token, then sign S3 requests with AWS Signature Version 4 against `[s3] region` and the access key id / secret access key pair. A credential's expiry is always clamped to its owning session's expiry, and every S3 request re-resolves that session live - logout, expiry, and revocation on the native API kill S3 access immediately, mid-transfer included.

```sh
# 1. Log in on the native listener, mint an S3 credential
TOKEN=$(curl -s -X POST https://y2qd.example:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"hunter2"}' | jq -r .token)
CRED=$(curl -s -X POST https://y2qd.example:8080/api/v1/s3/credentials \
  -H "Authorization: Bearer $TOKEN")

# 2. Point any SigV4-capable S3 client at the S3 listener
aws --endpoint-url https://y2qd.example:9000 --region y2q \
  s3 cp report.pdf s3://archive/report.pdf
```

### Addressing

**Path-style** (`http://host:port/bucket/key`) always works. **Virtual-hosted-style** (`http://bucket.domain/key`) additionally works when `[s3] virtual_host_domain` is set to a base domain the bucket name is a subdomain of.

### Supported operations

| Category | Operations |
|---|---|
| Service | `ListBuckets` (`GET /`) |
| Bucket | `CreateBucket`, `DeleteBucket`, `HeadBucket`, `GetBucketLocation`, `GetBucketVersioning` (reports "never enabled"; `PUT` is `501`) |
| Object | `PutObject`, `GetObject` (ranged, conditional requests), `HeadObject`, `DeleteObject`, `CopyObject` |
| Listing | `ListObjectsV2`, `ListObjects` (with delimiter/common-prefix roll-up), `DeleteObjects` (batch) |
| Tagging | `GetObjectTagging`, `PutObjectTagging`, `DeleteObjectTagging` |
| Multipart | `CreateMultipartUpload`, `UploadPart`, `ListParts`, `ListMultipartUploads`, `CompleteMultipartUpload`, `AbortMultipartUpload` |

Object metadata maps to y2q labels: system headers (`Content-Type`, `Content-Encoding`, `Cache-Control`, ...) and `x-amz-meta-*` round-trip through GET/HEAD; every non-`amz-`-prefixed label is exposed as an S3 object tag. `x-amz-checksum-crc32`/`x-amz-checksum-sha256` are verified; other checksum algorithms are rejected with `400 InvalidRequest` rather than silently accepted unverified. `Content-MD5` is accepted but not verified.

S3 sub-resources with no faithful mapping onto y2q's persona-keyed cryptographic grants - `?acl`, `?policy`, `?lifecycle`, `?cors`, `?encryption` (SSE-C), `?replication`, `?object-lock`, and others - return `501 NotImplemented` rather than silently accepting and ignoring them. Bucket access control continues to go through `PUT /api/v1/buckets/{bucket}/acl` on the native listener.

### Authentication and errors

Every request must carry a valid SigV4 signature (header `Authorization: AWS4-HMAC-SHA256 ...` or a presigned `X-Amz-*` query string) - there is no anonymous or public-bucket access. Errors are XML (`Content-Type: application/xml`), matching the shape of a real S3 error response:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchKey</Code><Message>...</Message><Resource>/bucket/key</Resource><RequestId>...</RequestId></Error>
```

| S3 `Code` | Status | Cause |
|---|---|---|
| `NoSuchBucket` / `NoSuchKey` | 404 | Bucket or object not found, or not visible to the caller (existence hidden, same as the native API) |
| `AccessDenied` | 403 | No credentials at all, `Role::Disabled`, or a presigned URL past its effective expiry |
| `InvalidAccessKeyId` | 403 | Access key id unknown |
| `SignatureDoesNotMatch` | 403 | Signature mismatch, or an `aws-chunked` chunk/trailer signature failed to verify |
| `ExpiredToken` | 400 | Credential expired, or its owning session expired/was revoked |
| `RequestTimeTooSkewed` | 403 | `X-Amz-Date` outside `[s3] max_clock_skew_secs` of server time |
| `AuthorizationHeaderMalformed` | 400 | Malformed signature/scope, or the scope's region doesn't match `[s3] region` |
| `XAmzContentSHA256Mismatch` | 400 | Declared payload SHA-256 doesn't match the actual body |
| `EntityTooLarge` | 413 | Body exceeds `server.max_body_bytes`/bucket quota, or a multipart part exceeds `[s3] max_part_bytes` |
| `InvalidRequest` | 400 | Unsupported checksum algorithm, or other malformed input |
| `NotImplemented` | 501 | A recognized but unimplemented S3 sub-resource |
| `InternalError` | 500 | Internal failure (deliberately generic, same suppression as the native API's 500s) |

### Configuration

Full field reference: [configuration.md#s3](configuration.md#s3). Disabled by default; when enabled, the same non-loopback-without-TLS bind refusal as `[server]` applies to `[s3] host`/`[s3.tls]`.

## Observability endpoints

| Route | Purpose |
|---|---|
| `GET /metrics/prometheus` | Prometheus scrape format |
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
| 503 | `KeystoreNotFound` - `keystore.json`/`users.redb` missing at the configured `keystore_dir` (misconfiguration, or a copy that left the keystore behind) |

## Source

- [crates/y2qd/src/handlers/](../crates/y2qd/src/handlers/) - object, listing, and admin handlers
- [crates/y2qd/src/auth/handlers.rs](../crates/y2qd/src/auth/handlers.rs) - auth and user handlers
- [crates/y2qd/src/error.rs](../crates/y2qd/src/error.rs) - AppError → status mapping
- [crates/y2qd/src/auth/error.rs](../crates/y2qd/src/auth/error.rs) - AuthError → status mapping
- [crates/y2qd/src/s3/](../crates/y2qd/src/s3/) - S3 gateway: routes, SigV4, credentials, multipart, XML codec
- [crates/y2qd/src/s3/error.rs](../crates/y2qd/src/s3/error.rs) - S3Error → XML/status mapping
