# HTTP API Reference

`y2qd` speaks plain HTTP. All routes use `application/json` for structured request and response bodies. Object PUT/GET payloads are raw bytes with `application/octet-stream`. Errors are JSON.

For machine-readable schemas: `/api-docs/openapi.json`. Interactive UI: `/swagger-ui/`.

## Authentication

All non-auth routes (and `auth/logout` and `auth/password`) require:

```
Authorization: Bearer <token>
```

Tokens are issued by `POST /api/v1/auth/login`. They are 43-character URL-safe base64 strings (32 random bytes, no padding). They expire after `auth.default_ttl_seconds` (default 1 hour) unless a different `ttl_seconds` is requested at login time, capped by `auth.max_ttl_seconds`.

A daemon restart invalidates every token.

## Error model

Every error response carries this body:

```json
{ "error": "human-readable message" }
```

Status codes follow the table in each endpoint section. A few semantics worth knowing up front:

- **401** uses `WWW-Authenticate: Bearer` for auth errors.
- **429** on login uses `Retry-After: <seconds>` for lockouts.
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
| 429 | Account locked out - `Retry-After` header set |

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

Create a new user. Requires an active session - the SK is wrapped under the new user's password from the in-memory copy.

**Request:**
```json
{
  "username": "bob",
  "password": "..."
}
```

Username: `[A-Za-z0-9_.-]+`, max 64 bytes, case-sensitive.

**Response (201):** empty.

| Code | Meaning |
|---|---|
| 201 | User created |
| 400 | Invalid username or empty password |
| 401 | Token missing or invalid |
| 409 | Username already exists |

### `GET /api/v1/users`

List all users. Returns no cryptographic material.

**Response (200):**
```json
{
  "users": [
    {
      "username": "alice",
      "created_at": 1715000000000000000,
      "last_login": 1715002500000000000
    },
    {
      "username": "bob",
      "created_at": 1715001000000000000,
      "last_login": null
    }
  ]
}
```

Timestamps are nanoseconds since the Unix epoch. `last_login` is `null` if the user has never logged in.

| Code | Meaning |
|---|---|
| 200 | User list |
| 401 | Token missing or invalid |

### `DELETE /api/v1/users/{user}`

Remove a user. Other users keep their wrapped SK copies and continue to work. Refuses to delete the last remaining user.

**Response (204):** empty.

| Code | Meaning |
|---|---|
| 204 | Deleted |
| 401 | Token missing or invalid |
| 404 | User not found |
| 409 | Cannot delete the last user |

## Objects

Object paths take the form `/{bucket}/{key}`. Keys may contain `/` characters and are matched by a greedy tail pattern - `/photos/2024/05/cat.jpg` is bucket `photos`, key `2024/05/cat.jpg`.

Bucket names: ASCII alphanumeric plus `-` and `_`. The case-insensitive name `api` is reserved.
Keys: up to 1024 bytes, no null bytes, non-empty.

### `PUT /{bucket}/{key}`

Store an object. The body is encrypted (envelope + ML-KEM-768 + AES-256-GCM) and written to disk.

**Request:**
- Body: raw bytes, any Content-Type. Up to `server.max_body_bytes` (default 256 MiB).
- Headers (optional):

| Header | Values | Default | Effect |
|---|---|---|---|
| `X-Y2Q-Sync` | `durable`, `best-effort` | `durable` | `durable` fsyncs the object file and parent directory before responding (crash-safe); `best-effort` skips the fsyncs and queues the write for asynchronous flushing. |
| `X-Y2Q-<label>` | any UTF-8 string | - | Attach a custom label. Repeatable. The `X-Y2Q-` prefix is stripped and the name is lowercased before storage. |

Reserved label names (rejected case-insensitively): `Created`, `Modified`, `Checksum-MD5`, `Checksum-SHA256`. These conflict with auto-generated headers on GET/HEAD.

**Response:** empty body. 201 for first write, 200 for overwrite.

| Code | Meaning |
|---|---|
| 200 | Existing object replaced |
| 201 | Object created |
| 400 | Invalid bucket, key, label, or `X-Y2Q-Sync` value |
| 401 | Token missing or invalid |
| 409 | Object is currently locked (a PUT to this key is already in progress, or a stale lock is present) |
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
| `Range: bytes=N-M` | Closed inclusive byte range over the plaintext. For v2-chunked encrypted objects (the default) only the covering ciphertext chunks are read and decrypted (206). Legacy plaintext objects are sliced directly (206). v1 whole-object encrypted objects cannot be partially decrypted and return 501. The range must be well-formed (`N <= M`) and lie within the object, else 416. |

**Response (200):** raw object bytes, `Content-Type: application/octet-stream`. The full set of metadata headers from `HEAD` is also present.

**Response (206):** the requested byte range, with `Content-Range: bytes N-M/<size>`.

| Code | Meaning |
|---|---|
| 200 | Full object |
| 206 | Partial Content (Range; v2-encrypted or plaintext) |
| 400 | Invalid bucket or key |
| 401 | Token missing or invalid |
| 404 | Not found |
| 409 | Object locked |
| 416 | Range not satisfiable (inverted or out of bounds); `Content-Range: bytes */<size>` |
| 500 | Decryption or storage failure (intentionally generic message) |
| 501 | `Range` on a v1 whole-object encrypted object |

### `HEAD /{bucket}/{key}`

Metadata only - no body.

**Response (200):** empty body. Metadata is exposed as headers:

| Header | Always present | Value |
|---|---|---|
| `Content-Length` | yes | Plaintext size in bytes |
| `Content-Type` | yes | `application/octet-stream` |
| `X-Y2Q-Created` | yes | Nanoseconds since Unix epoch when first written |
| `X-Y2Q-Modified` | yes | Nanoseconds since Unix epoch when last overwritten |
| `X-Y2Q-Checksum-MD5` | yes | Full 16-byte MD5 digest, standard base64 (24 chars) |
| `X-Y2Q-Checksum-SHA256` | yes | Full 32-byte SHA-256 digest, standard base64 (44 chars) |
| `X-Y2Q-Cipher-Size` | encrypted only | On-disk envelope size in bytes |
| `X-Y2Q-Cipher-SHA256` | encrypted only | SHA-256 of the envelope, base64 |
| `X-Y2Q-Kem-Alg` | encrypted only | `ml-kem-768` |
| `X-Y2Q-Aead-Alg` | encrypted only | `aes-256-gcm` |
| `X-Y2Q-Envelope-Version` | encrypted only | `1` |
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
      "checksum_md5":     "<b64 16-byte digest>",
      "checksum_sha256":  "<b64 32-byte digest>",
      "bucket":           "photos",
      "key":              "2024/05/cat.jpg",
      "disk_path":        "/var/lib/y2qd/objects/photos/ab/cd/<uuid>.obj",
      "url_path":         "photos/2024/05/cat.jpg",
      "labels":           { "owner": "alice", "album": "vacation" },
      "cipher_size":      13477,
      "cipher_sha256":    "<b64>",
      "kem_alg":          "ml-kem-768",
      "aead_alg":         "aes-256-gcm",
      "envelope_version": 1
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

## Admin

### `POST /api/v1/rebuild`

Start a metadata index rebuild in the background. Fire-and-forget.

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

## Observability endpoints

These are usually auth-gated. Set `[server] unauthenticated_metrics = true` to expose them without a Bearer token.

| Route | Purpose |
|---|---|
| `GET /metrics/prometheus` | Prometheus scrape format |
| `GET /metrics/dashboard` | Interactive in-browser metrics dashboard |
| `GET /swagger-ui/` | Interactive API documentation |
| `GET /api-docs/openapi.json` | Raw OpenAPI 3 document |

## Status code summary

| Code | When you'll see it |
|---|---|
| 200 | Successful read or overwrite |
| 201 | New object or user created |
| 202 | Rebuild kicked off |
| 204 | Successful mutation with no body (logout, password change, delete) |
| 206 | Partial Content (Range on a v2-encrypted or plaintext object) |
| 400 | Bad bucket name, key, label, request body, or query parameter |
| 401 | Auth missing/invalid, or login credentials wrong |
| 404 | Object or user not found |
| 409 | Conflict - object locked, rebuild already running, username taken, last-user deletion |
| 416 | `Range` not satisfiable (inverted or out of bounds) |
| 429 | Login lockout - see `Retry-After` |
| 500 | Internal failure: encryption, decryption, index, or storage |
| 501 | `Range` request on a v1 whole-object encrypted object |
| 503 | `KeystoreUnavailable` - daemon has no SK in memory (idle-dropped). Log in to install it. |

## Source

- [crates/y2qd/src/handlers/](../crates/y2qd/src/handlers/) - object, listing, and admin handlers
- [crates/y2qd/src/auth/handlers.rs](../crates/y2qd/src/auth/handlers.rs) - auth and user handlers
- [crates/y2qd/src/error.rs](../crates/y2qd/src/error.rs) - AppError → status mapping
- [crates/y2qd/src/auth/error.rs](../crates/y2qd/src/auth/error.rs) - AuthError → status mapping
