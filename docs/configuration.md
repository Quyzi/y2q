# Configuration Reference

`y2qd` is configured from three layered sources, merged in priority order (lowest first):

1. **TOML file** named by `--config` (default `./config.toml`)
2. **Environment variables** prefixed `Y2QD_` with `__` (two underscores) as the section separator
3. **CLI overrides** via repeatable `--set KEY=VALUE` arguments, using `.` as the section separator

Later sources win. Anything not set at all falls back to the documented default (or rejects the load if the field is required).

## Required fields

These three have no default - the daemon will refuse to start without them:

| Field | Why it's required |
|---|---|
| `server.host` | No safe default; explicit binding prevents accidentally exposing the daemon |
| `server.port` | No safe default |
| `storage.base_path` | No safe default; refusing to start prevents accidentally writing into a tmpfs |
| `crypto.keystore_dir` | No safe default; must be a path you intend to back up |

## Override syntax

### TOML

```toml
[server]
port = 9090
```

### Environment variable

The full dotted path becomes `Y2QD_<SECTION>__<FIELD>`, with section/field separator `__` (two underscores):

```sh
Y2QD_SERVER__PORT=9090
Y2QD_STORAGE__BACKEND=uring
Y2QD_CRYPTO__ARGON2__M_COST_KIB=131072
Y2QD_AUTH__KEYSTORE_IDLE_DROP_SECONDS=600
```

Single underscores are kept as-is - `max_body_bytes` stays `MAX_BODY_BYTES`.

### CLI `--set`

```sh
y2qd --set server.port=9090
y2qd --set storage.backend=uring --set storage.max_labels=64
y2qd --set crypto.argon2.m_cost_kib=131072
```

CLI values are coerced as integer first, then `true`/`false`, then string.

## Full schema

### `[server]`

| Field | Type | Default | Notes |
|---|---|---|---|
| `host` | string | *required* | Bind address - `127.0.0.1` for local-only, `0.0.0.0` for all interfaces |
| `port` | u16 | *required* | TCP port |
| `max_body_bytes` | usize | `268435456` (256 MiB) | Maximum PUT request body size |
| `unauthenticated_metrics` | bool | `false` | When `true`, `/metrics/prometheus` and `/api-docs/openapi.json` are exposed without a Bearer token. When `false` (default) they are **not registered at all** - there is no auth-gated variant; the daemon logs that they are disabled. |
| `allow_insecure_bind` | bool | `false` | Permit binding a non-loopback `host` while `[server.tls] enabled = false`. Defaults to `false`: the daemon refuses to start rather than silently serve session tokens, passwords, and object plaintext unencrypted. Loopback (`127.0.0.1`/`::1`/`localhost`) is always permitted regardless of this flag. |
| `allow_unprotected_memory` | bool | `false` | Permit starting when guarded memory is unavailable (Linux only - e.g. `RLIMIT_MEMLOCK` too low to lock session key pages out of swap; see [SECURITY.md](../SECURITY.md#guarded-memory-linux-only) for the full mechanism). Defaults to `false`: the daemon refuses to start rather than hold session identity keys in swappable, dumpable, core-dumpable memory. Has no effect on non-Linux builds, where guarded memory is unconditionally unavailable and startup never refuses on this basis. |

### `[server.actix]`

The entire section is optional. Omitting it leaves actix's compiled-in defaults in effect.

| Field | Type | Default | Notes |
|---|---|---|---|
| `workers` | u32 | *(logical CPUs)* | Worker thread count. Comment out or omit to use the OS-reported CPU count. |
| `backlog` | u32 | `1024` | TCP listen backlog - depth of the kernel's accept queue. |
| `max_connections` | usize | `25000` | Maximum concurrent connections handled per worker thread. |
| `keep_alive_secs` | u64 | `5` | Keep-alive idle timeout in seconds. Set to `0` to disable keep-alive. |
| `client_request_timeout_secs` | u64 | `5` | How long to wait for the first request bytes after accepting a connection. Silent connections are closed. |
| `client_disconnect_timeout_secs` | u64 | `1` | How long to wait for the client to close after the final response is sent. |
| `shutdown_timeout_secs` | u64 | `30` | Graceful shutdown window - in-flight requests have this long to complete after SIGTERM. |

### `[server.tls]`

Optional. When `enabled = true` the daemon binds **HTTPS** at `[server] port` using rustls and refuses plaintext HTTP entirely; `cert_path` and `key_path` become required. To run HTTP and HTTPS side by side, run two `y2qd` processes on different ports - this section flips a single listener between modes.

| Field | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Bind HTTPS instead of HTTP. |
| `cert_path` | string | *(none)* | PEM certificate chain (fullchain). Required when `enabled`. |
| `key_path` | string | *(none)* | PEM private key (PKCS#8, PKCS#1, or SEC1). Required when `enabled`. |
| `client_ca_path` | string | *(none)* | PEM CA bundle for **mutual TLS**. When set, every client must present a certificate chaining to one of these CAs or the handshake is rejected. Leave unset to accept clients without a client cert. |
| `require_pq_kex` | bool | `true` | When `true`, offer **only** the X25519MLKEM768 post-quantum hybrid key-exchange group; clients that cannot negotiate it are refused at handshake time. Set `false` to fall back to rustls's default preference list (PQ-hybrid preferred, classic X25519/ECDH still offered). |

### `[storage]`

| Field | Type | Default | Notes |
|---|---|---|---|
| `backend` | enum | `"filesystem"` | Either `"filesystem"` or `"uring"`. `uring` requires Linux ≥ 5.6 and is always compiled in on Linux (no cargo feature); on non-Linux targets it is unavailable and selecting it returns a runtime error. Both backends use the same on-disk `.obj` format and files are cross-compatible. |
| `base_path` | string | *required* | Root directory for the object tree. Created on first write if absent. |
| `index_path` | string | `<base_path>/_y2q_index.redb` | Path to the redb metadata index file. The whole file is encrypted at rest under a key derived from the operator-supplied node key; it is resident for the daemon's whole lifetime (no idle-drop). Override to put the index on a faster disk. |
| `max_labels` | usize | `32` | Maximum `X-Y2Q-<label>` headers accepted per PUT. |
| `max_label_name_bytes` | usize | `64` | Maximum byte length of a label name (after stripping `X-Y2Q-` and lowercasing). |
| `max_label_value_bytes` | usize | `1024` | Maximum byte length of a label value. |
| `default_sync` | enum | `"durable"` | Default durability for PUT requests that omit the `X-Y2Q-Sync` header. `"durable"` fsyncs the object and parent directory before responding (crash-safe). `"best-effort"` skips fsyncs; a background flusher drains the write queue asynchronously. Per-request `X-Y2Q-Sync` header overrides this. |
| `sync_flush_interval_secs` | u64 | `5` | How often (in seconds) the background best-effort flusher wakes to drain pending writes. Minimum 1. Only relevant when `default_sync = "best-effort"` or when requests override to `X-Y2Q-Sync: best-effort`. |
| `sync_flush_limit` | usize | `64` | Queue depth at which the flusher wakes early (before the timer fires). Acts as a watermark; entries are never dropped. |

The reserved bucket name `"api"` (case-insensitive) is rejected - it would collide with the `/api/v1/...` admin routes. Object keys are also bounded to 1024 bytes and must not contain null bytes.

### `[crypto]`

| Field | Type | Default | Notes |
|---|---|---|---|
| `keystore_dir` | string | *required* | Directory holding `keystore.json`, `users.redb`, and the daemon's `.lock`. Should be on a path you back up; should *not* live under `storage.base_path` so a `cp -r` of the storage tree can't accidentally copy authentication state. |
| `node_key_file` | string | *(none)* | Path to a file holding the operator-supplied node key (raw binary, hex, or base64; at least 32 bytes). Alternatively set `Y2QD_NODE_KEY`. One of the two is required - the daemon refuses to start without it and never auto-generates one. Must not live inside `storage.base_path` or `crypto.keystore_dir` (enforced at startup). |
| `envelope_chunk_size_bytes` | usize | `4194304` (4 MiB) | Plaintext chunk size for the v3/v4 chunked streaming envelope (current writes are v4; see [architecture.md#envelope-format](architecture.md#envelope-format)). Bounds: `65536` (64 KiB) .. `268435456` (256 MiB); out-of-range values are rejected at startup. Smaller chunks make ranged GETs finer-grained but add per-chunk AEAD overhead. **Recorded per-object in the envelope header** - see note below. |
| `argon2` | table | *(see below)* | Argon2id parameters used when writing *new* credential slots (existing slots keep their stored parameters). |

The chunk size is stored in each object's envelope header, and decryption always
reads it from there. Changing `envelope_chunk_size_bytes` therefore only affects
objects written *after* the change - existing objects keep decrypting (and serving
ranged reads) with their own stored size. There is no global re-chunking and no
risk to already-stored data; the "don't change it" caution you may expect from
fixed-block formats does not apply here.

### `[crypto.argon2]`

| Field | Type | Default | Notes |
|---|---|---|---|
| `m_cost_kib` | u32 | `65536` (64 MiB) | Memory cost per hash. Doubling it doubles the brute-force cost. |
| `t_cost` | u32 | `3` | Iteration count. |
| `p_cost` | u32 | `4` | Parallel lanes. |

Defaults follow OWASP's "second-tier" recommendation. Raise `m_cost_kib` first if you want more cost - it's the parameter attackers can't easily parallelize across cheap hardware.

Changing these only affects newly written records. Existing user records carry the parameters they were created with. To migrate a user to stronger parameters, call `POST /api/v1/auth/password` while logged in as that user - the SK gets re-wrapped under the current defaults.

### `[auth]`

| Field | Type | Default | Notes |
|---|---|---|---|
| `default_ttl_seconds` | u64 | `3600` (1 hour) | Session lifetime when `ttl_seconds` is omitted on login. |
| `max_ttl_seconds` | u64 | `86400` (24 hours) | Hard ceiling - logins requesting `ttl_seconds > max_ttl_seconds` get a 400. |
| `session_sweep_interval_seconds` | u64 | `300` (5 min) | How often the background sweeper purges expired sessions from memory. |
| `min_login_response_ms` | u64 | `250` | Floor on login response latency, success or failure. Smooths timing differences between "user not found" and "wrong password". |
| `max_failed_logins` | u32 | `10` | Consecutive failed logins per username before lockout. Set to `0` to disable lockout. |
| `lockout_seconds` | u64 | `900` (15 min) | Lockout duration once `max_failed_logins` is hit. |
| `enforce_authorization` | bool | `true` | Enforce per-bucket ownership/ACLs and the global admin role. New buckets are private to their creator; admin endpoints (user management, rebuild, locks, trace) require an admin account. Set `false` for a single-user or migration deployment where every authenticated user should have full access. See the [API authorization model](api.md#authorization). |
| `max_refreshes` | u32 | `0` | Maximum times a token may be refreshed via `POST /api/v1/auth/refresh` before it's rejected with 403. `0` (default) disables refresh entirely - the first attempt on any token fails. A token past its limit is not revoked; it keeps authenticating normally elsewhere until it naturally expires. |

### `[s3]`

Optional S3-compatible gateway: a second HTTP(S) listener speaking AWS SigV4/S3 REST semantics. Entirely disabled by default; every field below is inert unless `enabled = true`. Full protocol/security model: [api.md#s3-gateway](api.md#s3-gateway), [../SECURITY.md#s3-gateway](../SECURITY.md#s3-gateway).

| Field | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Whether the second listener binds at all. |
| `host` | string | `"127.0.0.1"` | Bind address for the S3 listener. |
| `port` | u16 | `9000` | TCP port for the S3 listener. |
| `region` | string | `"y2q"` | SigV4 credential-scope region. Must match what S3 clients are configured with; a mismatch fails the request with `AuthorizationHeaderMalformed` rather than silently accepting it. Must not be empty (checked unconditionally, even when `enabled = false`). |
| `virtual_host_domain` | string | `""` | Base domain for virtual-hosted-style addressing (`<bucket>.<domain>`). Empty (default) accepts path-style addressing only (`http://host:port/bucket/key`). Must not start with `.` when set. |
| `default_credential_ttl_seconds` | u64 | `3600` (1 hour) | Default lifetime for a minted S3 credential when `POST /api/v1/s3/credentials` omits `ttl_seconds`. Always clamped to `min(requested, session.expires_at)` regardless of this value. |
| `max_credentials_per_session` | usize | `4` | Maximum live S3 credentials one session may hold. Minting past this FIFO-evicts the session's oldest credential. |
| `session_recheck_bytes` | u64 | `8388608` (8 MiB) | Re-validate the owning session after this many bytes transferred on an S3 upload/download stream. Minimum `65536` when `enabled = true`. |
| `session_recheck_interval_secs` | u64 | `5` | Re-validate the owning session at least this often during a transfer, regardless of byte count. Minimum `1` when `enabled = true`. |
| `max_clock_skew_secs` | u64 | `900` | Maximum accepted deviation between a request's `X-Amz-Date` and server time before it's rejected with `RequestTimeTooSkewed`. |
| `max_part_bytes` | u64 | `67108864` (64 MiB) | Maximum bytes accepted for a single multipart upload part. Must be at least `5242880` (S3's own minimum part size, checked unconditionally) and must not exceed `[server] max_body_bytes`. |
| `allow_insecure_bind` | bool | `false` | Permit binding a non-loopback `[s3] host` while `[s3.tls] enabled = false`. Same rationale and loopback exemption as `[server] allow_insecure_bind`. |

### `[s3.tls]`

TLS settings for the S3 listener, completely independent of `[server.tls]` - the two listeners can run with different TLS configurations (or one with TLS and one without). Same field shapes and semantics as `[server.tls]` above: `enabled`, `cert_path`, `key_path`, `client_ca_path` (mutual TLS), `require_pq_kex` (default `true`).

### `[observability]`

| Field | Type | Default | Notes |
|---|---|---|---|
| `log_filter` | string | `"info"` | Log level directive in RUST_LOG syntax. Examples: `"info"`, `"y2qd=debug,actix_web=info"`, `"y2q_core::storage::filesystem=trace"`. The `RUST_LOG` environment variable takes precedence when set. |
| `log_format` | enum | `"text"` | `"text"` - human-readable coloured output. `"json"` - structured JSON, one object per line; suited for aggregators like Grafana Loki, Elasticsearch, or Datadog. |

## Worked example

```toml
[server]
host = "0.0.0.0"
port = 8443
max_body_bytes = 1073741824           # 1 GiB
unauthenticated_metrics = false

[server.actix]
# workers = 8                         # defaults to logical CPU count
backlog = 2048
max_connections = 50000
keep_alive_secs = 10
shutdown_timeout_secs = 60

[storage]
backend = "uring"
base_path = "/var/lib/y2qd/objects"
index_path = "/var/lib/y2qd/index/objects.redb"
max_labels = 64
max_label_name_bytes = 128
max_label_value_bytes = 4096
default_sync = "durable"              # change to "best-effort" for max throughput
sync_flush_interval_secs = 5
sync_flush_limit = 128

[crypto]
keystore_dir = "/var/lib/y2qd/keystore"
node_key_file = "/etc/y2qd/node.key"  # or set Y2QD_NODE_KEY
envelope_chunk_size_bytes = 4194304   # 4 MiB plaintext chunks

[crypto.argon2]
m_cost_kib = 131072                    # 128 MiB - doubled from default
t_cost = 3
p_cost = 4

[auth]
default_ttl_seconds = 3600
max_ttl_seconds = 28800                # 8 hours
session_sweep_interval_seconds = 60    # sweep every minute for tighter expiry cleanup
min_login_response_ms = 500
max_failed_logins = 5
lockout_seconds = 1800                 # 30 min
enforce_authorization = true           # bucket ownership/ACLs + admin role
max_refreshes = 3                      # allow a handful of refreshes before requiring a fresh login

[s3]
enabled = true
host    = "0.0.0.0"
port    = 9000
region  = "us-east-1"                  # match whatever region S3 clients are configured with

[s3.tls]
enabled   = true
cert_path = "/etc/y2qd/tls/fullchain.pem"
key_path  = "/etc/y2qd/tls/privkey.pem"

[observability]
log_filter = "y2qd=info,actix_web=warn"
log_format = "json"                    # ship to a log aggregator
```

## Logging

Logging is controlled by `[observability]` in config (or the `RUST_LOG` environment variable, which takes precedence). Examples:

```sh
# via environment variable (overrides config)
RUST_LOG=info y2qd
RUST_LOG=y2qd=debug,actix_web=info y2qd
RUST_LOG=y2q_core::storage::filesystem=trace y2qd   # very loud

# via config (no env var needed)
[observability]
log_filter = "y2qd=debug,actix_web=info"
log_format = "json"    # structured output for log aggregators
```

Per-request spans flow through `tracing-actix-web`. Each HTTP request gets a span with method, path, status, elapsed time, and a 32-character hex `X-Request-ID`. Override verbosity with `RUST_LOG=tracing_actix_web=warn` if it's too noisy.

The other binaries have no `[observability]` config section - they log to stderr and are controlled by `RUST_LOG` alone:

- **`y2q`** - defaults to `warn`; `--verbose`/`-v` (repeatable) raises it to `info`/`debug`/`trace`, `--debug` forces `trace`, `--quiet` forces `error`. `RUST_LOG`, if set, always wins over these flags.
- **`y2q-warp`** - defaults to `error` (`EnvFilter::from_default_env()`'s built-in default) when `RUST_LOG` is unset; there is no `-v` flag.
- **`y2q-fuse`** - defaults to `warn` when `RUST_LOG` is unset.

## Source

- [crates/y2qd/src/config.rs](../crates/y2qd/src/config.rs) - schema, defaults, and Figment wiring (includes `ActixConfig`, `ObservabilityConfig`, `SyncLevel`)
- [crates/y2qd/src/cli.rs](../crates/y2qd/src/cli.rs) - `--config` and `--set` parsing
- [crates/y2q-config/src/config.rs](../crates/y2q-config/src/config.rs) - shared config types used by `y2q-cli` and `y2q-warp`
- [config.default.toml](../config.default.toml) - fully-commented reference for every daemon knob
