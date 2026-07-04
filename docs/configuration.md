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
| `unauthenticated_metrics` | bool | `false` | When `true`, `/metrics/prometheus`, `/metrics/dashboard`, `/swagger-ui/`, and `/api-docs/openapi.json` are exposed without a Bearer token. When `false` (default) they are **not registered at all** - there is no auth-gated variant; the daemon logs that they are disabled. |

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

When clustering with `cluster.auth = "mtls"`, `client_ca_path` is also what peer connections are verified against.

### `[storage]`

| Field | Type | Default | Notes |
|---|---|---|---|
| `backend` | enum | `"filesystem"` | Either `"filesystem"` or `"uring"`. `uring` requires Linux ≥ 5.6 and is always compiled in on Linux (no cargo feature); on non-Linux targets it is unavailable and selecting it returns a runtime error. Both backends use the same on-disk `.obj` format and files are cross-compatible. |
| `base_path` | string | *required* | Root directory for the object tree. Created on first write if absent. |
| `index_path` | string | `<base_path>/_y2q_index.redb` | Path to the redb metadata index file. The whole file is encrypted at rest under a key derived from the login-gated MEK; it is opened on first login and closed on idle. Override to put the index on a faster disk. |
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
| `keystore_dir` | string | *required* | Directory holding `pubkey.json`, `users.redb`, and the daemon's `.lock`. Should be on a path you back up; should *not* live under `storage.base_path` so a `cp -r` of the storage tree can't accidentally copy authentication state. |
| `envelope_chunk_size_bytes` | usize | `4194304` (4 MiB) | Plaintext chunk size for v2 streaming encryption. Bounds: `65536` (64 KiB) .. `268435456` (256 MiB); out-of-range values are rejected at startup. Smaller chunks make ranged GETs finer-grained but add per-chunk AEAD overhead. **Recorded per-object in the envelope header** - see note below. |
| `argon2` | table | *(see below)* | Argon2id parameters used when writing *new* user records (existing users keep their stored parameters). |

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
| `session_sweep_interval_seconds` | u64 | `300` (5 min) | How often the background sweeper purges expired sessions and runs idle-keystore reconciliation. |
| `min_login_response_ms` | u64 | `250` | Floor on login response latency, success or failure. Smooths timing differences between "user not found" and "wrong password". |
| `max_failed_logins` | u32 | `10` | Consecutive failed logins per username before lockout. Set to `0` to disable lockout. |
| `lockout_seconds` | u64 | `900` (15 min) | Lockout duration once `max_failed_logins` is hit. |
| `keystore_idle_drop_seconds` | u64 | `0` | Drop the in-memory decrypted SK this many seconds after the last session expires. `0` = drop immediately on the next sweep. Raise to forgive brief gaps between sessions; lower to bound how long the SK lives in memory. |
| `enforce_authorization` | bool | `true` | Enforce per-bucket ownership/ACLs and the global admin role. New buckets are private to their creator; admin endpoints (user management, rebuild, locks, trace) require an admin account. Set `false` for a single-user or migration deployment where every authenticated user should have full access. See the [API authorization model](api.md#authorization). |

### `[observability]`

| Field | Type | Default | Notes |
|---|---|---|---|
| `log_filter` | string | `"info"` | Log level directive in RUST_LOG syntax. Examples: `"info"`, `"y2qd=debug,actix_web=info"`, `"y2q_core::storage::filesystem=trace"`. The `RUST_LOG` environment variable takes precedence when set. |
| `log_format` | enum | `"text"` | `"text"` - human-readable coloured output. `"json"` - structured JSON, one object per line; suited for aggregators like Grafana Loki, Elasticsearch, or Datadog. |

### `[observability.pyroscope]`

Continuous CPU profiling via pprof-rs shipped to a Pyroscope server or Grafana Cloud. Requires building with `--features pyroscope`. All fields have safe defaults; the section can be omitted entirely.

| Field | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Start the Pyroscope agent on daemon startup. Must be `true` to collect profiles. |
| `server_url` | string | `"http://localhost:4040"` | Pyroscope server URL. For Grafana Cloud use the profiling push endpoint shown in your stack settings. |
| `sample_rate` | u32 | `100` | pprof CPU sampling rate in Hz. Higher rates give finer resolution at the cost of overhead. 100 Hz is a good default. |
| `basic_auth_user` | string | *(none)* | HTTP Basic auth username. Grafana Cloud uses a numeric user ID. Omit for unauthenticated servers. |
| `basic_auth_password` | string | *(none)* | HTTP Basic auth password. Grafana Cloud uses an API token with profiling write scope. Omit for unauthenticated servers. |

Tags attached to every profile: `version` (daemon version), `backend` (`"filesystem"` or `"uring"`).

The agent runs a background OS thread using SIGPROF; it does not interact with the tokio runtime and has negligible impact on request latency.

### `[cluster]` and `[cluster.raft]`

Distributed mode (**experimental** - functional and tested, but young and not yet recommended for production data). **Disabled by default** (`enabled = false`) - the whole section is optional and every key is defaulted; with it off the daemon is byte-for-byte single-node. Enabling clustering requires the **same deployment keystore on every node** (the key hierarchy is derived deterministically from it). This table is a quick reference; the full design, bootstrap/join procedure, voter/learner split, and migration live in [clustering.md](clustering.md).

| Field | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Master switch. `false` => single node, no clustering behavior. |
| `node_id` | string | *(derived)* | Explicit `u64` node id; empty derives and persists one. |
| `advertise_addr` | string | *(none)* | `host:port` peers dial for the internal API. **Required when `enabled`.** |
| `replication_factor` | usize | `3` | `R` = chain length (replicas per object); clamped to membership. |
| `virtual_nodes_per_node` | u32 | `256` | Consistent-hash ring smoothing. |
| `consistency` | enum | `"strong"` | `strong` \| `eventual` \| `eventual-bounded`. |
| `eventual_bound_ms` | u64 | `2000` | Freshness window for `eventual-bounded` reads. |
| `prepare_timeout_ms` | u64 | `30000` | Per-hop PREPARE forward timeout. |
| `ack_timeout_ms` | u64 | `30000` | HEAD wait for full-chain commit. |
| `auth` | enum | `"shared-secret"` | `shared-secret` \| `mtls`. `mtls` reuses `[server.tls] client_ca_path`. |
| `shared_secret` | string | *(none)* | Peer-auth secret when `auth = "shared-secret"`; prefer `Y2QD_CLUSTER__SHARED_SECRET`. |
| `health_probe_interval_ms` | u64 | `1000` | Inter-node health probe cadence. |
| `health_fail_threshold` | u32 | `3` | Consecutive failed probes before a node is marked down. |
| `unlock` | enum | `"provisioned"` | Boot unlock mode so peer writes commit unattended. |
| `unlock_secret_file` | string | *(none)* | File holding the provisioned unlock secret; or set `Y2QD_CLUSTER__UNLOCK_SECRET`. |
| `raft.heartbeat_interval_ms` | u64 | `250` | Raft heartbeat cadence. |
| `raft.election_timeout_min_ms` | u64 | `1000` | Election timeout lower bound. |
| `raft.election_timeout_max_ms` | u64 | `1500` | Election timeout upper bound. |
| `raft.log_dir` | string | `<base_path>/_y2q_raft` | Raft log/state directory. |
| `raft.bootstrap` | bool | `false` | Set `true` on exactly **one** node's first boot to initialize Raft. |
| `raft.role` | enum | `"auto"` | `auto` (use `voter_seeds`) \| `voter` \| `learner`. |
| `raft.voter_seeds` | array | `[]` | Node ids forming the voting quorum (size 3/5/7). Set identically on every node. |

`Vec` fields (`cluster.peers`, `raft.voter_seeds`) cannot be set through environment variables - use a config file for those.

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
envelope_chunk_size_bytes = 4194304   # 4 MiB plaintext chunks

[crypto.argon2]
m_cost_kib = 131072                    # 128 MiB - doubled from default
t_cost = 3
p_cost = 4

[auth]
default_ttl_seconds = 3600
max_ttl_seconds = 28800                # 8 hours
session_sweep_interval_seconds = 60    # sweep every minute for tighter idle drop
min_login_response_ms = 500
max_failed_logins = 5
lockout_seconds = 1800                 # 30 min
keystore_idle_drop_seconds = 300       # forget SK 5 min after last logout
enforce_authorization = true           # bucket ownership/ACLs + admin role

[observability]
log_filter = "y2qd=info,actix_web=warn"
log_format = "json"                    # ship to a log aggregator

[observability.pyroscope]
enabled     = false
server_url  = "http://localhost:4040"
sample_rate = 100
# basic_auth_user     = "123456"
# basic_auth_password = "glc_..."
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

Per-request spans flow through `tracing-actix-web`. Each HTTP request gets a span with method, path, status, elapsed time, and a UUID `X-Request-ID`. Override verbosity with `RUST_LOG=tracing_actix_web=warn` if it's too noisy.

The other binaries have no `[observability]` config section - they log to stderr and are controlled by `RUST_LOG` alone:

- **`y2q`** - defaults to `warn`; `--verbose`/`-v` (repeatable) raises it to `info`/`debug`/`trace`, `--debug` forces `trace`, `--quiet` forces `error`. `RUST_LOG`, if set, always wins over these flags.
- **`y2q-warp`** - defaults to `error` (`EnvFilter::from_default_env()`'s built-in default) when `RUST_LOG` is unset; there is no `-v` flag.
- **`y2q-fuse`** - defaults to `warn` when `RUST_LOG` is unset.

## Source

- [crates/y2qd/src/config.rs](../crates/y2qd/src/config.rs) - schema, defaults, and Figment wiring (includes `ActixConfig`, `ObservabilityConfig`, `SyncLevel`)
- [crates/y2qd/src/cli.rs](../crates/y2qd/src/cli.rs) - `--config` and `--set` parsing
- [crates/y2q-config/src/config.rs](../crates/y2q-config/src/config.rs) - shared config types used by `y2q-cli` and `y2q-warp`
- [config.default.toml](../config.default.toml) - fully-commented reference for every daemon knob
