# Configuration Reference

`y2qd` is configured from three layered sources, merged in priority order (lowest first):

1. **TOML file** named by `--config` (default `./config.toml`)
2. **Environment variables** prefixed `Y2QD_` with `__` (two underscores) as the section separator
3. **CLI overrides** via repeatable `--set KEY=VALUE` arguments, using `.` as the section separator

Later sources win. Anything not set at all falls back to the documented default (or rejects the load if the field is required).

## Required fields

These three have no default — the daemon will refuse to start without them:

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

Single underscores are kept as-is — `max_body_bytes` stays `MAX_BODY_BYTES`.

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
| `host` | string | *required* | Bind address — `127.0.0.1` for local-only, `0.0.0.0` for all interfaces |
| `port` | u16 | *required* | TCP port |
| `max_body_bytes` | usize | `268435456` (256 MiB) | Maximum PUT request body size |
| `unauthenticated_metrics` | bool | `false` | When `true`, `/metrics/prometheus`, `/metrics/dashboard`, and `/swagger-ui/` are exposed without a Bearer token. Default keeps them auth-gated. |

### `[storage]`

| Field | Type | Default | Notes |
|---|---|---|---|
| `backend` | enum | `"filesystem"` | Either `"filesystem"` or `"uring"`. `uring` requires the daemon to be built with `--features uring` on Linux ≥ 5.6. |
| `base_path` | string | *required* | Root directory for the object tree. Created on first write if absent. |
| `index_path` | string | `<base_path>/_y2q_index.redb` | Path to the redb metadata index file. Override to put the index on a faster disk. |
| `max_labels` | usize | `32` | Maximum `X-Y2Q-<label>` headers accepted per PUT. |
| `max_label_name_bytes` | usize | `64` | Maximum byte length of a label name (after stripping `X-Y2Q-` and lowercasing). |
| `max_label_value_bytes` | usize | `1024` | Maximum byte length of a label value. |

The reserved bucket name `"api"` (case-insensitive) is rejected — it would collide with the `/api/v1/...` admin routes. Object keys are also bounded to 1024 bytes and must not contain null bytes.

### `[crypto]`

| Field | Type | Default | Notes |
|---|---|---|---|
| `keystore_dir` | string | *required* | Directory holding `pubkey.json`, `users.redb`, and the daemon's `.lock`. Should be on a path you back up; should *not* live under `storage.base_path` so a `cp -r` of the storage tree can't accidentally copy authentication state. |
| `argon2` | table | *(see below)* | Argon2id parameters used when writing *new* user records (existing users keep their stored parameters). |

### `[crypto.argon2]`

| Field | Type | Default | Notes |
|---|---|---|---|
| `m_cost_kib` | u32 | `65536` (64 MiB) | Memory cost per hash. Doubling it doubles the brute-force cost. |
| `t_cost` | u32 | `3` | Iteration count. |
| `p_cost` | u32 | `4` | Parallel lanes. |

Defaults follow OWASP's "second-tier" recommendation. Raise `m_cost_kib` first if you want more cost — it's the parameter attackers can't easily parallelize across cheap hardware.

Changing these only affects newly written records. Existing user records carry the parameters they were created with. To migrate a user to stronger parameters, call `POST /api/v1/auth/password` while logged in as that user — the SK gets re-wrapped under the current defaults.

### `[auth]`

| Field | Type | Default | Notes |
|---|---|---|---|
| `default_ttl_seconds` | u64 | `3600` (1 hour) | Session lifetime when `ttl_seconds` is omitted on login. |
| `max_ttl_seconds` | u64 | `86400` (24 hours) | Hard ceiling — logins requesting `ttl_seconds > max_ttl_seconds` get a 400. |
| `session_sweep_interval_seconds` | u64 | `300` (5 min) | How often the background sweeper purges expired sessions and runs idle-keystore reconciliation. |
| `min_login_response_ms` | u64 | `250` | Floor on login response latency, success or failure. Smooths timing differences between "user not found" and "wrong password". |
| `max_failed_logins` | u32 | `10` | Consecutive failed logins per username before lockout. Set to `0` to disable lockout. |
| `lockout_seconds` | u64 | `900` (15 min) | Lockout duration once `max_failed_logins` is hit. |
| `keystore_idle_drop_seconds` | u64 | `0` | Drop the in-memory decrypted SK this many seconds after the last session expires. `0` = drop immediately on the next sweep. Raise to forgive brief gaps between sessions; lower to bound how long the SK lives in memory. |

## Worked example

```toml
[server]
host = "0.0.0.0"
port = 8443
max_body_bytes = 1073741824           # 1 GiB
unauthenticated_metrics = false

[storage]
backend = "uring"
base_path = "/var/lib/y2qd/objects"
index_path = "/var/lib/y2qd/index/objects.redb"
max_labels = 64
max_label_name_bytes = 128
max_label_value_bytes = 4096

[crypto]
keystore_dir = "/var/lib/y2qd/keystore"

[crypto.argon2]
m_cost_kib = 131072                    # 128 MiB — doubled from default
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
```

## Logging

Tracing is configured from `RUST_LOG`. Examples:

```sh
RUST_LOG=info                                  # default if unset
RUST_LOG=y2qd=debug,actix_web=info             # debug the daemon, info from actix
RUST_LOG=y2q_core::storage::filesystem=trace   # trace one module
```

## Source

- [crates/y2qd/src/config.rs](../crates/y2qd/src/config.rs) — schema, defaults, and Figment wiring
- [crates/y2qd/src/cli.rs](../crates/y2qd/src/cli.rs) — `--config` and `--set` parsing
