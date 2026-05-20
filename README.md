# y2q

Post-quantum secure object storage. `y2qd` is a REST daemon that encrypts every object at rest using ML-KEM-768 key encapsulation and AES-256-GCM, with token-based session authentication and a choice of storage backends.

> Early development - APIs and on-disk formats may change.

## Documentation

- [docs/architecture.md](docs/architecture.md) - system design, encryption envelope, storage backends, metadata index, sessions
- [docs/configuration.md](docs/configuration.md) - full config reference with all fields, defaults, and override syntax
- [docs/operations.md](docs/operations.md) - first run, user management, backup/recovery, runbook
- [docs/api.md](docs/api.md) - complete HTTP API reference: routes, schemas, error codes, examples

## Features

- **Post-quantum encryption at rest** - each object is encapsulated against an ML-KEM-768 public key; content and metadata is encrypted with AES-256-GCM via [ring](https://github.com/briansmith/ring) (5–7× faster than the pure-Rust aes-gcm crate)
- **Argon2id-protected secret key** - the ML-KEM private key is never stored in plaintext; it is wrapped under each user's password and only held in memory during an active session
- **Token-based session auth** - Bearer tokens with configurable TTL, per-account lockout after repeated failures
- **Dual storage backends** - portable filesystem backend (all platforms); optional Linux io_uring fast path (kernel ≥ 5.6); both use the same on-disk `.obj` format and are fully cross-compatible
- **Fast listing** - embedded [redb](https://github.com/cberner/redb) metadata index; auto-rebuilt on startup; can be manually triggered at any time
- **Best-effort mode with background flusher** - skip per-PUT fsyncs for throughput; a background task drains the dirty queue on a configurable interval
- **Custom object labels** - attach arbitrary key/value metadata to objects via `X-Y2Q-<label>` request headers on PUT
- **Prometheus metrics** - scrape endpoint at `/metrics/prometheus`; interactive dashboard at `/metrics/dashboard`; storage and auth counters with latency histograms
- **Structured observability** - per-request IDs (`X-Request-ID`), INFO/ERROR log events on every request, configurable log format (`text` or `json`)
- **Continuous profiling** - optional Pyroscope/pprof-rs integration; opt-in with `--features pyroscope`, ships CPU profiles to a Pyroscope server or Grafana Cloud
- **OpenAPI / Swagger UI** - interactive docs at `/swagger-ui/`

## Getting Started

### Prerequisites

- Rust toolchain (stable, edition 2024)
- Linux kernel ≥ 5.6 if using the `uring` backend (not required for `filesystem`)

### Build

```sh
cargo build --release -p y2qd
```

The io_uring backend is included by default (`uring` is a default feature, Linux only). To build without it (e.g. on macOS for tooling):

```sh
cargo build --release -p y2qd --no-default-features
```

To enable continuous profiling (Pyroscope/pprof-rs):

```sh
cargo build --release -p y2qd --features pyroscope
```

### First Run

On first startup, `y2qd` generates an ML-KEM-768 keypair and prints a one-time root password to stdout:

```
y2qd: first run - root password: <password>
y2qd: this password will not be shown again. Store it securely.
```

**This password is shown exactly once.** It is used to log in and create additional users. Store it before the line scrolls.

### Run

```sh
./target/release/y2qd --config config.toml
```

CLI flags:

| Flag | Default | Purpose |
|---|---|---|
| `--config <path>` | `config.toml` | Path to configuration file |
| `--set KEY=VALUE` | - | Override a config value, e.g. `--set server.port=9090` |

### Container

Build images locally with `make`:

```sh
make image          # y2q:latest  (filesystem backend)
make image-uring    # y2q:latest-uring  (io_uring backend, kernel >= 5.6)
make images         # both
```

Run with rootless podman:

```sh
podman run \
  --network=host \
  --userns=keep-id \
  --user $(id -u):$(id -g) \
  -v /path/to/config.toml:/etc/y2q/config.toml:ro \
  -v /path/to/data:/var/lib/y2q/data \
  -v /path/to/keys:/var/lib/y2q/keys \
  y2q:latest
```

`--network=host` gives the container direct access to the host network stack - required for rootless podman to expose a port without NAT.
`--userns=keep-id` maps your host UID into the container unchanged so bind-mounted directories are writable.

The image ships a default config at `/etc/y2q/config.toml` with `base_path = "/var/lib/y2q/data"` and `keystore_dir = "/var/lib/y2q/keys"`. Mount your own config over it or override individual values with environment variables (`Y2QD_SECTION__KEY=value`).

All three binaries (`y2qd`, `y2q`, `y2q-warp`) are present in the image. The entrypoint is `y2qd`; override to run the others:

```sh
podman run --entrypoint y2q --network=host ... y2q:latest ls prod/
```

**The root password is printed once on first run** - same as the native path. Check stdout/container logs before doing anything else.

## CLI (`y2q`)

Build the client:

```sh
cargo build --release -p y2q-cli
```

### Setup

Add a server profile and log in:

```sh
y2q config add prod https://y2qd.example
y2q login prod --user alice
```

Profiles and cached tokens are stored in `~/.config/y2q/config.toml` and `~/.local/share/y2q/tokens.toml`.

### Copying files

Upload a single file:

```sh
y2q cp report.pdf prod/documents/reports/q1.pdf
```

Upload from stdin:

```sh
tar czf - /etc | y2q cp - prod/backups/etc.tar.gz
```

Download to a file or stdout:

```sh
y2q cp prod/documents/reports/q1.pdf ./q1.pdf
y2q cat prod/documents/reports/q1.pdf | less
```

**Recursive directory upload** - preserves the local directory tree as remote key paths:

```sh
y2q cp -r ./photos prod/media/photos/
```

**Glob patterns** - shell-quote the pattern to prevent local shell expansion when you want y2q to expand it:

```sh
y2q cp '*.log' prod/logs/host1/
y2q cp -r './2024/**' prod/archive/2024/   # -r recurses into matched directories
```

Attach custom labels to an upload:

```sh
y2q cp notes.txt prod/docs/notes.txt --label project=y2q --label env=prod
```

Control durability:

```sh
y2q cp big.bin prod/data/big.bin --sync best-effort   # skip fsync for speed
```

### Listing and metadata

```sh
y2q ls prod/                    # list buckets
y2q ls prod/documents/          # list objects in bucket
y2q ls prod/documents/reports/  # list by prefix
y2q ls prod/documents/ --all    # auto-paginate
y2q stat prod/documents/reports/q1.pdf
```

### Deleting objects

Delete a single object:

```sh
y2q rm prod/documents/old.txt
```

Delete multiple objects matching a glob - prompts for confirmation before deleting:

```sh
y2q rm 'prod/logs/host1/*.log'
y2q rm 'prod/logs/host1/*.log' --force   # -f skips the prompt
```

### Admin

```sh
y2q admin user add prod bob
y2q admin user ls prod
y2q admin user rm prod bob

y2q admin rebuild start prod
y2q admin rebuild status prod

# List active in-flight PUTs held longer than a threshold
y2q admin locks ls prod --older-than 30m
# Force-release locks stuck longer than a threshold (use carefully)
y2q admin locks clear prod --older-than 30m
```

### Live trace

Stream every request hitting the server in real time, similar to `mc admin trace`:

```sh
y2q admin trace prod
```

Each line shows timestamp, method, path, HTTP status (colour-coded), latency, and payload sizes:

```
12:34:56.123  PUT      /bucket/key                               200    42.1ms      1.2 KiB↑    4.0 KiB↓
12:34:57.001  GET      /bucket/other/path                        200     1.2ms          -↑      3.4 KiB↓
12:34:58.400  DELETE   /bucket/missing                           404     0.8ms          -↑          -↓
```

Filter to errors only:

```sh
y2q admin trace prod --errors
```

Press Ctrl-C to disconnect. The server continues running with zero overhead when no trace client is connected.

### Shell completions

Print a completion script to stdout and install it:

```sh
# fish
y2q completions fish > ~/.config/fish/completions/y2q.fish

# zsh
y2q completions zsh > "${fpath[1]}/_y2q"

# bash
y2q completions bash > /etc/bash_completion.d/y2q
```

Supported shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`.

### TUI

Launch the interactive file explorer (also the default when no subcommand is given):

```sh
y2q tui
y2q         # same
```

### Global flags

| Flag | Short | Env | Effect |
|---|---|---|---|
| `--json` | `-j` | `Y2Q_OUTPUT` | Output as JSON |
| `--verbose` | `-v` | - | Increase log verbosity (repeatable) |
| `--config <path>` | - | - | Override config file location |

## Load Benchmarking (`y2q-warp`)

`y2q-warp` is a dedicated load benchmarking tool modelled after MinIO's `warp`. It runs timed workloads against a live `y2qd` server and records per-operation latencies to a compressed CSV file for offline analysis.

Build:

```sh
cargo build --release -p y2q-warp
```

### Workloads

```sh
# Single-operation benchmarks (5 minutes, 8 concurrent workers, 4 MiB objects)
y2q-warp prod put   --duration 5m --concurrent 8 --obj-size 4MiB
y2q-warp prod get   --duration 5m --concurrent 8 --objects 1000
y2q-warp prod stat  --duration 5m --concurrent 16
y2q-warp prod delete --duration 2m

# Mixed workload (GET 45% / PUT 15% / DELETE 25% / STAT 15%)
y2q-warp prod mixed --duration 10m --concurrent 16

# Pre-seed objects without timing, then run a read benchmark
y2q-warp prod prepare --objects 5000 --obj-size 1MiB
y2q-warp prod get --duration 5m --no-cleanup
y2q-warp prod cleanup
```

Variable-size objects:

```sh
y2q-warp prod put --obj-size-min 64KiB --obj-size-max 16MiB
```

### Offline analysis

```sh
y2q-warp analyze warp-mixed-*.csv.zst
y2q-warp analyze warp-put-*.csv.zst --op PUT --skip 5s
```

Outputs a per-operation summary table: throughput (MiB/s and ops/s), p50/p90/p99 latency, total ops, error count.

### TUI during a run

While a benchmark is running, a live ratatui TUI shows:
- Per-operation ops/s sparklines (stacked for mixed workloads)
- 4xx/5xx error rates
- Live throughput and latency

## Configuration

`config.default.toml` in the repo root contains every knob with inline comments. Copy it and fill in the three required fields (`server.host`, `server.port`, `storage.base_path`, `crypto.keystore_dir`). The sections below show the key options.

```toml
[server]
host = "127.0.0.1"
port = 8080
max_body_bytes = 268435456        # 256 MiB upload limit
unauthenticated_metrics = false   # expose /metrics/* and /swagger-ui/ without auth

# actix HttpServer tuning - entire section optional; omit to use actix defaults
[server.actix]
# workers = 4                     # default: number of logical CPUs
backlog = 1024
max_connections = 25000
keep_alive_secs = 5
shutdown_timeout_secs = 30

[storage]
base_path = "/var/lib/y2qd/objects"   # required
backend = "filesystem"                 # "filesystem" or "uring" (Linux, --features uring)
# index_path = "/var/lib/y2qd/objects/_y2q_index.redb"
max_labels = 32
max_label_name_bytes = 64
max_label_value_bytes = 1024
default_sync = "durable"              # "durable" (fsync) or "best-effort" (no fsync)
sync_flush_interval_secs = 5          # how often the background flusher drains best-effort writes
sync_flush_limit = 64                 # pending-write watermark that triggers an early flush

[crypto]
keystore_dir = "/var/lib/y2qd/keystore"   # required; keep separate from base_path
[crypto.argon2]
m_cost_kib = 65536   # 64 MiB
t_cost = 3
p_cost = 4

[auth]
default_ttl_seconds = 3600
max_ttl_seconds = 86400
session_sweep_interval_seconds = 300
min_login_response_ms = 250
max_failed_logins = 10
lockout_seconds = 900
keystore_idle_drop_seconds = 0

[observability]
log_filter = "info"      # RUST_LOG syntax; RUST_LOG env var takes precedence
log_format = "text"      # "text" or "json" (for Loki, Datadog, etc.)

# Continuous profiling — requires building with --features pyroscope
[observability.pyroscope]
enabled     = false
server_url  = "http://localhost:4040"
sample_rate = 100
# basic_auth_user     = "123456"   # Grafana Cloud numeric user ID
# basic_auth_password = "glc_..."  # Grafana Cloud API token
```

Environment variables override any config file value. Prefix the dotted key with `Y2QD_` and use `__` (two underscores) as the section separator - e.g. `Y2QD_SERVER__PORT=9090`, `Y2QD_OBSERVABILITY__LOG_FORMAT=json`. See [docs/configuration.md](docs/configuration.md) for the full schema.

## API Reference

All authenticated routes require `Authorization: Bearer <token>`.

### Auth

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/auth/login` | No | Obtain a Bearer token |
| `POST` | `/api/v1/auth/refresh` | Yes | Extend session TTL (old token revoked) |
| `POST` | `/api/v1/auth/logout` | Yes | Revoke the current token |
| `POST` | `/api/v1/auth/password` | Yes | Change password |

### Users

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `PUT` | `/api/v1/users/add` | Yes | Create a new user |
| `GET` | `/api/v1/users` | Yes | List all users |
| `DELETE` | `/api/v1/users/{user}` | Yes | Delete a user (refuses if last user) |

### Objects

Object keys may contain `/`. Use `/{bucket}/{key}` where `{key}` is the full path after the bucket name.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `PUT` | `/{bucket}/{key}` | Yes | Store an object (encrypted) |
| `GET` | `/{bucket}/{key}` | Yes | Retrieve an object (decrypted) |
| `DELETE` | `/{bucket}/{key}` | Yes | Delete an object |
| `HEAD` | `/{bucket}/{key}` | Yes | Object metadata only |

**Custom labels on PUT:** Include `X-Y2Q-<label>: <value>` headers to attach metadata to the object.

### Listing

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/` | Yes | List all non-empty buckets |
| `GET` | `/{bucket}/` | Yes | List objects in a bucket |

Listing query parameters: `?prefix=<str>`, `?after=<cursor>`, `?limit=<n>`.

### Admin

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/rebuild` | Yes | Start a metadata index rebuild |
| `GET` | `/api/v1/rebuild` | Yes | Poll rebuild status |
| `GET` | `/api/v1/locks` | Yes | List active in-flight write locks older than a threshold |
| `DELETE` | `/api/v1/locks` | Yes | Force-release write locks older than a threshold |

### Observability

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/metrics/prometheus` | Configurable | Prometheus scrape endpoint |
| `GET` | `/metrics/dashboard` | Configurable | Interactive metrics dashboard |
| `GET` | `/swagger-ui/` | No | Interactive API documentation |

Auth for metrics and Swagger UI is controlled by `server.unauthenticated_metrics` in config.

## Security Model

Every PUT encapsulates a fresh ephemeral keypair against the server's ML-KEM-768 public key. The resulting shared secret is passed through HKDF-SHA256 to derive a per-object AES-256-GCM content key. The ciphertext and encapsulated key are stored together; GET reverses the process using the private key held in process memory.

The ML-KEM private key is never written to disk in plaintext. At rest it is wrapped under each user's password with Argon2id. On login the correct user's wrapped copy is unwrapped, the plaintext key is loaded into memory, and it is zeroized on drop. If `auth.keystore_idle_drop_seconds` is set, the key is also dropped after the configured idle period.

## Development

```sh
make build     # debug build, all workspace crates
make test      # run all tests
make clippy    # lint (warnings as errors)
make fmt       # format
make check     # fmt-check + clippy + test (CI gate)
```

Run `make help` for all targets including per-binary builds, uring variants, and image targets.
