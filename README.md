# y2q

Post-quantum secure object storage. `y2qd` is a REST daemon that encrypts every object at rest using ML-KEM-768 key encapsulation and AES-256-GCM, with token-based session authentication, per-bucket access control, optional post-quantum TLS, and an optional distributed mode (CRAQ chain replication over an embedded Raft control plane).

> Early development - APIs and on-disk formats may change. Distributed (cluster) mode is **experimental** - see [Clustering](#clustering).

## Contents

- [Documentation](#documentation)
- [Features](#features)
- [Workspace](#workspace)
- [Getting Started](#getting-started)
- [CLI (`y2q`)](#cli-y2q)
- [Load Benchmarking (`y2q-warp`)](#load-benchmarking-y2q-warp)
- [FUSE Mount (`y2q-fuse`)](#fuse-mount-y2q-fuse)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Clustering](#clustering)
- [Object Data Security](#object-data-security)
- [Development](#development)

## Documentation

- [docs/architecture.md](docs/architecture.md) - system design, encryption envelope (v1 + v2 chunked), storage backends, metadata index, sessions, authorization
- [docs/configuration.md](docs/configuration.md) - full config reference: every field, default, TLS, and override syntax
- [docs/operations.md](docs/operations.md) - first run, user/role/ACL management, TLS, clustering, backup/recovery, runbook
- [docs/api.md](docs/api.md) - complete HTTP API reference: routes, authorization model, schemas, error codes, examples
- [docs/search.md](docs/search.md) - label search query language: operators, regex, grammar, examples
- [docs/clustering.md](docs/clustering.md) - distributed mode: CRAQ data plane, Raft control plane, replication, migration, internal API

## Features

- **Post-quantum encryption at rest** - each object is encapsulated against an ML-KEM-768 public key; content is encrypted with AES-256-GCM via [ring](https://github.com/briansmith/ring) (5-7x faster than the pure-Rust aes-gcm crate)
- **Streaming chunked envelope (v2)** - objects are encrypted in configurable plaintext chunks (default 4 MiB), so multi-GiB PUTs stream without buffering and `Range` GETs decrypt only the covering chunks
- **Post-quantum TLS (optional)** - native rustls listener offering the X25519MLKEM768 hybrid key exchange; `require_pq_kex` can refuse any client that won't negotiate it; optional mutual TLS via a client CA bundle
- **Argon2id-protected secret key** - the ML-KEM private key is never stored in plaintext; it is wrapped under each user's password and only held in memory during an active session
- **Token-based session auth** - Bearer tokens with configurable TTL, per-account lockout after repeated failures
- **Bucket ownership, ACLs, and global roles** - new buckets are private to their creator; per-bucket grants (read/write/writeonly/admin) plus account-wide roles (admin/user/readonly/writeonly/auditor/disabled). Disable with `auth.enforce_authorization = false` for single-user deployments
- **Distributed mode (experimental, optional)** - run multiple daemons as one store: CRAQ chain replication for object data, an embedded Raft controller for topology + user/bucket metadata, apportioned reads, online migration single-node <-> cluster. Off by default; experimental - not yet recommended for production data. See [docs/clustering.md](docs/clustering.md)
- **Dual storage backends** - portable filesystem backend (all platforms); optional Linux io_uring fast path (kernel >= 5.6); both use the same on-disk `.obj` format and are fully cross-compatible
- **Encrypted, fast listing** - embedded [redb](https://github.com/cberner/redb) metadata index, itself encrypted at rest under the login-gated key; auto-rebuilt on startup; can be triggered manually
- **Best-effort mode with background flusher** - skip per-PUT fsyncs for throughput; a background task drains the dirty queue on a configurable interval
- **Custom object labels** - attach arbitrary key/value metadata to objects via `X-Y2Q-<label>` request headers on PUT; query them with the label search language
- **Prometheus metrics + live trace** - Prometheus scrape and an interactive dashboard (auth-gated by default); a server-sent-events trace stream (`y2q admin trace`) of every request
- **Structured observability** - per-request IDs (`X-Request-ID`), INFO/ERROR log events on every request, configurable log format (`text` or `json`)
- **Continuous profiling** - optional Pyroscope/pprof-rs integration; opt-in with `--features pyroscope`
- **OpenAPI / Swagger UI** - interactive docs at `/swagger-ui/` (when metrics are exposed)

## Workspace

| Crate | Binary | Purpose |
|---|---|---|
| `y2qd` | `y2qd` | HTTP REST daemon |
| `y2q-core` | - | Crypto, storage backends, metadata index |
| `y2q-behavior` | - | Trait-only behavioral contract mirroring `y2q-core` (I/O, crypto, storage, index), no implementations |
| `y2q-cli` | `y2q` | Client CLI and TUI |
| `y2q-client` | - | HTTP client library |
| `y2q-cluster` | - | CRAQ data plane + embedded Raft control plane |
| `y2q-config` | - | Shared config types |
| `y2q-warp` | `y2q-warp` | Load benchmarking tool |
| `y2q-fuse` | `y2q-fuse` | FUSE filesystem driver (mount a store as a directory tree) |

## Getting Started

### Prerequisites

- Rust toolchain (stable, edition 2024)
- Linux kernel >= 5.6 if using the `uring` backend (not required for `filesystem`)

### Build

```sh
cargo build --release -p y2qd
```

The io_uring backend is always compiled on Linux (no feature flag). On non-Linux
targets it is simply absent, and selecting `storage.backend = "uring"` at runtime
returns an error - a standard `cargo build` works everywhere.

To enable continuous profiling (Pyroscope/pprof-rs):

```sh
cargo build --release -p y2qd --features pyroscope
```

### First Run

On first startup, `y2qd` generates an ML-KEM-768 keypair and prints a one-time root password to stdout:

```
===========================================================
  y2qd first-run: ROOT PASSWORD (recorded NOWHERE - copy now)
    username: root
    password: <43 url-safe-base64 chars>
===========================================================
```

**This password is shown exactly once.** It is printed with `println!`, bypassing the log subscriber, so it always appears regardless of `RUST_LOG`. Use it to log in and create additional users. Store it before the line scrolls - there is no recovery path if you lose it before adding a second user.

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
make image          # y2q:latest         - distroless runtime (filesystem + uring both compiled in)
make image-dev      # y2q:dev            - same, with Pyroscope profiling enabled
make image-cluster  # y2q-cluster:latest - shell-bearing image used by the cluster demo
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

For a self-contained multi-node cluster on one host, see [Clustering](#clustering) below and [deploy/cluster/README.md](deploy/cluster/README.md).

## CLI (`y2q`)

Build the client:

```sh
cargo build --release -p y2q-cli
# or install y2q + y2qd + y2q-warp into ~/.cargo/bin:
make install-local
```

### Setup

Add a server alias and log in:

```sh
y2q alias set prod https://y2qd.example --user alice
y2q login prod
```

Aliases live in `~/.config/y2q/config.toml`; cached session tokens in `~/.local/share/y2q/tokens.toml`. `y2q alias export`/`import` move alias sets between machines as TOML. Paths use `alias/bucket/key` syntax.

For a self-signed dev endpoint, add `--insecure` (per alias or per command), or trust a CA bundle with `--ca-cert <pem>`. For mutual TLS, add `--client-cert`/`--client-key` to the alias.

### Copying files

```sh
y2q cp report.pdf prod/documents/reports/q1.pdf      # upload one file
tar czf - /etc | y2q pipe prod/backups/etc.tar.gz    # upload from stdin
y2q cp prod/documents/reports/q1.pdf ./q1.pdf         # download to a file
y2q cat prod/documents/reports/q1.pdf | less          # download to stdout
y2q mv prod/a/old.txt prod/a/new.txt                  # rename (copy then delete source)
```

Recursive directory upload (preserves the local tree as remote key paths) and glob patterns:

```sh
y2q cp -r ./photos prod/media/photos/
y2q cp '*.log' prod/logs/host1/         # shell-quote so y2q does the expansion
```

Attach labels, or trade durability for speed:

```sh
y2q cp notes.txt prod/docs/notes.txt --label project=y2q --label env=prod
y2q cp big.bin prod/data/big.bin --sync best-effort   # skip fsync
```

### Listing, metadata, and inspection

```sh
y2q ls prod/                       # list buckets
y2q ls prod/documents/             # list objects in a bucket
y2q ls prod/documents/ --all       # auto-paginate
y2q stat prod/documents/q1.pdf     # object metadata
y2q head prod/logs/app.log -c 4096 # first N bytes to stdout
y2q get prod/big.bin ./big.bin --range 0-1023   # ranged download
y2q du prod/photos/ --depth 2      # disk usage grouped by prefix
y2q tree prod/media/ --depth 3     # directory tree
y2q find prod/logs/ --name '*.log' --size +10Mi --older-than 7d
```

### Searching by label

Boolean query over labels. Operators: `==` `!=` `=~` (regex) `^=` (prefix) `$=` (suffix); combine with `and`/`or`/`not` and parentheses.

```sh
y2q search prod/photos --query 'env == prod and tier != test'
y2q search prod/ --query 'team =~ "infra|sre" and name ^= log-'   # all buckets
y2q --json search prod/photos --query 'owner == alice'             # JSON output
```

`alias/` searches every bucket; `alias/bucket/prefix` narrows by bucket and key prefix. Full reference: [docs/search.md](docs/search.md).

### Buckets, tags, quotas

```sh
y2q mb prod/archive                 # create a bucket
y2q rb prod/archive --force         # remove a bucket and all its objects
y2q tag set prod/a/x.bin team=infra env=prod   # set object tags (labels)
y2q tag ls prod/a/x.bin
y2q quota set prod/archive --size 50g          # per-bucket size quota
y2q quota info prod/archive
```

`attribute` is an alias of `tag` (same label store); `encrypt` records a bucket's informational default-SSE marker.

### Deleting objects

```sh
y2q rm prod/documents/old.txt
y2q rm 'prod/logs/host1/*.log'          # glob; prompts before deleting many
y2q rm 'prod/logs/host1/*.log' --force  # -f skips the prompt
```

### Sync and compare

```sh
y2q diff ./local prod/backup/           # report what differs
y2q mirror ./local prod/backup/ --overwrite --remove   # rsync-style one-way sync
```

### Admin: users, roles, ACLs, rebuild, locks

```sh
# users + global roles
y2q admin user add prod bob --role user
y2q admin user ls prod
y2q admin user role prod bob readonly      # admin|user|readonly|writeonly|auditor|disabled
y2q admin user rm prod bob

# per-bucket ownership + ACLs
y2q admin acl get prod photos
y2q admin acl grant prod photos bob write  # read|write|admin
y2q admin acl revoke prod photos bob
y2q admin acl chown prod photos alice

# index rebuild + stale write locks
y2q admin rebuild start prod
y2q admin rebuild status prod
y2q admin locks ls prod --older-than 30m
y2q admin locks clear prod --older-than 30m
```

### Live trace and watch

```sh
y2q admin trace prod            # stream every request hitting the server
y2q admin trace prod --errors   # only status >= 400
y2q watch prod/uploads/         # stream PUT/DELETE/GET/HEAD events under a prefix
```

`trace` shows timestamp, method, path, colour-coded status, latency, and payload sizes:

```
12:34:56.123  PUT      /bucket/key                               200    42.1ms      1.2 KiB^    4.0 KiB v
12:34:58.400  DELETE   /bucket/missing                           404     0.8ms          -^          - v
```

Ctrl-C disconnects; the server has zero overhead when no client is attached.

### Health probes

```sh
y2q ping prod                 # repeated liveness probes
y2q ready prod                # single readiness check; non-zero exit if not ready
```

### TUI

```sh
y2q tui      # interactive file explorer
y2q          # same (default when no subcommand is given)
```

### Shell completions

```sh
y2q completions fish > ~/.config/fish/completions/y2q.fish
y2q completions zsh  > "${fpath[1]}/_y2q"
y2q completions bash > /etc/bash_completion.d/y2q
```

Supported shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`.

### Global flags

| Flag | Short | Env | Effect |
|---|---|---|---|
| `--json` | `-j` | `Y2Q_OUTPUT` | Output as JSON |
| `--verbose` | `-v` | - | Increase log verbosity (repeatable) |
| `--quiet` | `-q` | - | Silence progress/non-error output |
| `--no-color` | - | `NO_COLOR` | Disable ANSI colors |
| `--debug` | - | - | Maximum verbosity |
| `--insecure` | - | - | Skip TLS cert verification (dev/staging only) |
| `--ca-cert <path>` | - | - | Trust this PEM CA bundle for this invocation |
| `--config <path>` | - | - | Override config file location |

`RUST_LOG`, if set, overrides `--verbose`/`--quiet`/`--debug` entirely (see [docs/configuration.md#logging](docs/configuration.md#logging)).

## Load Benchmarking (`y2q-warp`)

`y2q-warp` runs timed workloads against a live `y2qd` server, records per-operation latencies to a compressed CSV, and shows a live ratatui dashboard. The first positional argument is the **alias** (server profile), followed by the workload subcommand.

```sh
cargo build --release -p y2q-warp
```

### Workloads

```sh
# Single-operation benchmarks (alias first, then the workload)
y2q-warp prod put    --duration 5m --concurrent 8 --obj-size 4MiB
y2q-warp prod get    --duration 5m --concurrent 8 --objects 1000
y2q-warp prod stat   --duration 5m --concurrent 16
y2q-warp prod delete --duration 2m
y2q-warp prod list   --duration 1m

# Mixed workload (GET 45% / PUT 15% / DELETE 25% / STAT 15%)
y2q-warp prod mixed --duration 10m --concurrent 16

# Pre-seed objects without timing, then run a read benchmark
y2q-warp prod prepare --objects 5000 --obj-size 1MiB
y2q-warp prod get --duration 5m --no-cleanup
y2q-warp prod cleanup

# Variable-size objects
y2q-warp prod put --obj-size-min 64KiB --obj-size-max 16MiB
```

### Multi-node fan-out (clusters)

The alias is node 0; add extra contact endpoints with repeatable `--node` URLs. Workers round-robin across all nodes. Because sessions are node-local, a multi-node run needs a password (`--password` or `Y2QWARP_PASSWORD`) to log into each extra node:

```sh
Y2QWARP_PASSWORD=$PW y2q-warp prod mixed \
  --node http://localhost:8081 --node http://localhost:8082 \
  --node http://localhost:8083 --node http://localhost:8084 \
  --duration 60s --concurrent 32
```

The live TUI and the post-run summary both break results down per contact node.

### Offline analysis

```sh
y2q-warp analyze warp-mixed-*.csv.zst
y2q-warp analyze warp-put-*.csv.zst --op PUT --skip 5s
```

Outputs a per-operation summary table (throughput in MiB/s and ops/s, p50/p90/p99 latency, total ops, error count) plus a per-node breakdown when the run fanned across more than one endpoint.

`y2q-warp` logs to stderr via `RUST_LOG` (no config file, no `-v` flag); unset, only `error`-level events print. See [docs/configuration.md#logging](docs/configuration.md#logging).

## FUSE Mount (`y2q-fuse`)

Mounts a y2q store at a local directory using [FUSE](https://github.com/cberner/fuser), so any program can read and write objects as ordinary files. Linux and macOS. Linux requires `libfuse3` (or `libfuse2` - it falls back to `fusermount` if `fusermount3` isn't found). macOS requires [macFUSE](https://macfuse.github.io/) (`brew install --cask macfuse`); on Apple Silicon you may need to enable the third-party kernel extension in System Settings (or use the kext-free FSKit backend on macOS 26+).

```sh
cargo build --release -p y2q-fuse
# or: make install-local  (installs y2q, y2qd, y2q-warp, y2q-fuse to ~/.cargo/bin)
```

Log in first, then mount - the alias must already have a valid cached token (`y2q login <alias>`):

```sh
y2q login prod
y2q-fuse --alias prod /mnt/y2q
```

By default every bucket appears as a top-level directory. Restrict the mount to one bucket (bucket becomes the root) with `--bucket`:

```sh
y2q-fuse --alias prod --bucket photos /mnt/photos
```

Unmount with Ctrl+C, SIGTERM, or manually: `fusermount3 -u /mnt/y2q` on Linux, `umount /mnt/y2q` (or `diskutil unmount /mnt/y2q`) on macOS. The session token is refreshed in the background ~60 seconds before expiry for as long as the mount is alive.

| Flag | Effect |
|---|---|
| `--alias <NAME>` | Server alias to use (required) |
| `--config <PATH>` | Config file path (default: platform config dir) |
| `--bucket <BUCKET>` | Mount a single bucket as the filesystem root; default is all buckets |
| `--read-only` | Disable all write operations |
| `--allow-other` | Allow other users to access the mount; requires `user_allow_other` in `/etc/fuse.conf` |

`y2q-fuse` logs to stderr via `RUST_LOG`, defaulting to `warn` when unset. See [docs/configuration.md#logging](docs/configuration.md#logging).

## Configuration

`config.default.toml` in the repo root documents every knob with inline comments. Required fields (no compiled-in default): `server.host`, `server.port`, `storage.base_path`, `crypto.keystore_dir`. Key sections:

```toml
[server]
host = "127.0.0.1"
port = 8080
max_body_bytes = 268435456        # 256 MiB upload limit
unauthenticated_metrics = false   # expose /metrics/* and /swagger-ui/ without auth (else NOT served)

[server.tls]
enabled        = false
# cert_path    = "/etc/y2q/tls/fullchain.pem"
# key_path     = "/etc/y2q/tls/privkey.pem"
# client_ca_path = "/etc/y2q/tls/client-ca.pem"   # require mutual TLS
require_pq_kex = true             # offer ONLY X25519MLKEM768; refuse classic-only clients

[storage]
base_path = "/var/lib/y2q/data"        # required
backend = "filesystem"                  # "filesystem" or "uring" (Linux only)
default_sync = "durable"               # "durable" (fsync) or "best-effort"
sync_flush_interval_secs = 5
sync_flush_limit = 64

[crypto]
keystore_dir = "/var/lib/y2q/keys"     # required; keep separate from base_path
envelope_chunk_size_bytes = 4194304    # 4 MiB plaintext chunks (v2 envelope)
[crypto.argon2]
m_cost_kib = 65536   # 64 MiB
t_cost = 3
p_cost = 4

[auth]
default_ttl_seconds = 3600
max_ttl_seconds = 86400
max_failed_logins = 10
lockout_seconds = 900
keystore_idle_drop_seconds = 0
enforce_authorization = true           # bucket ownership/ACLs + global admin role

[observability]
log_filter = "info"      # RUST_LOG syntax; RUST_LOG env var takes precedence
log_format = "text"      # "text" or "json"

[cluster]
enabled = false          # master switch; false => single node, zero clustering behavior
# see docs/clustering.md for the full distributed-mode reference
```

Environment variables override any config file value: prefix the dotted key with `Y2QD_` and use `__` (two underscores) as the section separator - e.g. `Y2QD_SERVER__PORT=9090`, `Y2QD_OBSERVABILITY__LOG_FORMAT=json`. Full schema: [docs/configuration.md](docs/configuration.md).

## API Reference

All authenticated routes require `Authorization: Bearer <token>`. Authorization (bucket ownership, ACLs, global roles) is enforced when `auth.enforce_authorization = true` (default); see the [authorization model](docs/api.md#authorization).

### Auth and users

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/auth/login` | No | Obtain a Bearer token |
| `POST` | `/api/v1/auth/refresh` | Yes | Extend session TTL (old token revoked) |
| `POST` | `/api/v1/auth/logout` | Yes | Revoke the current token |
| `POST` | `/api/v1/auth/password` | Yes | Change password |
| `PUT` | `/api/v1/users/add` | Admin | Create a user (optional `role`) |
| `GET` | `/api/v1/users` | Admin/auditor | List users |
| `PUT` | `/api/v1/users/{user}/role` | Admin | Change a user's global role |
| `DELETE` | `/api/v1/users/{user}` | Admin | Delete a user |

### Objects and buckets

Object keys may contain `/`. Use `/{bucket}/{key}` where `{key}` is the full path after the bucket name.

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `PUT` | `/{bucket}/{key}` | write | Store an object (encrypted) |
| `GET` | `/{bucket}/{key}` | read | Retrieve an object (decrypted; supports `Range`) |
| `HEAD` | `/{bucket}/{key}` | read | Object metadata only |
| `PATCH` | `/{bucket}/{key}` | write | Edit object labels/tags |
| `DELETE` | `/{bucket}/{key}` | write | Delete an object |
| `PUT` | `/{bucket}/` | write | Create a bucket (caller becomes owner) |
| `DELETE` | `/{bucket}/` | admin | Remove a bucket and its objects |
| `GET`/`PUT` | `/api/v1/buckets/{bucket}/config` | read/admin | Read or set bucket config (quota, default-SSE marker) |
| `GET`/`PUT` | `/api/v1/buckets/{bucket}/acl` | owner/admin | Read or set bucket owner + grants |

**Custom labels on PUT:** include `X-Y2Q-<label>: <value>` headers (repeatable). `X-Y2Q-Sync: best-effort` overrides per-request durability. `Range: bytes=N-M` on GET returns 206 for v2-chunked and plaintext objects.

### Listing and search

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/` | Yes | List visible non-empty buckets |
| `GET` | `/{bucket}/` | read | List objects in a bucket (`?prefix=`, `?after=`, `?limit=`) |
| `GET` | `/api/v1/search` | read | Find objects by a label query (`?q=` required, `?bucket=`) |

### Admin and observability

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST`/`GET` | `/api/v1/rebuild` | admin / admin+auditor | Start / poll a metadata index rebuild |
| `GET`/`DELETE` | `/api/v1/locks` | admin+auditor / admin | List / force-release stale in-flight write locks |
| `GET` | `/api/v1/trace` | admin+auditor | Server-sent-events stream of every request |
| `GET` | `/metrics/prometheus` | Gated | Prometheus scrape endpoint |
| `GET` | `/metrics/dashboard` | Gated | Interactive metrics dashboard |
| `GET` | `/swagger-ui/` | Gated | Interactive API documentation |

`/metrics/*`, `/swagger-ui/`, and `/api-docs/openapi.json` are served **only** when `server.unauthenticated_metrics = true`, and then without auth. With the default `false` they are not registered at all.

When clustering is enabled, additional `/api/v1/cluster/{status,join,migrate}` and peer-only `/internal/v1/*` routes are exposed - see [docs/clustering.md](docs/clustering.md).

## Clustering

> **Experimental.** Distributed mode works and is covered by integration tests, but it is young and not yet recommended for production data. The single-node path (`cluster.enabled = false`, the default) is unaffected and is the supported deployment.

`y2qd` can run as a distributed store. The data plane is **CRAQ** (chain replication with apportioned reads); the control plane is an **embedded Raft** controller that replicates only topology plus low-volume user/bucket metadata - object data never enters the Raft log. Every node shares one deployment keystore, so the derived key hierarchy is identical and ciphertext is portable verbatim (no re-encryption on replication or migration).

Enable per node with `[cluster] enabled = true` and a shared keystore; one node bootstraps Raft and admits the others. Online migration moves data either direction between a single node and a cluster. The whole feature is off by default - with `enabled = false`, behavior is byte-for-byte single-node.

A ready-to-run 5-node demo lives in [deploy/cluster/](deploy/cluster/):

```sh
make cluster-up      # build + start a 5-node cluster (podman-compose)
make cluster-down    # stop and wipe its volumes
```

Full design, configuration, internal API, failure handling, and migration: [docs/clustering.md](docs/clustering.md).

## Object Data Security

`y2qd` protects not just the object *contents* but the information *about* the data - sizes, names, labels, and the listing index. Every layer below is enforced by default (TLS and authorization are opt-in via config). Full design and threat model: [docs/architecture.md](docs/architecture.md).

| What is protected | How | Where |
|---|---|---|
| **Object contents** | Per-object ML-KEM-768 encapsulation -> HKDF-SHA256 -> AES-256-GCM content key. v2 objects seal the plaintext in independent chunks (each its own AEAD frame). The encapsulated key and ciphertext are stored together; nothing is decryptable without the deployment secret key. | [crypto/envelope.rs](crates/y2q-core/src/crypto/envelope.rs) |
| **Tamper / integrity** | The AEAD tag authenticates every chunk; the fixed envelope header is bound as AAD, so altering any header field invalidates the tag. A non-cryptographic gxhash64 plaintext digest catches accidental corruption. | envelope.rs |
| **Secret key at rest** | The ML-KEM private key is never on disk in plaintext - it is Argon2id-wrapped under each user's password, unwrapped into memory only during an active session, zeroized on drop, and idle-dropped after `auth.keystore_idle_drop_seconds`. | [crypto/kdf.rs](crates/y2q-core/src/crypto/kdf.rs), [auth/keystore.rs](crates/y2qd/src/auth/keystore.rs) |
| **Object metadata at rest** | The per-object metadata blob (labels, timestamps, checksums, the cleartext key) embedded in each `.obj` is itself encrypted with AES-256-GCM under the login-gated master key (MEK) - not stored in the clear. | [crypto/metadata_key.rs](crates/y2q-core/src/crypto/metadata_key.rs) |
| **Listing index at rest** | The whole redb metadata index is encrypted (per-4 KiB-block AES-256-GCM, block index bound as AAD) under a key derived from the MEK. It is opened on first login and closed on idle - while idle, only ciphertext remains on disk. | [storage/index.rs](crates/y2q-core/src/storage/index.rs) |
| **File and bucket names** | On-disk directory and file names are irreversible keyed HMAC-SHA256 under the login-gated path key, so the storage tree leaks **neither bucket names nor object keys** to anyone who can read the directory. | [storage/filesystem.rs](crates/y2q-core/src/storage/filesystem.rs) |
| **Object size** | Plaintext length is rounded up with Padmé padding before encryption, so the on-disk size leaks at most O(log log n) bits about the true size (<~12% overhead). The exact size lives only in the encrypted metadata. | envelope.rs (`padme_len`) |
| **Data in transit** | Optional native TLS (`[server.tls]`) via rustls, restrictable to the X25519MLKEM768 post-quantum hybrid group (`require_pq_kex`), with optional mutual TLS. | [tls.rs](crates/y2qd/src/tls.rs) |
| **Access** | Bucket ownership + per-bucket ACLs + global roles (when `auth.enforce_authorization = true`); a bucket you have no relationship to is hidden (404, never 403) so existence cannot be probed. | [authz.rs](crates/y2qd/src/authz.rs) |
| **Session tokens** | Only `SHA-256(token)` is held in memory - the plaintext token is never persisted, and a daemon restart invalidates every session. Repeated failed logins lock the account behind a response-time floor. | [auth/session.rs](crates/y2qd/src/auth/session.rs) |

**What it does not defend against:** a compromised running daemon (the SK is in memory while sessions are active), a leaked Bearer token until it expires or is revoked, and traffic analysis when TLS is disabled. Key rotation is not yet implemented. See the full [threat model](docs/architecture.md#threat-model-brief).

> In **cluster mode** (experimental) every node shares the deployment keystore, so all of the above holds identically on each node and ciphertext replicates verbatim (never re-encrypted). Inter-node traffic is authenticated by a shared secret or mutual TLS over the same TLS stack.

## Development

```sh
make build     # debug build, all workspace crates
make test      # run all tests
make clippy    # lint (warnings as errors)
make fmt       # format
make check     # fmt-check + clippy + test (CI gate)
make install-local  # install y2q + y2qd + y2q-warp into ~/.cargo/bin
```

Required after any code change (CI gate): `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo build --all-targets --all-features`, then `make check`. Run `make help` for all targets including per-binary builds, release builds, and image targets.
