# y2q

Post-quantum secure object storage. `y2qd` is a REST daemon that encrypts every object at rest using ML-KEM-768 key encapsulation and AES-256-GCM, with token-based session authentication and a choice of storage backends.

> Early development — APIs and on-disk formats may change.

## Documentation

- [docs/architecture.md](docs/architecture.md) — system design, encryption envelope, storage backends, metadata index, sessions
- [docs/configuration.md](docs/configuration.md) — full config reference with all fields, defaults, and override syntax
- [docs/operations.md](docs/operations.md) — first run, user management, backup/recovery, stale-lock cleanup, runbook
- [docs/api.md](docs/api.md) — complete HTTP API reference: routes, schemas, error codes, examples

## Features

- **Post-quantum encryption at rest** — each object is encapsulated against an ML-KEM-768 public key; content is encrypted with AES-256-GCM
- **Argon2id-protected secret key** — the ML-KEM private key is never stored in plaintext; it is wrapped under each user's password and only held in memory during an active session
- **Token-based session auth** — Bearer tokens with configurable TTL, per-account lockout after repeated failures
- **Dual storage backends** — portable filesystem backend (all platforms); optional Linux io_uring fast path (kernel ≥ 5.6)
- **Fast listing** — embedded [redb](https://github.com/cberner/redb) metadata index; can be rebuilt from on-disk sidecars at any time
- **Custom object labels** — attach arbitrary key/value metadata to objects via `X-Y2Q-<label>` request headers on PUT
- **Prometheus metrics** — scrape endpoint at `/metrics/prometheus`; interactive dashboard at `/metrics/dashboard`
- **OpenAPI / Swagger UI** — interactive docs at `/swagger-ui/`

## Getting Started

### Prerequisites

- Rust toolchain (stable, edition 2024)
- Linux kernel ≥ 5.6 if using the `uring` backend (not required for `filesystem`)

### Build

```sh
cargo build --release -p y2qd
```

To build with the io_uring backend:

```sh
cargo build --release -p y2qd --features uring
```

### First Run

On first startup, `y2qd` generates an ML-KEM-768 keypair and prints a one-time root password to stdout:

```
y2qd: first run — root password: <password>
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
| `--set KEY=VALUE` | — | Override a config value, e.g. `--set server.port=9090` |

## Configuration

```toml
[server]
host = "127.0.0.1"
port = 8080
# Maximum request body size in bytes (default: 256 MiB)
max_body_bytes = 268435456
# Allow unauthenticated access to /metrics/* and /swagger-ui/
unauthenticated_metrics = false

[storage]
# Where objects are stored on disk
base_path = "/var/lib/y2qd/objects"
# "filesystem" (default) or "uring" (Linux only, requires --features uring)
backend = "filesystem"
# Path for the metadata index database (default: <base_path>/_y2q_index.redb)
# index_path = "/var/lib/y2qd/objects/_y2q_index.redb"
# Label limits per object
max_labels = 32
max_label_name_bytes = 64
max_label_value_bytes = 1024

[crypto]
# Directory holding pubkey.json and the user store database
keystore_dir = "/var/lib/y2qd/keystore"
# Argon2id parameters for secret key wrapping
[crypto.argon2]
m_cost_kib = 65536  # 64 MiB memory
t_cost = 3          # iterations
p_cost = 4          # parallelism

[auth]
# Default and maximum session lifetimes
default_ttl_seconds = 3600
max_ttl_seconds = 86400
# How often the session sweeper runs
session_sweep_interval_seconds = 300
# Minimum login response time (milliseconds) — prevents timing attacks
min_login_response_ms = 250
# Lockout policy
max_failed_logins = 10
lockout_seconds = 900
# Drop the decrypted secret key from memory after this many idle seconds
# 0 = keep it for the lifetime of the process
keystore_idle_drop_seconds = 0
```

Environment variables override config file values. Prefix any config key with `Y2QD_`, use `__` (two underscores) as the section separator, and convert to uppercase — e.g. `Y2QD_SERVER__PORT=9090`, `Y2QD_CRYPTO__ARGON2__M_COST_KIB=131072`. See [docs/configuration.md](docs/configuration.md) for the full schema.

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
| `GET` | `/api/v1/locks` | Yes | List stale write locks |
| `DELETE` | `/api/v1/locks` | Yes | Clear stale write locks |

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
cargo build         # debug build
cargo build --release
cargo test          # run all tests
cargo clippy        # lint
cargo fmt           # format
```
