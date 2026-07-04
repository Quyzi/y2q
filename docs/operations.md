# Operations Guide

How to run, manage, and recover a `y2qd` deployment. Read this before putting anything important behind it.

## First run

1. Build the daemon:
   ```sh
   cargo build --release -p y2qd
   ```
   The io_uring backend is included by default. To build with Pyroscope profiling:
   ```sh
   cargo build --release -p y2qd --features pyroscope
   ```

   The workspace `.cargo/config.toml` sets `RUSTFLAGS = -C target-cpu=native`
   and `[profile.release]` enables thin LTO with one codegen unit. This pulls
   in SHA-NI, AES-NI, and AVX2 instructions automatically, but ties the
   resulting binary to the build host's CPU family. To produce a portable
   binary, override the rustflags on the command line:
   ```sh
   RUSTFLAGS="" cargo build --release -p y2qd
   ```
   or set a portable feature subset (for x86_64-v3 hosts):
   ```sh
   RUSTFLAGS="-C target-feature=+sha,+aes,+ssse3,+avx2" cargo build --release -p y2qd
   ```

2. Write a minimal `config.toml`:
   ```toml
   [server]
   host = "127.0.0.1"
   port = 8080

   [storage]
   base_path = "/var/lib/y2qd/objects"

   [crypto]
   keystore_dir = "/var/lib/y2qd/keystore"

   [auth]
   # defaults are fine for first run
   ```

3. Start it:
   ```sh
   ./target/release/y2qd --config config.toml
   ```

4. **Capture the root password.** First start prints this once on stdout:
   ```
   ===========================================================
     y2qd first-run: ROOT PASSWORD (recorded NOWHERE - copy now)
       username: root
       password: <43 url-safe-base64 chars>
   ===========================================================
   ```
   It is written by `println!`, bypassing the tracing subscriber, so it always appears regardless of `RUST_LOG`. Save it in your secret store before doing anything else. There is no recovery path if you lose it before adding a second user.

5. (Optional but recommended) Create at least one operator user, then keep `root` for emergency access only:
   ```sh
   TOKEN=$(curl -s -X POST http://127.0.0.1:8080/api/v1/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"root","password":"<copied above>"}' | jq -r .token)

   curl -X PUT http://127.0.0.1:8080/api/v1/users/add \
     -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"username":"alice","password":"<strong password>"}'
   ```

## Container

Both storage backends are compiled into one image; pick the backend at runtime with `storage.backend` (`uring` needs Linux >= 5.6). Image variants:

| Image | Target | Notes |
|---|---|---|
| `y2q:latest` | `make image` | Distroless runtime; filesystem + io_uring both compiled in |
| `y2q:dev` | `make image-dev` | Same, built with `--features pyroscope` for profiling |
| `y2q-cluster:latest` | `make image-cluster` | Shell-bearing image used by the multi-node cluster demo (see [Clustering](#clustering)) |

Build locally:

```sh
make image          # y2q:latest
make image-dev      # y2q:dev (Pyroscope enabled)
```

### First container run

1. Create host directories and write a config:
   ```sh
   mkdir -p ~/y2q/data ~/y2q/keys
   cp config.default.toml ~/y2q/config.toml
   # edit ~/y2q/config.toml -- at minimum set base_path and keystore_dir
   ```

2. Run (rootless podman):
   ```sh
   podman run \
     --network=host \
     --userns=keep-id \
     --user $(id -u):$(id -g) \
     -v ~/y2q/config.toml:/etc/y2q/config.toml:ro \
     -v ~/y2q/data:/var/lib/y2q/data \
     -v ~/y2q/keys:/var/lib/y2q/keys \
     y2q:latest
   ```

   - `--network=host` - container uses the host network directly; required for rootless podman to expose a port without NAT
   - `--userns=keep-id` - maps your host UID into the container so bind-mounted directories are writable
   - `--user $(id -u):$(id -g)` - runs the daemon as your host user

3. **Capture the root password** from stdout - it appears once on first run, same as native.

### Config in containers

The image ships a default config at `/etc/y2q/config.toml` with `base_path = "/var/lib/y2q/data"` and `keystore_dir = "/var/lib/y2q/keys"`. Three ways to configure:

- **Mount your own config** (shown above, `:ro` recommended)
- **Environment variable overrides** - any config key can be overridden at runtime:
  ```sh
  -e Y2QD_SERVER__PORT=9090
  -e Y2QD_OBSERVABILITY__LOG_FORMAT=json
  -e Y2QD_STORAGE__BACKEND=filesystem
  ```
  Syntax: `Y2QD_SECTION__KEY=value` (double underscore for nesting). See [configuration.md](configuration.md) for the full reference.

### Running other binaries

All three binaries (`y2qd`, `y2q`, `y2q-warp`) are present in the image. The default entrypoint is `y2qd`. Override to run others (`y2q-fuse` is not built into the image - it needs a FUSE mount namespace and `libfuse3` on the host):

```sh
# client CLI
podman run --entrypoint y2q --network=host \
  --userns=keep-id --user $(id -u):$(id -g) \
  y2q:latest ls prod/

# benchmarking tool
podman run --entrypoint y2q-warp --network=host \
  --userns=keep-id --user $(id -u):$(id -g) \
  y2q:latest prod put --duration 5m
```

## User management

`y2q`'s authentication model is unusual in one key way: **every user record carries its own wrapped copy of the same deployment secret key**. To add a user you must already be logged in (so the daemon has the unwrapped SK in memory), and adding the user re-wraps that SK under the new password.

Consequences:

- **You cannot add the first user without the root password.** Lose it before creating a second user and the deployment is effectively dead.
- **Compromising any user's password compromises the deployment.** If a user's password leaks, decrypt access to *every* object is potentially gone. Rotate immediately (see below) and consider whether you trust your at-rest storage.
- **A user's password change does not affect any other user.** Each `UserRecord` is independent.
- **You cannot reset a user's password without their current password.** There is no "admin reset". Delete and re-add instead.

### Add a user

```sh
curl -X PUT https://y2qd.example/api/v1/users/add \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"correct-horse-battery-staple"}'
```

Usernames must match `[A-Za-z0-9_.-]+`, max 64 bytes, case-sensitive.

### Change your own password

```sh
curl -X POST https://y2qd.example/api/v1/auth/password \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"current":"...","new":"..."}'
```

This also re-wraps the SK under whatever Argon2id parameters are currently configured, so it's the lever for migrating users to stronger work factors after raising `[crypto.argon2]`.

### Delete a user

```sh
curl -X DELETE https://y2qd.example/api/v1/users/bob \
  -H "Authorization: Bearer $TOKEN"
```

The daemon refuses to delete the last remaining user (409). Other users are unaffected - their wrapped SK copies remain valid.

### "Reset" a forgotten password

There is no admin reset. Procedure:

1. Log in as another user.
2. `DELETE /api/v1/users/<forgotten>`
3. `PUT /api/v1/users/add` with the same username and a new password.

### Roles and access control

When `auth.enforce_authorization = true` (default), each user has a global role and each bucket has an owner plus an ACL. The first-run `root` user is `admin`. Create users with a role, change roles later, and manage per-bucket grants (full model: [api.md](api.md#authorization)):

```sh
# create with an explicit role (admin|user|readonly|writeonly|auditor|disabled)
y2q admin user add prod bob --role user

# change a role; takes effect immediately (target's sessions are revoked).
# `disabled` locks an account out without deleting it. Refuses to demote the last admin.
y2q admin user role prod bob readonly

# per-bucket ownership + grants (read|write|admin)
y2q admin acl get prod photos
y2q admin acl grant prod photos bob write
y2q admin acl revoke prod photos bob
y2q admin acl chown prod photos alice
```

Equivalent HTTP: `PUT /api/v1/users/{user}/role`, `GET`/`PUT /api/v1/buckets/{bucket}/acl`. Set `auth.enforce_authorization = false` only for single-user or migration deployments where every authenticated user should have full access.

## Backup and recovery

### What to back up

| Path | What it is | Priority |
|---|---|---|
| `<crypto.keystore_dir>/pubkey.json` | Deployment public key + fingerprint | **Critical** |
| `<crypto.keystore_dir>/users.redb` | Every user's wrapped SK and Argon2 params | **Critical** |
| `<storage.base_path>/` | All objects - each is a single `.obj` file containing ciphertext and embedded metadata | **Critical** |
| `<storage.base_path>/_y2q_index.redb` | redb metadata index | Optional - rebuildable |

Lose `pubkey.json` or `users.redb` and your ciphertext is unrecoverable. Back them up to a different host (or at least a different volume) than `base_path`.

Recommended: keep `keystore_dir` and `base_path` on different mount points. A `cp -r` of the storage tree by an operator should not accidentally exfiltrate authentication state, and a failure of one volume should not necessarily destroy both halves.

### Hot backup

The keystore and storage tree are both safe to copy while `y2qd` is running, with one caveat:

- **`users.redb`** is a redb database. `redb` writes are crash-safe, but a `cp` mid-write can capture a torn copy. Either: stop the daemon briefly, or use a filesystem-level snapshot (LVM, ZFS, btrfs).

Write locks are in-memory and vanish on process exit - there are no lock files in the storage tree to worry about during backup.

### Restore

1. Stop `y2qd`.
2. Restore `keystore_dir` and `base_path` from backup to the original paths (or fix up `config.toml` to point at the new paths).
3. Start `y2qd`. It should find `pubkey.json` and skip first-run.
4. Inspect: log in as any restored user, `GET /` to list buckets, do a few HEAD/GET round trips on objects you expect to exist.
5. If listing looks wrong but objects are readable by direct GET, the index is out of sync. Kick off a rebuild:
   ```sh
   curl -X POST https://y2qd.example/api/v1/rebuild \
     -H "Authorization: Bearer $TOKEN"
   curl https://y2qd.example/api/v1/rebuild -H "Authorization: Bearer $TOKEN"
   # {"state":"running","percent":42}
   ```
6. Once `state == "completed"`, listing should be authoritative again.

## Key rotation

**Not currently implemented.** The deployment's ML-KEM-768 keypair is generated on first run and lives forever. There is no in-place rotation today.

Workarounds:

- **Password rotation per user** - `POST /api/v1/auth/password` works fine and re-wraps that user's copy of the SK under fresh Argon2 parameters. Do this routinely.
- **Migrating to a new keypair** - currently requires standing up a fresh deployment, copying objects through (re-encrypting on the new keypair), and switching consumers over.

If your threat model requires periodic SK rotation, file an issue or plan for a migration. Don't pretend the existing pubkey is rotatable.

## Write locks

`y2qd` holds an in-memory per-object write lock for the duration of each PUT. Locks live in a `LockRegistry` (a lock-free in-memory hash map). Because locks are in-memory, they vanish on process exit - a SIGKILL or daemon crash leaves no orphaned lock files.

`GET /api/v1/locks?older_than=...` shows locks that are *currently held* and whose acquisition timestamp is older than the cutoff. A lock appearing here means a PUT is actively running and taking longer than expected - this is unusual.

`DELETE /api/v1/locks?older_than=...` force-releases those locks. Use with care: force-releasing a lock that belongs to a genuinely in-flight PUT may leave the object in a partially written state.

`older_than` formats:

- Relative: `<n>{s|m|h|d|w}` - e.g. `1h`, `30m`, `2d`. Cutoff is `now - duration`.
- Absolute: bare Unix-seconds integer - e.g. `1715000000`.

```sh
# List locks held longer than 30 minutes
curl "https://y2qd.example/api/v1/locks?older_than=30m" \
  -H "Authorization: Bearer $TOKEN"
# [
#   {
#     "bucket": "my-bucket",
#     "key": "path/to/object",
#     "locked_since_nanos": 1715000000000000000,
#     "age_seconds": 1834
#   }
# ]

# Force-release them
curl -X DELETE "https://y2qd.example/api/v1/locks?older_than=30m" \
  -H "Authorization: Bearer $TOKEN"
# {"removed": 1}
```

After force-releasing a stuck lock, run an index rebuild to repair any inconsistent state:

```sh
curl -X POST https://y2qd.example/api/v1/rebuild -H "Authorization: Bearer $TOKEN"
```

## Index rebuild

The metadata index in `_y2q_index.redb` is a cache. The daemon keeps it in sync during normal operation, but it can drift after a crash or a bulk file restore.

### Automatic startup rebuild

On every startup, `y2qd` automatically walks the storage tree and reconciles the index against the on-disk `.obj` files:

- Objects present on disk but missing from the index are re-inserted.
- Index rows whose `.obj` file is gone are removed (logged as `tracing::error!` data-loss events with the affected key).

This happens before the daemon begins accepting requests, so listing is always authoritative by the time the first request arrives. No operator action is required after an unclean shutdown.

### Manual rebuild

`POST /api/v1/rebuild` returns 202 and starts a background scan; concurrent kicks return 409. `GET /api/v1/rebuild` polls progress:

```json
{"state": "idle"}
{"state": "running", "percent": 73}
{"state": "completed"}
{"state": "failed", "reason": "..."}
```

GET and PUT continue to work during a manual rebuild - they read and write the on-disk truth. Listing may temporarily show stale data until rebuild completes.

## Observability

### Metrics

Prometheus scrape endpoint:

```sh
curl https://y2qd.example/metrics/prometheus -H "Authorization: Bearer $TOKEN"
```

Interactive dashboard (in-browser):

```
https://y2qd.example/metrics/dashboard
```

By default these endpoints are **not served at all** - there is no auth-gated variant. To expose them (without a Bearer token; e.g. for an internal Prometheus scraper):

```toml
[server]
unauthenticated_metrics = true
```

When enabled, `/metrics/prometheus`, `/metrics/dashboard`, `/swagger-ui/`, and `/api-docs/openapi.json` are all reachable unauthenticated. Restrict access at the network layer (or behind your TLS/proxy) if you turn this on. With it `false` (default) the daemon logs that they are disabled at startup.

### Tracing

Set `RUST_LOG` before launch. Examples:

```sh
RUST_LOG=info y2qd
RUST_LOG=y2qd=debug,actix_web=info y2qd
RUST_LOG=y2qd=trace,y2q_core=trace y2qd          # very loud
```

Per-request spans flow through `tracing-actix-web`, so each HTTP request gets a span with method, path, status, and elapsed time. Override via `RUST_LOG=tracing_actix_web=warn` if it's too noisy.

### Continuous profiling (Pyroscope)

Requires building with `--features pyroscope`. Enable in config:

```toml
[observability.pyroscope]
enabled    = true
server_url = "http://localhost:4040"   # or Grafana Cloud endpoint
sample_rate = 100                       # Hz
```

For Grafana Cloud add credentials:

```toml
basic_auth_user     = "123456"   # numeric user ID
basic_auth_password = "glc_..."  # API token with profiling write scope
```

The agent starts a background OS thread using SIGPROF before the HTTP server begins accepting connections. On shutdown (SIGTERM / graceful stop) the agent flushes and stops cleanly. Tags `version` and `backend` are attached to every profile.

To profile a running deployment without restarting, rebuild with `--features pyroscope`, set `enabled = true`, and restart. The agent has no effect when `enabled = false` even if the feature is compiled in.

### Daemon flock

`y2qd` holds an exclusive `flock` on `<keystore_dir>/.lock` for its lifetime. Two daemons pointing at the same keystore will refuse to start. Healthy state shows the `.lock` file present and the daemon running; if a daemon crashes the OS releases the flock, so a normal restart Just Works without manual cleanup.

## TLS

`y2qd` can terminate TLS natively with rustls. Enable it and point at a PEM cert/key:

```toml
[server.tls]
enabled        = true
cert_path      = "/etc/y2q/tls/fullchain.pem"
key_path       = "/etc/y2q/tls/privkey.pem"
require_pq_kex = true                          # offer ONLY X25519MLKEM768; refuse classic-only clients
# client_ca_path = "/etc/y2q/tls/client-ca.pem"  # require mutual TLS
```

When `enabled = true` the daemon binds HTTPS at `[server] port` and refuses plaintext HTTP. The private key may be PKCS#8, PKCS#1, or SEC1. `require_pq_kex = true` (default) makes the handshake post-quantum-only; set `false` to also offer classic X25519/ECDH. Set `client_ca_path` to require every client to present a certificate chaining to that CA bundle (mutual TLS) - the same bundle backs `cluster.auth = "mtls"`. To serve HTTP and HTTPS together, run two `y2qd` processes on different ports.

`y2q` and `y2q-warp` verify the server certificate by default; use `--ca-cert <pem>` to trust a private CA, `--client-cert`/`--client-key` on an alias for mutual TLS, or `--insecure` for self-signed dev endpoints.

### Behind a reverse proxy

Alternatively (or in addition) run `y2qd` behind a reverse proxy (nginx, Caddy, traefik) that:

- Terminates TLS
- Forwards the `Authorization` header
- Optionally limits body size at the proxy layer (otherwise `server.max_body_bytes` is the only bound)

Example nginx snippet:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_request_buffering off;          # stream PUT bodies through
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    client_max_body_size 1G;
}
```

`proxy_request_buffering off` matters for large PUTs - otherwise nginx will buffer the whole body to disk before sending it on, doubling the bandwidth and adding latency.

## Clustering

> **Experimental** - functional and tested, but not yet recommended for production data. The default single-node mode is the supported deployment.

`y2qd` can run as a distributed store (off by default). Operational essentials; full reference in [clustering.md](clustering.md):

- **Shared keystore is mandatory.** Every node must load the *same* deployment keystore (`pubkey.json` + `users.redb`) before joining - the key hierarchy is derived from it and the leader refuses to admit a node whose deployment-key fingerprint differs. Back it up exactly as in single-node mode.
- **Boot unlock.** Cluster nodes unwrap the secret key at startup from a provisioned secret (`Y2QD_CLUSTER__UNLOCK_SECRET` or `cluster.unlock_secret_file`) so peer-forwarded writes commit unattended; idle-drop is disabled while clustered.
- **Bring-up.** Exactly one node sets `cluster.raft.bootstrap = true` on first boot; the rest join and are admitted as voters (if in `voter_seeds`) or learners. Check `GET /api/v1/cluster/status` for membership, leader, and committed epoch.
- **Migration.** `POST /api/v1/cluster/migrate` moves objects online in either direction (distribute into the cluster / collect back to one node); it is idempotent and resumable.
- **Local demo.** `make cluster-up` starts a 5-node cluster via podman-compose ([deploy/cluster/](../deploy/cluster/)); `make cluster-down` tears it down and wipes volumes. The demo's `init` service generates the shared keystore and captures the root password to `/seed/unlock_secret.txt`.
- **Keep client and server in lockstep.** After rebuilding the cluster image, run `make install-local` so the `y2q`/`y2q-warp` binaries match the daemon's object-metadata format.

## Failure modes and how to recognize them

| Symptom | Likely cause | What to do |
|---|---|---|
| Daemon refuses to start: `acquire keystore lock` | Another `y2qd` is already running against the same `keystore_dir` | Check `ps` / systemd. If stale, the flock is released by the OS - investigate why the daemon didn't exit cleanly. |
| `503` on any object op | `KeystoreUnavailable` - SK not in memory (idle-dropped, no active sessions) | Log in (any user). The SK is reinstalled on the first successful login. |
| `409 Conflict` on PUT | Active in-flight write lock for that key (same key PUT in two concurrent requests) | Normally self-resolves; if stuck, use `GET /api/v1/locks` to check and `DELETE /api/v1/locks` to force-release. |
| `501 Not Implemented` on GET with `Range` | The object is a **v1** whole-object envelope (legacy); only v2 chunked objects (the default for new writes) support ranged reads | Re-PUT the object so it is stored as v2, or fetch the whole object client-side and slice. |
| `429 Too Many Requests` on login | Per-username lockout | Wait `lockout_seconds`, or use another user. `Retry-After` tells you exactly how long. |
| Listing shows missing or stale objects after restore | Index drift after bulk restore | Run `POST /api/v1/rebuild` (or restart the daemon - startup auto-rebuild handles it). |
| Data-loss `tracing::error!` messages at startup | `.obj` files referenced in index are gone | Indicates actual data loss (e.g. from a partial restore). Startup rebuild logs the affected keys. |
| `503` cluster writes stall; reads still work | Raft quorum lost (voter-majority partition) - correct CP behavior | Restore connectivity / a voter majority. Reads keep serving; writes resume once quorum returns. See [clustering.md](clustering.md). |
| Joined node 404s or `STALE_EPOCH` on peer ops | Wrong keystore (fingerprint mismatch) or stale topology after a re-splice | Verify every node shares the deployment keystore; check `GET /api/v1/cluster/status` for the committed epoch and member states. |

## Source

- [crates/y2qd/src/main.rs](../crates/y2qd/src/main.rs) - startup, first-run, lifecycle
- [crates/y2qd/src/handlers/locks.rs](../crates/y2qd/src/handlers/locks.rs) - stale-lock endpoints
- [crates/y2qd/src/handlers/rebuild.rs](../crates/y2qd/src/handlers/rebuild.rs) - index rebuild endpoints
- [crates/y2qd/src/tls.rs](../crates/y2qd/src/tls.rs) - native TLS listener
- [crates/y2q-core/src/crypto/keystore.rs](../crates/y2q-core/src/crypto/keystore.rs) - keystore on-disk layout
- [docs/clustering.md](clustering.md) - distributed-mode operations and design
- [deploy/cluster/README.md](../deploy/cluster/README.md) - 5-node docker/podman compose demo
