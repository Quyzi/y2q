# Operations Guide

How to run, manage, and recover a `y2qd` deployment. Read this before putting anything important behind it.

## First run

1. Build the daemon:
   ```sh
   cargo build --release -p y2qd
   # or, for the Linux io_uring backend:
   cargo build --release -p y2qd --features uring
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
     y2qd first-run: ROOT PASSWORD (recorded NOWHERE — copy now)
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

The daemon refuses to delete the last remaining user (409). Other users are unaffected — their wrapped SK copies remain valid.

### "Reset" a forgotten password

There is no admin reset. Procedure:

1. Log in as another user.
2. `DELETE /api/v1/users/<forgotten>`
3. `PUT /api/v1/users/add` with the same username and a new password.

## Backup and recovery

### What to back up

| Path | What it is | Priority |
|---|---|---|
| `<crypto.keystore_dir>/pubkey.json` | Deployment public key + fingerprint | **Critical** |
| `<crypto.keystore_dir>/users.redb` | Every user's wrapped SK and Argon2 params | **Critical** |
| `<storage.base_path>/` | All objects (ciphertext) and metadata sidecars | **Critical** |
| `<storage.base_path>/_y2q_index.redb` | redb metadata index | Optional — rebuildable |

Lose `pubkey.json` or `users.redb` and your ciphertext is unrecoverable. Back them up to a different host (or at least a different volume) than `base_path`.

Recommended: keep `keystore_dir` and `base_path` on different mount points. A `cp -r` of the storage tree by an operator should not accidentally exfiltrate authentication state, and a failure of one volume should not necessarily destroy both halves.

### Hot backup

The keystore and storage tree are both safe to copy while `y2qd` is running, with two caveats:

- **`users.redb`** is a redb database. `redb` writes are crash-safe, but a `cp` mid-write can capture a torn copy. Either: stop the daemon briefly, or use a filesystem-level snapshot (LVM, ZFS, btrfs).
- **`.lock` files** in the storage tree are ephemeral and may or may not be present at backup time. They are harmless; restore them or skip them — the `GET /api/v1/locks` endpoint can clean stragglers later.

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

- **Password rotation per user** — `POST /api/v1/auth/password` works fine and re-wraps that user's copy of the SK under fresh Argon2 parameters. Do this routinely.
- **Migrating to a new keypair** — currently requires standing up a fresh deployment, copying objects through (re-encrypting on the new keypair), and switching consumers over.

If your threat model requires periodic SK rotation, file an issue or plan for a migration. Don't pretend the existing pubkey is rotatable.

## Stale write locks

`y2qd` writes objects atomically through a `<uuid>.lock` sidecar acquired with `O_EXCL`. If the daemon is killed mid-PUT (SIGKILL, panic, host crash), the lock is left behind and blocks any subsequent PUT to the same key.

### Find stale locks

`older_than` is required. Accepted forms:

- Relative: `<n>{s|m|h|d|w}` — e.g. `1h`, `30m`, `2d`. Cutoff is `now - duration`.
- Absolute: bare Unix-seconds integer — e.g. `1715000000`.

```sh
# Locks held longer than 30 minutes
curl "https://y2qd.example/api/v1/locks?older_than=30m" \
  -H "Authorization: Bearer $TOKEN"
# [
#   {"bucket":"my-bucket", "uuid":"abc...", "locked_since_nanos":1715000000000000000, "age_seconds":1834},
#   ...
# ]
```

### Clear stale locks

Same query, with `DELETE`:

```sh
curl -X DELETE "https://y2qd.example/api/v1/locks?older_than=30m" \
  -H "Authorization: Bearer $TOKEN"
# {"removed": 3}
```

Clearing a stale lock does *not* touch the metadata index. If the partial PUT corrupted the object file or its sidecar, run an index rebuild afterward:

```sh
curl -X POST https://y2qd.example/api/v1/rebuild -H "Authorization: Bearer $TOKEN"
```

## Index rebuild

The metadata index in `_y2q_index.redb` is a cache built from the on-disk sidecars. The daemon keeps it in sync during normal operation, but it can drift after a crash, a bulk file restore, or a stale-lock cleanup of a partial PUT.

Rebuild is fire-and-forget. `POST /api/v1/rebuild` returns 202 and starts a background scan; concurrent kicks return 409. `GET /api/v1/rebuild` polls progress:

```json
{"state": "idle"}
{"state": "running", "percent": 73}
{"state": "completed"}
{"state": "failed", "reason": "..."}
```

GET and PUT continue to work during a rebuild — they read and write the on-disk truth. Listing operations may temporarily show stale data until rebuild completes.

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

Both are auth-gated by default. To expose them without a token (e.g. for an internal Prometheus scraper that doesn't speak Bearer):

```toml
[server]
unauthenticated_metrics = true
```

When this is enabled, `/swagger-ui/` and `/api-docs/openapi.json` are also exposed without auth.

### Tracing

Set `RUST_LOG` before launch. Examples:

```sh
RUST_LOG=info y2qd
RUST_LOG=y2qd=debug,actix_web=info y2qd
RUST_LOG=y2qd=trace,y2q_core=trace y2qd          # very loud
```

Per-request spans flow through `tracing-actix-web`, so each HTTP request gets a span with method, path, status, and elapsed time. Override via `RUST_LOG=tracing_actix_web=warn` if it's too noisy.

### Daemon flock

`y2qd` holds an exclusive `flock` on `<keystore_dir>/.lock` for its lifetime. Two daemons pointing at the same keystore will refuse to start. Healthy state shows the `.lock` file present and the daemon running; if a daemon crashes the OS releases the flock, so a normal restart Just Works without manual cleanup.

## Putting it behind a proxy

`y2qd` doesn't terminate TLS. Production deployments should run it behind a reverse proxy (nginx, Caddy, traefik) that:

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

`proxy_request_buffering off` matters for large PUTs — otherwise nginx will buffer the whole body to disk before sending it on, doubling the bandwidth and adding latency.

## Failure modes and how to recognize them

| Symptom | Likely cause | What to do |
|---|---|---|
| Daemon refuses to start: `acquire keystore lock` | Another `y2qd` is already running against the same `keystore_dir` | Check `ps` / systemd. If stale, the lock should have been released by the OS — investigate. |
| `503` on any object op | `KeystoreUnavailable` — SK not in memory (idle-dropped, no active sessions) | Log in (any user). The SK is reinstalled on the first successful login. |
| `409 Conflict` on PUT | Active write lock for that key | If unexpected, the previous writer crashed — clean stale locks. |
| `501 Not Implemented` on GET with `Range` | Range reads on encrypted objects aren't supported (whole-object AEAD) | Don't use `Range` for encrypted objects, or fetch the whole object client-side and slice. |
| `429 Too Many Requests` on login | Per-username lockout | Wait `lockout_seconds`, or use another user. `Retry-After` tells you exactly how long. |
| Listing shows missing or stale objects | Index drift after restore or crash | Run `POST /api/v1/rebuild`. |

## Source

- [crates/y2qd/src/main.rs](../crates/y2qd/src/main.rs) — startup, first-run, lifecycle
- [crates/y2qd/src/handlers/locks.rs](../crates/y2qd/src/handlers/locks.rs) — stale-lock endpoints
- [crates/y2qd/src/handlers/rebuild.rs](../crates/y2qd/src/handlers/rebuild.rs) — index rebuild endpoints
- [crates/y2q-core/src/crypto/keystore.rs](../crates/y2q-core/src/crypto/keystore.rs) — keystore on-disk layout
