# Architecture

This document describes how `y2qd` is put together: the components, the encryption envelope, the storage backends, the metadata index, and the authentication model.

## Overview

`y2qd` is an HTTP daemon that exposes an object store. Every object is encrypted at rest using ML-KEM-768 key encapsulation feeding AES-256-GCM. The deployment's private key is never written to disk in plaintext — it is wrapped under each authorized user's password with Argon2id, unwrapped into process memory on successful login, and dropped when no sessions remain (subject to an optional idle timeout).

Two storage backends ship in tree:

- **Filesystem** (default, all platforms) — built on `tokio::fs`. Each object lives in its own file with a JSON metadata sidecar.
- **io_uring** (Linux only, `--features uring`) — a single-file format with a header/trailer pair for torn-write recovery, driven through `tokio-uring`.

A redb-backed metadata index sits in front of both backends to make listing operations cheap. The index is a cache: the on-disk sidecars (filesystem) and per-object headers (uring) are the source of truth, and the index can be rebuilt from them at any time.

```
                  ┌──────────────────────────┐
   HTTP request → │  actix-web + middleware  │
                  │  (auth, tracing, metrics)│
                  └────────────┬─────────────┘
                               │
                  ┌────────────▼─────────────┐
                  │   Authenticated extractor│  ← Bearer token → session store
                  └────────────┬─────────────┘
                               │
                  ┌────────────▼─────────────┐
                  │      handlers/*.rs       │
                  │  (put, get, list, …)     │
                  └────────────┬─────────────┘
                               │
                  ┌────────────▼─────────────┐
                  │  envelope.rs (encrypt /  │
                  │  decrypt with in-memory  │
                  │  SK from session)        │
                  └────────────┬─────────────┘
                               │
                  ┌────────────▼─────────────┐
                  │   AnyStorage dispatcher  │
                  │  ┌──────────┬─────────┐  │
                  │  │Filesystem│ Uring   │  │
                  │  └────┬─────┴────┬────┘  │
                  └───────┼──────────┼───────┘
                          │          │
                  ┌───────▼───┐  ┌───▼──────┐
                  │ disk (fs) │  │ disk (uring│
                  │ + sidecars│  │  single-  │
                  │           │  │  file fmt) │
                  └───────────┘  └────────────┘
                          │          │
                          └────┬─────┘
                               │
                  ┌────────────▼─────────────┐
                  │   MetadataIndex (redb)   │
                  │  OBJECTS + LABELS tables │
                  └──────────────────────────┘
```

## Cryptography

### Envelope format

Each object on disk is wrapped in a 28-byte fixed header followed by the ML-KEM-768 ciphertext and the AES-256-GCM ciphertext. The header doubles as additional authenticated data (AAD) for AES-GCM, so tampering with any header field invalidates the tag.

```
offset  size   field
------  ----   -----
0       4      magic         = b"Y2Q1"
4       2      format_ver    = 1 (BE)
6       1      kem_alg       = 1 (ML-KEM-768)
7       1      aead_alg      = 1 (AES-256-GCM)
8       12     nonce         random per encryption
20      8      plaintext_len BE
28      1088   kem_ct        ML-KEM-768 ciphertext
1116    N+16   aead_ct       ciphertext || GCM tag
```

Fixed overhead per object is 1132 bytes (28 header + 1088 KEM + 16 tag).

### Per-object key derivation

The content key is derived fresh for every PUT:

1. `(kem_ct, ss) := ML-KEM-768.encapsulate(public_key)` — fresh ephemeral, produces a 32-byte shared secret.
2. `content_key := HKDF-SHA256(salt = kem_ct, ikm = ss, info = b"y2q/v1/content-key")` — 32 bytes.
3. `ciphertext := AES-256-GCM.encrypt(content_key, nonce, plaintext, aad = header)`.

On GET the daemon does the reverse: parse the header, decapsulate with the in-memory secret key, re-derive the content key, decrypt and verify the tag.

The shared secret is *not* the content key directly. HKDF binds the content key to both `ss` and `kem_ct`, which means two encapsulations against the same public key can never collide on content key even if `ss` did.

### Secret-key protection at rest

The ML-KEM-768 secret key is 2400 bytes. It is never written to disk in plaintext.

- On first run, a 32-byte random root password is generated, encoded as URL-safe base64 (no padding), printed once to stdout, and used to derive a 32-byte KEK via Argon2id.
- The KEK wraps the secret key under AES-256-GCM (AAD = `b"y2q/v1/sk-wrap"`).
- The wrapped secret, together with the user's Argon2id parameters and salt, is stored as a `UserRecord` in `users.redb`.
- On login, the password is run through Argon2id (using that user's stored salt and parameters), the KEK is recomputed, and the secret key is unwrapped into a `Zeroizing<Vec<u8>>` that clears on drop.

Adding a new user is just "wrap the in-memory SK under the new user's password" — there is one canonical secret key shared across all users; each user just has their own wrapped copy.

### Argon2id parameters

Defaults (overridable per deployment in `[crypto.argon2]`):

| Parameter | Default | Notes |
|---|---|---|
| `m_cost_kib` | 65 536 (64 MiB) | OWASP "second-tier" recommendation |
| `t_cost` | 3 | iterations |
| `p_cost` | 4 | parallelism / lanes |
| salt | 16 random bytes | fresh per user record |

Each user's `UserRecord` records the parameters used at the time of password write, so existing users keep working when defaults change. A password change re-wraps with the *current* configured defaults.

### Key file layout

```
<keystore_dir>/
  pubkey.json    plaintext public key, algorithm, fingerprint
  users.redb     one row per user (wrapped SK + Argon2 params + metadata)
  .lock          POSIX advisory exclusive flock, held while daemon runs
```

`pubkey.json` schema:

```json
{
  "kem_alg": "ml-kem-768",
  "public_key_b64": "<base64 of 1184-byte public key>",
  "fingerprint_sha256": "<lowercase hex SHA-256 of raw PK bytes>"
}
```

`UserRecord` (JSON inside redb):

```json
{
  "username": "alice",
  "created_at": 1715000000000000000,
  "last_login": 1715000123000000000,
  "kdf": { "m_cost_kib": 65536, "t_cost": 3, "p_cost": 4, "salt": "<b64>" },
  "wrapped_sk": { "nonce": "<b64>", "ciphertext": "<b64+tag>" }
}
```

## Storage

### Filesystem backend

Each object becomes a triple of files in a two-level hex-sharded directory:

```
<base_path>/<bucket>/<xx>/<yy>/<uuid>          object payload (envelope)
<base_path>/<bucket>/<xx>/<yy>/<uuid>.meta     JSON metadata sidecar
<base_path>/<bucket>/<xx>/<yy>/<uuid>.lock     ephemeral write lock (only during PUT)
```

The UUID is deterministic: `uuid::Uuid::new_v5(NAMESPACE_URL, key.as_bytes())`. The same key always maps to the same UUID, so the address of an object is a pure function of its key. `<xx><yy>` is the first four hex characters of that UUID.

Bucket names are validated: ASCII alphanumeric plus `-` and `_`, case-insensitive `"api"` is reserved (it would otherwise collide with `/api/v1/*` routes). Object keys are bounded to 1024 bytes and must not contain null bytes.

`Metadata` sidecar schema:

```json
{
  "created":         1715000000000000000,
  "modified":        1715000000000000000,
  "size":            12345,
  "checksum_md5":    "<b64 16-byte digest>",
  "checksum_sha256": "<b64 32-byte digest>",
  "bucket":          "my-bucket",
  "key":             "path/to/object",
  "disk_path":       "/var/lib/y2qd/objects/my-bucket/ab/cd/<uuid>",
  "url_path":        "my-bucket/path/to/object",
  "labels":          { "owner": "alice" },
  "cipher_size":     13477,
  "cipher_sha256":   "<b64>",
  "kem_alg":         "ml-kem-768",
  "aead_alg":        "aes-256-gcm",
  "envelope_version": 1
}
```

`size` always refers to the plaintext length. The `cipher_*` fields and crypto algorithm names are populated when the object is encrypted (which is always, in current builds).

### Write locks

PUT acquires a `.lock` sidecar with `O_EXCL` (atomic on Linux) before writing data or metadata. The lock file contains a single little-endian `u64`: the nanosecond timestamp of acquisition. On successful PUT (or any clean failure) it is removed in `Drop`.

If `y2qd` is killed mid-PUT, the lock file is left behind and blocks concurrent writes to that key. `GET /api/v1/locks?older_than=...` enumerates such locks; `DELETE /api/v1/locks?older_than=...` removes them. See [Operations](operations.md) for the runbook.

### io_uring backend

The uring backend stores each object as a single file with this layout:

```
[ header   64 B ]
[ padding  P    ]    P = data_offset - 64
[ data     N    ]    N = data_len      (plaintext or envelope, same as filesystem)
[ meta     M    ]    M = meta_len      (JSON metadata, same schema as sidecar)
[ trailer  64 B ]    bitwise copy of the header
```

Header layout (little-endian):

```
offset  size   field
------  ----   -----
0       4      magic   = b"Y2QO"
4       2      version = 1
6       2      flags   bit 0 = WRITTEN_O_DIRECT, bit 1 = DURABLE
8       8      data_len
16      4      meta_len
20      4      data_offset  (64 for buffered, 4096 for O_DIRECT)
24      36     reserved (zeros)
60      4      crc32 of bytes 0..60
```

The trailer is byte-identical to the header. Both carry the same CRC32 over bytes 0..60. A mismatch on either copy indicates a torn write, and the surviving copy is used for repair. Buffered writes place data at offset 64; O_DIRECT writes pad to 4096 to satisfy alignment.

## Metadata index

The index is a single redb database with two tables:

| Table | Key | Value | Purpose |
|---|---|---|---|
| `OBJECTS` | `len(bucket) || bucket || len(key) || key` | JSON `Metadata` | Object lookup, bucket scans |
| `LABELS` | `len(name) || name || len(value) || value || len(bucket) || bucket || len(key) || key` | empty | Forward index for `label_name=value` queries |

All composite keys use a 4-byte big-endian length prefix per field, which makes lexicographic byte order match `(field1, field2, ...)` tuple order. That lets range scans answer "all objects in bucket B" and "all `(bucket, key)` pairs with label N=V" with no extra filtering.

Listing operations are implemented as bounded range scans:

- `list_buckets()` skip-walks the OBJECTS table — one read per bucket, jumping to the lex-successor of each bucket prefix. O(num_buckets) reads instead of O(num_objects).
- `scan_objects(bucket, prefix?, after?, limit)` range scans within the bucket, filters by `prefix`, paginates past `after`, and applies `limit`. Returns a `ListPage { items, next }`. Sorted ascending by key. `next` is `None` when the page is the last.

The index is a cache. If it goes missing or corrupt, every operation still works against the on-disk truth — just slower for listings. `POST /api/v1/rebuild` walks the storage tree and reconciles the index. Rebuild is fire-and-forget and reports progress through `GET /api/v1/rebuild`.

## Authentication and sessions

### Token format

Session tokens are 32 cryptographically random bytes, encoded as URL-safe base64 (no padding) — 43 ASCII characters on the wire. The plaintext token is never persisted: the session store keys on `SHA-256(token)` and only the hash is held in memory. A leaked memory dump still cannot be replayed against a different process.

Wire format:

```
Authorization: Bearer <43-char base64url>
```

### Session store

In-memory `DashMap<[u8; 32], Arc<SessionInfo>>`. Each `SessionInfo` carries `(username, created_at, expires_at)`. There is no persistence: a daemon restart invalidates every session.

A background sweeper runs every `auth.session_sweep_interval_seconds` (default 300). On each pass it:

1. Iterates the session map and removes entries past `expires_at`.
2. Calls `keystore.reconcile(&sessions)` to drive idle-keystore drop.

### Lockout

Per-username failed login attempts are tracked in memory. Once `auth.max_failed_logins` consecutive failures hit, the username is locked for `auth.lockout_seconds`. Lockouts apply to malformed and valid usernames identically, so probing user existence isn't possible. A successful login or a lockout expiry resets the counter.

A floor of `auth.min_login_response_ms` (default 250 ms) is applied to both success and failure responses on login to smooth out timing differences between "user not found" and "wrong password".

### Idle keystore drop

The decrypted secret key lives in an `Arc<DecryptedKeystore>` held by the daemon's `KeystoreSlot`. While at least one active session exists, the slot holds the SK. When the last session expires the sweeper marks the slot's `empty_since`. Once `now - empty_since >= auth.keystore_idle_drop_seconds`, the SK is dropped and zeroized. The next login re-unwraps it from the user's password.

Default `keystore_idle_drop_seconds = 0` drops the SK immediately on the first sweep after the last session expires. Operators who want gap-tolerant uptime can extend it.

### Daemon-wide flock

On startup the daemon acquires a POSIX exclusive `flock` on `<keystore_dir>/.lock`. Two processes pointing at the same keystore would race on the user-store database; the flock makes the second one fail fast with a clear error.

## Threat model (brief)

What the design defends against:

- **Disk theft** — an adversary with full read access to the storage tree learns object sizes, keys, labels, timestamps, and ciphertext, but cannot recover plaintext without the secret key.
- **Server-stored-credentials theft** — the user-store database contains only Argon2id-wrapped copies of the secret key; brute-forcing requires the configured Argon2 work per guess.
- **Quantum adversary** — ML-KEM-768 is a NIST-selected post-quantum KEM. The AES-256-GCM content key derivation is symmetric and unaffected by Shor.

What it doesn't defend against:

- **Compromised running daemon** — once the SK is unwrapped into memory, anything that can read process memory can read objects. The `keystore_idle_drop_seconds` shortens but doesn't eliminate this window.
- **Compromised client** — Bearer tokens are bearer credentials. A client that leaks one gives the holder full access until expiry or revocation.
- **Traffic analysis on the wire** — `y2qd` does not currently terminate TLS. Put it behind a reverse proxy.
- **Replay of encrypted payloads under a different key** — the daemon trusts whatever public key is in `pubkey.json` at process start. Key rotation is not yet implemented.

## Source map

- [crates/y2q-core/src/crypto/envelope.rs](../crates/y2q-core/src/crypto/envelope.rs) — envelope format, encrypt/decrypt
- [crates/y2q-core/src/crypto/kdf.rs](../crates/y2q-core/src/crypto/kdf.rs) — Argon2id wrap/unwrap
- [crates/y2q-core/src/crypto/keystore.rs](../crates/y2q-core/src/crypto/keystore.rs) — pubkey.json, first-run, daemon flock
- [crates/y2q-core/src/crypto/user_store.rs](../crates/y2q-core/src/crypto/user_store.rs) — users.redb schema
- [crates/y2q-core/src/storage/filesystem.rs](../crates/y2q-core/src/storage/filesystem.rs) — filesystem backend, sharding, lock files
- [crates/y2q-core/src/storage/uring/format.rs](../crates/y2q-core/src/storage/uring/format.rs) — uring single-file format
- [crates/y2q-core/src/storage/index.rs](../crates/y2q-core/src/storage/index.rs) — redb metadata index
- [crates/y2qd/src/auth/session.rs](../crates/y2qd/src/auth/session.rs) — session store, token hashing
- [crates/y2qd/src/auth/keystore.rs](../crates/y2qd/src/auth/keystore.rs) — in-memory keystore slot, idle drop
- [crates/y2qd/src/main.rs](../crates/y2qd/src/main.rs) — startup, lifecycle, route wiring
