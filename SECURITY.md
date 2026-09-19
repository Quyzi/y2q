# Security

Every security mechanism `y2qd` implements, what it buys you, and — just as
important — what it explicitly does not. This is the consolidated reference;
[docs/architecture.md](docs/architecture.md) covers the same ground
component-by-component alongside the rest of the system design, and
[docs/operations.md](docs/operations.md) covers day-to-day operation of
each mechanism (key rotation, duress personas, memory hardening). Where
they'd otherwise duplicate a long explanation, this document links out
instead of repeating it.

> Early development. APIs, on-disk formats, and the details below may
> change without a deprecation period.

## Contents

- [Reporting a vulnerability](#reporting-a-vulnerability)
- [Threat model](#threat-model)
- [Encryption at rest](#encryption-at-rest)
- [Key hierarchy](#key-hierarchy)
- [Guarded memory (Linux only)](#guarded-memory-linux-only)
- [Authentication and sessions](#authentication-and-sessions)
- [Authorization](#authorization)
- [Duress personas](#duress-personas)
- [Transport security (TLS)](#transport-security-tls)
- [Node key and keystore](#node-key-and-keystore)
- [Storage-tree metadata protection](#storage-tree-metadata-protection)
- [Client-side credential storage](#client-side-credential-storage)
- [Platform support summary](#platform-support-summary)
- [Known limitations and non-goals](#known-limitations-and-non-goals)

## Reporting a vulnerability

This is an early-development project with no formal disclosure program.
Open a GitHub issue, or if the finding is sensitive, contact the repository
owner directly before filing anything public. Include the affected
component, a reproduction if you have one, and — for crypto findings —
which property from this document you believe is violated.

## Threat model

What the design defends against, and what it doesn't, is stated precisely
because a security document that only lists mechanisms without their
boundary is misleading. Full detail: [docs/architecture.md#threat-model-brief](docs/architecture.md#threat-model-brief).

**Defended against:**

- Disk theft (ciphertext, sizes, and blinded names only — no plaintext).
- A compromised administrator account (strict crypto-layer exclusion from
  object plaintext — see [Authorization](#authorization)).
- A compromised, less-privileged account (blast radius bounded to that
  account's own grants).
- Coercion to reveal a password (duress personas — deniable, indistinguishable
  from an ordinary low-access account).
- Server-stored-credential theft (Argon2id-wrapped keys, not passwords).
- A quantum adversary (ML-KEM-768 throughout).
- Memory disclosure while idle, **on Linux** (core dump, swap, same-uid
  `ptrace`/`/proc/<pid>/mem`, VM snapshot — see
  [Guarded memory](#guarded-memory-linux-only)).

**Not defended against:**

- A live memory read timed to a request actually in flight, or by a
  root/kernel-privileged reader (guarded memory closes *idle* disclosure,
  not a read that races a request).
- Object body plaintext in ordinary heap (see
  [Guarded memory's scope boundary](#guarded-memory-linux-only)).
- The node key holder's view of deployment shape (bucket/object counts,
  labels, sizes — see [Key hierarchy](#key-hierarchy)).
- A leaked, valid Bearer token, until it expires or is revoked.
- Plaintext on the wire when `[server.tls] enabled = false` (put a
  TLS-terminating proxy in front, or enable native TLS).
- Anything about the client side of a deployment (`y2q-cli`, `y2q-fuse`,
  `y2q-warp`) beyond what's noted in
  [Client-side credential storage](#client-side-credential-storage).

## Encryption at rest

Every object is sealed with a fresh ML-KEM-768 encapsulation against the
target bucket's current-epoch public key, feeding HKDF-SHA256 to derive an
AES-256-GCM content key bound to the object's `(bucket, key)` address. The
plaintext is split into independently sealed chunks (default 4 MiB) so
`Range` GETs decrypt only the covering chunks and multi-GiB PUTs stream
without buffering. There is no unauthenticated passthrough: an envelope
with an unrecognized magic — including retired v1/v2 formats — is rejected
outright, never treated as legacy plaintext.

AES-256-GCM runs through the pure-Rust [`aes-gcm`](https://github.com/RustCrypto/AEADs)
crate (hardware-accelerated where the target supports AES-NI/NEON, portable
elsewhere), so the daemon builds and runs on any architecture the Rust
toolchain supports — it no longer depends on `ring`'s assembly backend.

Almost the entire fixed envelope header is bound as AEAD associated data
(everything except `plaintext_len`, which is only known after streaming
completes), so tampering with `key_epoch`, `chunk_size`, or any other
structural field invalidates the tag instead of silently succeeding. Two
non-cryptographic XXH3-64 checksums (plaintext and on-disk ciphertext) catch
accidental corruption; they are not a substitute for the AEAD tag, which is
the actual tamper-detection mechanism.

Object size itself is a side channel: plaintext length is rounded up with
Padmé padding before encryption, so the on-disk size leaks at most
O(log log n) bits about the true size (under ~12% overhead) instead of the
exact byte count.

Full format details, AAD coverage, and the per-object key derivation:
[docs/architecture.md#cryptography](docs/architecture.md#cryptography).

## Key hierarchy

There is no single deployment-wide secret key. Four tiers, each with a
different exposure boundary:

| Tier | What | Derived from | Persisted plaintext? |
|---|---|---|---|
| 0 | Node key — drives the metadata index key, path-blinding key, object-metadata key, bucket-config key, container-header key | Operator-supplied, never auto-generated | Never (see below) |
| 1 | Per-persona ML-KEM-768 identity keypair (4 credential slots per account, occupied or decoy) | Argon2id(password) wraps the secret half | Wrapped (Argon2id), never plaintext |
| 2 | Per-bucket-per-epoch ML-KEM-768 keypair | A 32-byte bucket-wrap key, sealed once per grantee's identity, never itself persisted | Never |
| 3 | Per-object AES-256-GCM content key | Fresh ML-KEM-768 encapsulation against the bucket's current-epoch public key, every PUT | Never (re-derived on every GET) |

A compromised tier doesn't cascade: the node key alone (tier 0) cannot
decrypt object plaintext without the specific bucket's tier-2 key material,
and a tier-1 identity key only unlocks what that persona was actually
granted (tier 2), not every bucket in the deployment. Global `admin`/
`auditor` roles are cryptographically excluded from object plaintext they
weren't explicitly granted — see [Authorization](#authorization).

The node key (tier 0) must be operator-supplied CSPRNG output — it is
*never* auto-generated, and the daemon refuses to start without one
(`Y2QD_NODE_KEY` or `[crypto] node_key_file`). It is rejected outright if
it resolves to a path inside `storage.base_path` or `crypto.keystore_dir`,
so a `cp -r` of either tree can never accidentally carry the key that
protects it. A length floor (≥32 bytes) guards against a truncated paste,
but does **not** prove entropy — a passphrase that happens to decode to
32+ bytes will be accepted and will be crackable offline at HMAC speed by
anyone holding the storage tree. Use `y2q admin gen-node-key`, not a
memorized passphrase.

Argon2id parameters (tier 1, `[crypto.argon2]`) default to OWASP's
"second-tier" recommendation (64 MiB, 3 iterations, 4 lanes) and are
recorded per user record, so raising the defaults doesn't invalidate
existing accounts — only new records (or a password change) pick up the
new cost. On login, one Argon2id derivation tries all four credential
slots' unwrap *without short-circuiting*, so response timing never reveals
which slot — real or decoy — actually opened, nor how many of the four are
live.

Full hierarchy, on-disk layout, and worked JSON examples:
[docs/architecture.md#key-hierarchy-and-identity-protection-at-rest](docs/architecture.md#key-hierarchy-and-identity-protection-at-rest).

## Guarded memory (Linux only)

**This section describes a Linux-specific mechanism. Read
[Platform support summary](#platform-support-summary) before relying on
any claim below for a non-Linux deployment.**

### What it protects

Once a tier-1 identity key or a resolved tier-2 bucket key is unwrapped on
login, it used to sit as a plain `Zeroizing<Vec<u8>>` in the session store
for the session's whole lifetime (`auth.max_ttl_seconds`, up to 24 hours by
default). `Zeroizing` only scrubs on drop — it does nothing for a *live*
process, so a core dump, swap page, same-uid `ptrace`/`/proc/<pid>/mem`
read, or a VM snapshot taken any time during that window recovered the key
in plaintext. The same gap covered:

- Every active session's identity secret key and its cached bucket keys
  (up to 32 per session).
- Passwords and bearer tokens in login/refresh request and response
  buffers.
- The base64 copy of each identity key inside a wrapped credential slot.
- ML-KEM-768 shared secrets `ml-kem`'s `Copy` `SharedSecret` newtype leaves
  behind after every encapsulate/decapsulate (no `Drop` impl of its own;
  the `DecapsulationKey` itself zeroizes automatically on drop).
- The five node-derived (tier-0) keys, resident for the daemon's entire
  process lifetime.

### Mechanism

`y2q_core::secmem` (`crates/y2q-core/src/secmem.rs`) provides two guarded
allocation shapes, both built on `mmap` + `mprotect` + `mlock` + `madvise`:

- **`SecretBuf`** — a long-lived secret. Its pages are `PROT_NONE` at rest
  (unreadable, even to a reader that otherwise could access the process's
  memory) and briefly made `PROT_READ` for the duration of an `unlock()`
  guard, then restored to `PROT_NONE` when the guard drops. Reference-counted
  nesting supports concurrent readers from multiple request threads sharing
  one guard.
- **`SecretVec`** — a transient plaintext workspace (the destination of a
  decrypt, or the source of an encrypt), readable for its whole short life,
  with a fixed capacity so it never reallocates (a realloc would leave a
  stale, unzeroized copy in the old backing memory).

Both types are guard-paged (an inaccessible page immediately before and
after the data region) and locked out of swap (`mlock`), hinted
`MADV_DONTDUMP` (excluded from core dumps at the VMA level, independent of
the process-wide `RLIMIT_CORE`/dumpable flag below) and `MADV_WIPEONFORK`
(zeroed rather than copied into a child process). On drop, both scrub their
content with a volatile write (not eligible for compiler dead-store
elimination) before `munlock`/`munmap`.

**`MemoryKey`** wraps a fresh 32-byte AES-256-GCM key in a `SecretBuf`,
generated once per process at boot. `SessionKeyring`
(`crates/y2qd/src/auth/keyring.rs`) uses one process-wide `MemoryKey` to
seal every session's identity key and cached bucket keys as
`SealedSecret` ciphertext, with the AEAD associated data bound to the
sealing session's token hash — a sealed blob copied onto a different
session's row fails to open, so an attacker with memory *write* access
(not just read) can't graft one session's key onto another. A session row
therefore holds no plaintext key material at all; opening it
(`SessionInfo::with_identity_sk`) decrypts into a `SecretVec` for the
duration of one operation and drops (scrubbing) it immediately after.

**`SecretString`** (also backed by `SecretVec`) guards passwords and
bearer tokens the same way. Request bodies carrying a password are read
through a `SecretJson<T>` extractor that aggregates the HTTP body directly
into guarded memory, never an ordinary heap buffer the way `web::Json`
would. The login/refresh HTTP response — which carries a freshly minted
bearer token — is serialized into a pre-sized `Zeroizing` buffer and
returned via `Bytes::from_owner`, so the serialized token is scrubbed once
actix has written it to the socket, rather than left in an unscrubbed
response buffer.

**`scrub_pod()`** volatile-zeroes `ml-kem`'s `Copy` `SharedSecret` newtype
after its last use in every encapsulate/decapsulate call site — that type
has no `Drop` of its own, so without this it's ordinary stack/heap bytes
left behind after the call returns. The KEM secret key itself
(`DecapsulationKey`) needs no such treatment: it zeroizes automatically on
drop.

**`harden_process()`** runs once at boot, before any secret is loaded
(including the node key): sets `PR_SET_DUMPABLE=0` (blocks same-uid
`ptrace`/`gdb`/`strace -p`/`/proc/<pid>/mem` reads — a *process-wide*
protection, distinct from the per-page `MADV_DONTDUMP` hint above) and
`RLIMIT_CORE=0` (no core file on crash), then allocates and drops a
one-page `SecretBuf` as a boot-time probe — so a too-low `RLIMIT_MEMLOCK`
fails loudly at startup instead of silently at first login.

### Verifying it on a running daemon

```sh
# /proc/<pid>/maps and /proc/<pid>/mem ownership flips to root while the
# daemon runs unprivileged — same-uid reads are denied
stat -c %U /proc/$(pgrep -n y2qd)/maps
cat /proc/$(pgrep -n y2qd)/mem              # Operation not permitted

# core dumps and debugger attach are refused
gcore $(pgrep -n y2qd)                      # ptrace: Operation not permitted

# VmLck is small (a handful of pages) and nonzero — the guarded keys are
# locked, not the whole heap
grep VmLck /proc/$(pgrep -n y2qd)/status
```

### Configuration and failure mode

`[server] allow_unprotected_memory` (default `false`) gates all of this.
With the default, `y2qd` refuses to start if guarded allocation fails (most
commonly `RLIMIT_MEMLOCK` set too low — a handful of pages are needed, not
a meaningful fraction of any reasonable limit):

```
Error: refusing to start: mlock failed (1); raise RLIMIT_MEMLOCK or set
[server] allow_unprotected_memory = true. Core dumps and swap would
expose session identity keys; set [server] allow_unprotected_memory =
true to override.
```

Fix by raising the limit (`LimitMEMLOCK=infinity` in a systemd unit,
`ulimit -l unlimited` for a shell-launched daemon), not by setting the
override — that downgrades to best-effort (secrets may be written to swap,
one warning logged) and is meant for local development, not production.
Full runbook: [docs/operations.md#memory-hardening-linux-only](docs/operations.md#memory-hardening-linux-only).

### Scope boundary — what this does *not* close

Stated explicitly because it's easy to over-claim guarded memory's reach:

- **A root/kernel-privileged live read timed to a request in flight**
  recovers that request's plaintext and the `MemoryKey` that sealed it.
  Guarded memory defends against *idle* disclosure (a snapshot, dump, or
  same-uid read taken when nothing is actively using the key) — not
  against a privileged reader racing an in-progress operation.
- **Object body plaintext is left in ordinary heap, deliberately.**
  `mlock`ing bodies up to `server.max_body_bytes` (256 MiB default) isn't
  viable, and scrubbing every GET's response body would be a real
  throughput regression for a much smaller marginal gain than guarding key
  material. Body plaintext is only as protected as the response path
  itself (TLS in transit; nothing at rest in process memory beyond normal
  OS page lifecycle).
- **A dead-simple upgrade path exists if that boundary ever needs to move**
  (`Bytes::from_owner` over a scrubbing owner, the same mechanism used for
  the token response above) — it just isn't applied to bodies today.

## Authentication and sessions

Session tokens are 32 CSPRNG-random bytes, URL-safe base64 encoded (43
ASCII characters on the wire). Only `SHA-256(token)` is ever stored — the
plaintext token is never persisted anywhere, including in the in-memory
session map, so a memory dump of the daemon cannot be replayed against a
different process, and the daemon itself cannot recover a lost token for
you. A daemon restart invalidates every session (no persistence).

- **TTL** — `auth.default_ttl_seconds` (1h default) unless the login
  request specifies `ttl_seconds`, capped by `auth.max_ttl_seconds` (24h
  default). A background sweeper purges expired sessions from memory every
  `auth.session_sweep_interval_seconds`.
- **Per-username lockout** — `auth.max_failed_logins` consecutive failures
  locks the username for `auth.lockout_seconds`. Applies identically to
  malformed and valid usernames, so failed-login behavior cannot be used to
  probe account existence.
- **Per-source-IP rate limiting** — a `governor`-based limiter in front of
  `/api/v1/auth/login` (burst 5, refill 1/4s, keyed by the actual TCP peer
  address, never a client-supplied `X-Forwarded-For`/`Forwarded` header)
  closes the gap username-lockout leaves open: an attacker who varies the
  username on every request never triggers any single username's lockout,
  but still floods Argon2id work per request. `POST /api/v1/personas` has
  its own limiter (burst 5, refill 1/10s) — its 409 `PasswordReused`
  response is a verification oracle for the caller's own other slot
  passwords, so it's throttled the same way.
- **Response-time floor** — `auth.min_login_response_ms` (250ms default)
  smooths timing differences between "user not found" and "wrong
  password"; both cost one Argon2id derivation either way (against a
  throwaway all-decoy record when the username doesn't exist).
- **Constant-shape credential storage** — every account always carries
  exactly four credential slots (real or decoy, byte-shape identical: same
  wrapped-ciphertext length, same JSON structure), so nothing about a
  `UserRecord` on disk or on the wire reveals how many of a user's
  passwords are actually live.

Full detail: [docs/architecture.md#authentication-and-sessions](docs/architecture.md#authentication-and-sessions).

## Authorization

Enforced when `auth.enforce_authorization = true` (default). Two policy
layers intersect, plus a crypto-layer gate that policy alone cannot bypass:

1. **Global role** — an account-wide ceiling: `admin` (everything),
   `user`/`readonly`/`writeonly` (governed by bucket grants, capped to
   read-only or write-only respectively), `auditor` (read every bucket,
   read-only admin endpoints), `disabled` (nothing — login itself is
   refused).
2. **Per-bucket ownership + ACL** — an owner (full control) plus an
   optional grant map (`read`/`write`/`writeonly`/`admin`) for other users.
   New buckets are private to their creator. A bucket you have no
   relationship to is indistinguishable from one that doesn't exist:
   omitted from listings, 404 (never 403) on direct access — existence
   itself cannot be probed. 403 appears only when you can already see a
   bucket but lack the verb for the action.
3. **Cryptographic bucket-key grant — strict admin exclusion.** This is
   the property the per-bucket key hierarchy exists for. A global
   `admin`/`auditor` role satisfies layers 1 and 2 for every bucket (so
   `GET /` lists every bucket name), but actually reading an object
   additionally requires the caller's *persona* to hold a real, sealed
   bucket-key grant. A role ceiling alone confers none. **There is no
   admin group key, no escrow secret, and no break-glass self-grant** — a
   compromised admin account with no bucket grant of its own can see
   bucket/object *names*, sizes, and labels (tier-0 metadata) but cannot
   decrypt a single byte of content it wasn't explicitly granted. This is
   enforced at the crypto layer, identically regardless of whether the
   request even reaches the ACL check.

With `enforce_authorization = false` the first two layers are skipped
(single-user/migration mode) — layer 3 still applies unconditionally,
since it isn't an authorization *policy* choice, it's what the object is
physically encrypted under.

Full model, capability table, and status codes:
[docs/api.md#authorization](docs/api.md#authorization).

## Duress personas

Every account can hold up to three additional passwords beyond its real
one, each unlocking a completely separate identity (its own credential
slot, its own bucket grants) — self-service, via `POST /api/v1/personas`.
The account's real identity lives at a slot chosen **uniformly at random**
on creation, not a fixed index, so slot position alone reveals nothing
about which credential is real.

A persona created with `revoke_other_sessions: true` becomes usable under
coercion: logging in through it silently switches every other live session
on the account over to that persona's identity, **in place** — same
tokens, same expiry, no revocation, no error, no log line distinguishing
it from an ordinary login. A coercer who checks that some other session is
still "logged in" sees exactly that; it now just carries the duress
persona's (typically far more limited) access. `GET /api/v1/personas/me`
never reports the duress flag, even for the caller's own session, so a
technical coercer who queries the endpoint directly can't read it off
either.

Nothing about a `UserRecord` or `BucketKeyVersion`'s on-disk byte shape —
slot count, wrapped-ciphertext length, grant-row structure — distinguishes
a real persona from a decoy from the outside, including from the server
operator's own vantage point without that persona's password.

Full mechanics and CLI/API examples:
[docs/operations.md#duress-personas](docs/operations.md#duress-personas).

## Transport security (TLS)

Optional, native, via rustls (`[server.tls]`). When `enabled = true` the
daemon binds HTTPS and refuses plaintext HTTP entirely — there is no mixed
mode on one port (run two `y2qd` processes on different ports for that).

- `require_pq_kex = true` (default) offers **only** the X25519MLKEM768
  post-quantum hybrid key-exchange group; a client that cannot negotiate it
  is refused at handshake time. Set `false` to fall back to rustls's
  default preference list (PQ-hybrid preferred, classic X25519/ECDH still
  offered).
- `client_ca_path` enables mutual TLS: every client must present a
  certificate chaining to that CA bundle, or the handshake is rejected.
- When TLS is disabled, `[server] allow_insecure_bind` gates whether the
  daemon will bind a non-loopback address at all — by default it refuses,
  since that would serve session tokens, passwords, and object plaintext
  unencrypted to the network. Loopback binds are always exempt (not
  reachable off-host).

`y2q`/`y2q-warp`/`y2q-fuse` verify the server certificate by default;
`--insecure` skips verification (dev/staging only), `--ca-cert` trusts a
private CA, `--client-cert`/`--client-key` supply a client certificate for
mutual TLS.

## Node key and keystore

The node key (tier 0) is the one piece of key material every other secret
in the deployment ultimately traces back to for server-structural
encryption (index, paths, metadata, bucket-config sidecars). It:

- Is **never auto-generated** — the daemon refuses to start without one
  supplied via `Y2QD_NODE_KEY` or `[crypto] node_key_file`.
- Is **never persisted** anywhere inside `storage.base_path` or
  `crypto.keystore_dir` — enforced at startup, so a `cp -r` of either tree
  cannot carry its own key.
- Only a **verifier** (`HMAC-SHA256(node_key, "y2q/v3/node-key-verifier")`)
  is stored, in `keystore.json`, to detect a wrong key at boot without ever
  writing the key itself to disk.
- Rotates **offline only** (`y2qd --rotate-node-key`), under the daemon's
  own keystore flock, journaled for crash safety (idempotent resume on
  interruption). Object bodies are never touched by a rotation — only
  metadata sidecars, bucket-config sidecars, and the index are
  re-encrypted under the new key.

`users.redb` and all bucket key material need no rotation when the node
key rotates — they're wrapped under user passwords and sealed to identity
keypairs, neither of which the node key touches.

Full rotation runbook and crash-safety details:
[docs/operations.md#node-key-rotation-offline](docs/operations.md#node-key-rotation-offline).

## Storage-tree metadata protection

Beyond object content (covered under
[Encryption at rest](#encryption-at-rest)):

- **File and bucket names** — on-disk directory and file names are
  irreversible keyed HMAC-SHA256 under a node-key-derived path key, so the
  storage tree leaks **neither bucket names nor object keys** to anyone who
  can read the directory. Listing reads names from the encrypted index, not
  the directory.
- **Object metadata** (labels, timestamps, checksums, the cleartext key) —
  encrypted per-object with AES-256-GCM under the node-key-derived Object
  Metadata Key, AEAD-bound to the object's opaque on-disk id so a metadata
  blob copied onto a different object's storage location fails to decrypt
  there.
- **The listing index** (`_y2q_index.redb`) — the entire file is encrypted
  at rest, per-4-KiB-block AES-256-GCM with the block index bound as AAD,
  under a node-key-derived Index File Key. It's a cache: if it goes
  missing or corrupt, every operation still works against on-disk truth,
  just slower for listings, and a startup/manual rebuild repopulates it.
- **The `.obj` container header** — authenticated by a node-key-derived
  Container Header Key, since it would otherwise be protected only by a
  CRC32 an on-disk-write attacker could simply recompute.

Source: [docs/architecture.md#storage](docs/architecture.md#storage).

## Client-side credential storage

`y2q-cli`, `y2q-fuse`, and `y2q-warp` are explicitly **out of scope** for
the guarded-memory work above (no `y2q-core` dependency, no guarded
allocations). This is a deliberate, not accidental, boundary: the CLI's
bearer token is already persisted to `~/.local/share/y2q/tokens.toml` (mode
`0600`) by design, for exactly the reason a stateless CLI needs to survive
between invocations — a client-side memory dump would reveal nothing the
token file doesn't already contain on disk. Aliases (server URL, username,
TLS options) live in `~/.config/y2q/config.toml`. Neither file is
guarded-memory protected while the process runs, and neither needs to be
for that specific threat to already be closed by filesystem permissions.

## Platform support summary

| Mechanism | Linux | macOS | Windows |
|---|---|---|---|
| Object/metadata/index encryption at rest | Yes | Yes | Yes |
| Key hierarchy, Argon2id, duress personas | Yes | Yes | Yes |
| TLS (native rustls, PQ-hybrid, mTLS) | Yes | Yes | Yes |
| Authorization (roles/ACLs/strict admin exclusion) | Yes | Yes | Yes |
| `uring` storage backend | Yes (kernel ≥5.6) | No | No |
| **Guarded memory** (`PROT_NONE`-at-rest pages, `mlock`, `MADV_DONTDUMP`/`WIPEONFORK`) | **Yes** | **No — `Zeroizing`-only fallback** | **No — `Zeroizing`-only fallback** |
| **Process hardening** (`PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, refuse-to-start probe) | **Yes** | **No — no-op, always starts** | **No — no-op, always starts** |

The bottom two rows are the ones to read carefully. `y2q_core::secmem` is
gated `#[cfg(target_os = "linux")]` throughout
(`crates/y2q-core/src/secmem.rs`); everything above that line in the table
is portable and behaves identically everywhere it's tested. On macOS and
Windows, `SecretBuf`/`SecretVec` compile and run via a
`Zeroizing<Vec<u8>>`-backed fallback behind the *identical* public API —
nothing fails to build, and functional behavior (sessions, logins, bucket
grants) is unaffected — but `unlock()` is a no-op and `harden_process()`
just logs a warning and unconditionally returns success. That means, on
those platforms:

- Plaintext session identity keys, bucket keys, passwords, and bearer
  tokens sit in ordinary, swappable heap for the session's whole lifetime,
  exactly as they did before this mechanism existed.
- The daemon **never refuses to start** on memory-protection grounds —
  `[server] allow_unprotected_memory` has no effect either way.
- A core dump, same-user debugger attach, or swapped page recovers
  whatever a live daemon holds, with no additional barrier beyond what the
  OS does by default for any ordinary process.

`y2qd` is developed and tested against Linux (the `uring` storage backend
already reflects a Linux-first posture); the CLI and client crates are
genuinely cross-platform. If you deploy `y2qd` itself on a non-Linux host,
budget for this gap explicitly rather than assuming parity with the table
above.

## Known limitations and non-goals

Consolidated from the sections above, so the boundary of what this project
claims is in one place:

- A root/kernel-privileged reader racing a request in flight recovers that
  request's plaintext, regardless of platform.
- Object body plaintext is never guarded-memory protected, by design (cost
  vs. benefit at `server.max_body_bytes` scale).
- Guarded memory and process hardening are Linux-only; see
  [Platform support summary](#platform-support-summary).
- The node key holder sees deployment *shape* (bucket/object counts,
  labels, sizes) without seeing content — an accepted consequence of
  keeping the metadata index reconstructible without every bucket's key.
- A leaked, valid Bearer token works until it expires or is explicitly
  revoked; there is no additional binding (e.g. to a TLS client
  certificate or source IP) today.
- Cross-architecture data portability is explicitly unsupported — see
  [docs/architecture.md#platform-support](docs/architecture.md#platform-support).
  This is a compatibility statement, not a security one, but is included
  here since it's adjacent to the platform-support caveats above.
- No pre-guarded-memory performance baseline has been published; the
  reasoned-about (not measured) per-request cost is one
  `mmap`+`mlock`+`munmap` pair and two `mprotect` calls against an ML-KEM
  decapsulation already costing tens of microseconds.
