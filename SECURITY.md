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
- [S3 gateway](#s3-gateway)
- [Duress personas](#duress-personas)
- [Transport security (TLS)](#transport-security-tls)
- [Node key and keystore](#node-key-and-keystore)
- [Device-based node-key unlock](#device-based-node-key-unlock)
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
- Memory disclosure of guarded secrets, **on Linux** (core dump, swap, and
  `ptrace`/`/proc/<pid>/mem` — including a root reader, and including while
  the pages are unlocked — see
  [Guarded memory](#guarded-memory-linux-only)).

**Not defended against:**

- Object-body plaintext in ordinary heap while a request is in flight. A
  root reader can recover that body via `ptrace` or `/proc/<pid>/mem`.
  Those interfaces cannot read `SecretBuf`/`SecretVec` pages (see
  [Guarded memory's scope boundary](#guarded-memory-linux-only)).
- A kernel compromise, or a hypervisor/cold-boot read of physical RAM.
  `memfd_secret` removes pages from the kernel direct map; it does not
  encrypt them.
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
| 0 | Node key — drives the metadata index key, path-blinding key, object-metadata key, bucket-config key, container-header key | Operator-supplied (`Y2QD_NODE_KEY` / `node_key_file`), or — in device mode — generated by `y2q admin device init` and recoverable only through the Registry Master Key layer (RMK; home-device wraps, away-device grants, emergency wraps — see [Device-based node-key unlock](#device-based-node-key-unlock)) | Operator mode: never. Device mode: only wrapped (AES-256-GCM under a key derived from RMK) in `devices.json` |
| 1 | Per-persona ML-KEM-768 identity keypair (4 credential slots per account, occupied or decoy) | Argon2id(password) wraps the secret half | Wrapped (Argon2id), never plaintext |
| 2 | Per-bucket-per-epoch ML-KEM-768 keypair | A 32-byte bucket-wrap key, sealed once per grantee's identity, never itself persisted | Never |
| 3 | Per-object AES-256-GCM content key | Fresh ML-KEM-768 encapsulation against the bucket's current-epoch public key, every PUT | Never (re-derived on every GET) |

A compromised tier doesn't cascade: the node key alone (tier 0) cannot
decrypt object plaintext without the specific bucket's tier-2 key material,
and a tier-1 identity key only unlocks what that persona was actually
granted (tier 2), not every bucket in the deployment. Global `admin`/
`auditor` roles are cryptographically excluded from object plaintext they
weren't explicitly granted — see [Authorization](#authorization).

The node key (tier 0) has two modes. In **operator mode** it is
operator-supplied CSPRNG output — never auto-generated by the daemon, which
refuses to start without one (`Y2QD_NODE_KEY` or `[crypto] node_key_file`)
unless a device registry exists. It is rejected outright if it resolves to a
path inside `storage.base_path` or `crypto.keystore_dir`, so a `cp -r` of
either tree can never accidentally carry the key that protects it. A length
floor (≥32 bytes) guards against a truncated paste, but does **not** prove
entropy — a passphrase that happens to decode to 32+ bytes will be accepted
and will be crackable offline at HMAC speed by anyone holding the storage
tree. Use `y2q admin gen-node-key --output PATH`, not a memorized passphrase.
A `node_key_file` is refused at startup unless only its owner can access it
(no group/other permission bits, checked on the opened file); `--output`
creates it exclusively with mode `0400`. The mode rule does not apply to
`Y2QD_NODE_KEY`.

In **device mode** the node key *is* generated (by `y2q admin device init`)
and *is* persisted, wrapped, inside `crypto.keystore_dir` (`devices.json`).
A `cp -r` of `keystore_dir` therefore carries wrapped key material; it is
useless without a TPM, an authenticator or a printed emergency code, but it
is no longer key-free. See
[Device-based node-key unlock](#device-based-node-key-unlock).

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
process, so a core dump, a swap page, or a `ptrace`/`/proc/<pid>/mem` read
(same-uid or root) recovered the key in plaintext. The same gap covered:

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
allocation shapes. The secret bytes are `memfd_secret` pages (`mmap`
`MAP_SHARED`), not ordinary anonymous memory. `memfd_secret` removes those
pages from the kernel direct map, so `PTRACE_PEEKDATA` and
`/proc/<pid>/mem` cannot read them — even while the owning process has
them `PROT_READ` or `PROT_READ|PROT_WRITE`, and even for root. A
`PROT_NONE` anonymous mapping does **not** do this: Linux still satisfies
those reads with `FOLL_FORCE`. `mprotect` between `PROT_NONE`,
`PROT_READ`, and `PROT_READ|PROT_WRITE` still works on the secretmem pages.

- **`SecretBuf`** — a long-lived secret. Its `memfd_secret` pages are
  `PROT_NONE` at rest and briefly `PROT_READ` for the duration of an
  `unlock()` guard, then restored to `PROT_NONE` when the guard drops.
  `PROT_NONE` stops accidental access from inside the process; it is not
  what stops `ptrace`. Reference-counted nesting supports concurrent
  readers from multiple request threads sharing one guard.
- **`SecretVec`** — a transient plaintext workspace (the destination of a
  decrypt, or the source of an encrypt), also `memfd_secret`, readable for
  its whole short life, with a fixed capacity so it never reallocates (a
  realloc would leave a stale, unzeroized copy in the old backing memory).

Guard pages on either side of the data are ordinary `PROT_NONE` anonymous
mappings and hold no secrets. Secretmem pages are locked out of swap (the
kernel charges them to `RLIMIT_MEMLOCK` and marks the VMA `VM_LOCKED`;
`mlock(2)` itself cannot pin secretmem and is used only for the anonymous
fallback below). They are hinted `MADV_DONTDUMP` (excluded from core dumps
at the VMA level, independent of the process-wide `RLIMIT_CORE`/dumpable
flag below). `MADV_WIPEONFORK` does not apply: secretmem is a shared
mapping and the kernel rejects that hint, so a `fork` would hand the
child the same bytes. `y2qd` does not fork. On drop, both scrub their
content with a volatile write (not eligible for compiler dead-store
elimination) before `munlock`/`munmap`.

If `memfd_secret` fails (`ENOSYS`, a kernel built without it, `EAGAIN` from
`RLIMIT_MEMLOCK`, permission) and the process policy is `Require` — the
production default — the allocation fails and `harden_process` refuses to
start. There is no silent fallback to anonymous `mmap`. `BestEffort`
(`[server] allow_unprotected_memory`) does fall back, once, with one
warning; those anonymous pages **are** readable by a privileged `ptrace`
or `/proc/<pid>/mem` reader.

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
one-page `SecretBuf` as a boot-time probe — so a missing `memfd_secret`
or a too-low `RLIMIT_MEMLOCK` fails loudly at startup instead of silently
at first login.

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
With the default, `y2qd` refuses to start if guarded allocation fails —
`memfd_secret` unavailable, or `RLIMIT_MEMLOCK` too small to charge the
secretmem pages (a handful of pages, not a meaningful fraction of any
reasonable limit):

```
Error: refusing to start: mlock failed (11); raise RLIMIT_MEMLOCK or set
[server] allow_unprotected_memory = true. Core dumps and swap would
expose session identity keys; set [server] allow_unprotected_memory =
true to override.
```

Errno 11 is `EAGAIN`: the secretmem `mmap` could not charge the pages to
`RLIMIT_MEMLOCK`. A seccomp filter that blocks `memfd_secret` is a
different failure (`memfd_secret failed` with `EPERM`). `BestEffort`
falls back for both, including after `EAGAIN`, by installing a fresh
anonymous mapping — the failed `MAP_FIXED` mmap has already removed the
reserved hole, so the fallback does not `mprotect` that address.

Fix by raising the limit (`LimitMEMLOCK=infinity` in a systemd unit,
`ulimit -l unlimited` for a shell-launched daemon), not by setting the
override — that downgrades to best-effort (secrets may be written to swap,
one warning logged) and is meant for local development, not production.
Full runbook: [docs/operations.md#memory-hardening-linux-only](docs/operations.md#memory-hardening-linux-only).

### Scope boundary — what this does *not* close

Stated explicitly because it's easy to over-claim guarded memory's reach:

- **A kernel compromise, or a direct read of physical RAM.** Identity
  keys, bucket keys, the process `MemoryKey`, node-derived keys,
  passwords, and bearer tokens held in `SecretBuf`/`SecretVec` are
  `memfd_secret` pages: `ptrace` and `/proc/<pid>/mem` cannot read them,
  including while unlocked and including for root. That is removal from
  the kernel direct map, not encryption, so a reader of guest physical
  memory is outside this boundary.
- **Object body plaintext is left in ordinary heap, deliberately.**
  `mlock`ing bodies up to `server.max_body_bytes` (256 MiB default) isn't
  viable, and scrubbing every GET's response body would be a real
  throughput regression for a much smaller marginal gain than guarding key
  material. A root reader can still recover a request's body while it is
  in flight. Body plaintext is only as protected as the response path
  itself (TLS in transit; nothing at rest in process memory beyond normal
  OS page lifecycle). If `memfd_secret` is unavailable the daemon refuses
  to start unless `[server] allow_unprotected_memory` is set.
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
- **Refresh limit** — `POST /api/v1/auth/refresh` trades a live token for a
  new one carrying a fresh `default_ttl_seconds` window, but only up to
  `auth.max_refreshes` times per token (default `0`: refresh is disabled
  entirely, so the very first attempt on any token is rejected). A token
  that has hit its limit is not revoked — it keeps authenticating normally
  for every other endpoint until it naturally expires; only the refresh
  operation itself is denied, so a session's *extendable* lifetime is
  bounded even if the bearer token is never otherwise compromised. The
  counter is carried forward across refreshes and preserved (not reset) by
  a duress persona switch, since that isn't a refresh and shouldn't grant
  a free one back.
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

1. **Global role** — an account-wide ceiling: `admin` (full verb ceiling
   on buckets this persona can decrypt, plus admin endpoints),
   `user`/`readonly`/`writeonly` (governed by bucket grants, capped to
   read-only or write-only respectively), `auditor` (read-only on buckets
   this persona can decrypt, plus read-only admin endpoints), `disabled`
   (nothing — login itself is refused). A global role is not a visibility
   bypass.
2. **Per-bucket ownership + ACL** — an owner (full control) plus an
   optional grant map (`read`/`write`/`writeonly`/`admin`) for other users.
   New buckets are private to the persona that created them. A bucket this
   persona has no sealed grant for is indistinguishable from one that
   doesn't exist: omitted from listings, 404 (never 403) on direct access
   — existence itself cannot be probed. 403 appears only when you can
   already see a bucket but lack the verb for the action. The exception is
   an ACL relationship of exactly `writeonly` (a drop box): write needs no
   sealed secret, so write stays allowed and a read is 403.
3. **Cryptographic bucket-key grant.** This is the property the per-bucket
   key hierarchy exists for. Listing, HEAD metadata, reading, writing,
   deleting, and ACL changes all require the caller's *persona* to hold a
   real, sealed bucket-key grant. A global `admin`/`auditor` role does not
   skip that check: with no grant, `GET /` omits the bucket and
   GET/HEAD/PUT/DELETE/ACL return **404**, not 403. An admin who
   personally holds a real grant still sees and reads that bucket, and
   creating a brand-new bucket still works for any role that can write.
   **There is no admin group key, no escrow secret, and no break-glass
   self-grant.**

With `enforce_authorization = false` the first two layers are skipped
(single-user/migration mode) and today's global-role short-circuit stays
— every authenticated caller has full access. Object plaintext is still
sealed to whoever holds the bucket key; that isn't an authorization
*policy* choice.

Full model, capability table, and status codes:
[docs/api.md#authorization](docs/api.md#authorization).

## S3 gateway

Optional second listener (`[s3] enabled = true`, off by default) speaking
AWS SigV4/S3 REST semantics. It layers entirely on top of the mechanisms
above rather than introducing an independent credential system — that was
the literal design requirement: the S3 surface must respect every guarantee
above, especially session expiry.

- **No password authentication on this listener at all.** S3 access uses
  temporary credentials — an access key id (an opaque lookup handle, not a
  secret) and a secret access key — minted over the *already-authenticated*
  REST API via `POST /api/v1/s3/credentials`. There is no way to obtain an
  S3 credential without first holding a live Bearer token.
- **A credential cannot outlive its session.** `expires_at =
  min(requested_ttl, session.expires_at)` at mint time — asking for
  `[s3] default_credential_ttl_seconds` (or any longer TTL) one second
  before the session ends still yields a credential that dies with the
  session, never later.
- **Every S3 request re-resolves the owning session — no cached
  authority.** The SigV4 extractor calls the exact same
  `SessionStore::get_active(&token_hash)` the REST `Authenticated`
  extractor uses, on every request. Logout, natural expiry, admin
  revocation, and a role change all evict the credential and fail the next
  S3 request identically (`ExpiredToken`/`InvalidAccessKeyId`) to how they
  fail a REST request with the same dead token.
- **Mid-transfer session death aborts the transfer.** A `SessionLeash`
  re-checks `get_active` every `[s3] session_recheck_bytes` transferred and
  at least every `session_recheck_interval_secs`, on both upload and
  download streams and between parts/objects in multipart and batch-delete
  operations. It also compares `Arc::ptr_eq` against the exact session row
  captured at request start — `switch_user_to_persona` (the duress
  mechanism, see [Duress personas](#duress-personas) below) replaces that
  row in place under the same token hash, so the pointers diverge and an
  in-flight transfer aborts instead of continuing under the just-revoked
  persona's bucket key. **Caveat, stated plainly:** the recheck is
  threshold-based, not per-byte, so a bounded window of already-in-flight
  bytes (up to `session_recheck_bytes`, or up to
  `session_recheck_interval_secs` of wall-clock time) can be delivered
  after the session actually died before the next check catches it. This
  is a deliberate throughput/latency trade-off, not an oversight — lower
  both values to shrink the window at the cost of more `get_active` calls
  per transfer.
- **Presigned URLs cannot outlive the session either.** Effective expiry is
  `min(X-Amz-Expires, credential.expires_at, session.expires_at)` — a
  presigned link generated with a one-hour `X-Amz-Expires` still dies the
  moment the session does.
- **The secret access key is sealed, never plaintext at rest**, under the
  same process-ephemeral `SessionKeyring` and the same AAD-binding pattern
  (here to `(token_hash, access_key_id)`) as every other secret in
  [Guarded memory](#guarded-memory-linux-only) — opened into guarded memory
  only for the duration of a signature check.
- **Same TLS bind refusal as the REST listener.** `[s3.tls]` is
  independent of `[server.tls]`; binding a non-loopback `[s3] host` with
  `[s3.tls] enabled = false` is refused unless `[s3] allow_insecure_bind =
  true`, for the same reason as [Transport security](#transport-security-tls)
  below.
- **No admin back-door, no policy surface this project can't back with a
  real cryptographic grant.** The S3 layer never resolves bucket keys
  itself — it calls the same `authz::authorize_bucket` and
  `bucket_keys::resolve_read_key`/`resolve_write_key` the REST handlers
  call, so [Authorization](#authorization)'s strict admin exclusion and
  404-vs-403 existence hiding apply identically. S3 sub-resources with no
  faithful mapping onto y2q's persona-keyed grants (ACLs, bucket policy,
  SSE-C, lifecycle, and others) return `501 NotImplemented` rather than
  silently accepting and ignoring them.

Full protocol reference: [docs/api.md#s3-gateway](docs/api.md#s3-gateway).

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

`POST /api/v1/personas` and `DELETE /api/v1/personas/{slot}` always apply
to every slot other than the one the caller is currently authenticated
through, **including** the account's real `primary_slot`. The response
shape does not depend on which slot it was (create's warning still says
that slot was overwritten). A silent skip would let a follow-up login
fail only for the real slot and identify it. There is no in-band way to
preserve primary and also make that new password work: only four slots
exist, so redirecting the write collides and is itself detectable.
`primary_slot` is still the random slot third parties grant to; it is not
immune to the account's own other personas.

A bucket the signed-in persona cannot decrypt is 404 on read, write,
delete, HEAD, and ACL — not 403 — including for an `admin` duress persona.
A 403 is reserved for a bucket the persona can already see but lacks the
verb for, and for a `writeonly` drop box (write allowed, read 403).

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

The client never follows HTTP redirects (3xx is returned as an error), so a
compromised or MITM'd endpoint cannot bounce the login body or bearer token to
another URL.

## Node key and keystore

The node key (tier 0) is the one piece of key material every other secret
in the deployment ultimately traces back to for server-structural
encryption (index, paths, metadata, bucket-config sidecars). It:

- In **operator mode** it is never auto-generated — the daemon refuses to
  start without one supplied via `Y2QD_NODE_KEY` or
  `[crypto] node_key_file` (or a device registry, below).
- In operator mode it is never persisted anywhere inside `storage.base_path`
  or `crypto.keystore_dir` — enforced at startup, so a `cp -r` of either
  tree cannot carry its own key. **Device mode differs**: the key is
  generated at `device init` and stored wrapped in
  `<keystore_dir>/devices.json`; a `cp -r` of `keystore_dir` carries that
  wrapped material, which opens only with a registered TPM, authenticator
  or unused emergency code.
- Only a **verifier** (`HMAC-SHA256(node_key, "y2q/v3/node-key-verifier")`)
  is stored, in `keystore.json`, to detect a wrong key at boot without ever
  writing the key itself to disk.
- Rotates **offline only** (`y2qd --rotate-node-key`), under the daemon's
  own keystore flock, journaled for crash safety (idempotent resume on
  interruption). Object bodies are never touched by a rotation — only
  metadata sidecars, bucket-config sidecars, and the index are
  re-encrypted under the new key.

If the key is supplied via the environment, the daemon overwrites and
unsets that variable before serving; the key file on disk is unchanged
and root who can read the file still has the key.

`users.redb` and all bucket key material need no rotation when the node
key rotates — they're wrapped under user passwords and sealed to identity
keypairs, neither of which the node key touches.

Full rotation runbook and crash-safety details:
[docs/operations.md#node-key-rotation-offline](docs/operations.md#node-key-rotation-offline).

## Device-based node-key unlock

Optional, Linux-only, built with the `devices` cargo feature (off by
default). When `<keystore_dir>/devices.json` exists and no operator key
(`Y2QD_NODE_KEY` / `node_key_file`) is configured, `y2qd` recovers the node
key from registered hardware instead. An operator key, when present, always
takes precedence and the device path never runs.

**Key layering.** A 32-byte Registry Master Key (RMK) is generated at
`device init` and never stored in the clear. RMK is wrapped by each
registered home device (permanent), by each away device (as a time-boxed
*grant*), and by each of ten one-time emergency codes. The node key lives in
a single `nk_wrap` under an RMK-derived key. Every wrap is symmetric
(AES-256-GCM). The ML-KEM-768 secrets of tiers 1 and 2 are wrapped at rest
under symmetric keys, so no Shor-reachable at-rest secret exists; the
symmetric layers lose only Grover margin. The quantum-exposed links are
listed under [Transport note](#transport-note) and the Roughtime bullet
below.

- A **home device** is a TPM 2.0 on the host: non-interactive, PCR-sealed,
  holding a permanent wrap of RMK.
- An **away device** is any FIDO2/CTAP2 authenticator with the
  `hmac-secret` extension. It is registered permanently and never
  deregistered by expiry. A successful home unlock mints a grant for every
  away device: a fresh ciphertext of RMK under that device's key, carrying
  `not_after_unix = attested_now + away_grant_seconds`. Away devices unlock
  only while their grant exists and has not passed `not_after_unix`.
- `away_grant_seconds` is registry policy, not configuration: fixed at
  `device init` (default 43 200 s; bounds 60..=2 592 000), stored in
  `devices.json`, and bound into the AAD of `nk_wrap` and of every grant,
  so editing it makes the node key unrecoverable by every path rather than
  lengthening the window. Only `y2q admin device set-grant-period` changes
  it (home authority: any value; emergency authority: strictly smaller
  values only).
- **Time comes from Roughtime** (RFC 10049), not the host clock. An away
  unlock with a live grant requires a verified attested time; there is no
  host-clock fallback.
- With **zero home devices** there is nothing that could mint a grant, so
  away devices hold a permanent wrap instead and unlock unconditionally,
  with no network and no clock. This is opt-in: without a TPM home device,
  `device init --fido2` is refused unless `--permanent-away` is given, and
  the last TPM home device cannot be removed while any FIDO2 device
  survives.
- **Ten one-time emergency codes** are printed once at registry init and
  burned individually on use. The set is committed to as `ESC`, bound into
  every AAD.

### End state at its true strength

**Principal exposure: the away window is a software-only time-box.** A copy
of the medium taken while a grant was live, plus the away token (and PIN, if
`uv_required`), opens on any host at any later date, because the expiry
check is software that a patched binary skips. The only things that end
that exposure are a `device init` (new RMK) or, for a home-only registry,
having no away grants at all. Everything below about erasure concerns only
the original medium; it never reaches a copy already taken.

- A grant's `not_after_unix` is enforced in software on every away unlock,
  which requires an attested time. Key material enforces it only after an
  **attested sweep** erases the ciphertext: an unlock with attested time
  (daemon boot, admin CLI or away unlock), or the daemon's timer. Loading
  the registry alone never erases, because it reads no clock. From the
  first such sweep after expiry, the away authenticator opens nothing on
  that medium, not with a patched binary and not with a correct PIN. Until
  that sweep runs, a patched binary holding the token (and PIN, if `uv_required`) can still
  open an expired grant, so a powered-off medium that is never swept keeps
  that exposure. No cryptographic time-lock exists without a trusted clock
  on the medium.
- A **copy of the medium taken while a grant was live**, combined later
  with the away token (and its PIN, if the device is `uv_required`), yields
  RMK and therefore the node key, on any host and at any later date, until
  a `device init` creates a new RMK. The expiry check is software: a
  patched binary ignores `not_after_unix` on the copy. Erasure never
  reaches a copy already taken. A home-booted daemon re-mints grants every
  `grant_timer_interval_seconds`, so while it runs a snapshot always
  contains a live grant. After it stops, the last grant stays openable
  until the next attested sweep. `away_grant_seconds` therefore bounds only
  the *original* medium (once an attested sweep erases the grant), not a
  copy, and not the uptime-driven refresh chain.
- A **home device** plus the medium always yields the node key: the home
  wrap is permanent by construction, because something has to be able to
  mint the next grant. TPM sealing bounds that: the sealed blob is useless
  on another machine and refuses after a boot-chain change, but it does not
  bound an attacker who has the whole host running. With zero home devices,
  each away token plus the medium yields the node key permanently; that is
  the price of the no-network mode, chosen explicitly at init with
  `--permanent-away`. With zero home devices, anyone holding an away token,
  its PIN and the medium can also add a persistent FIDO2 record
  (`add-fido2` under away authority), and only an emergency code can remove
  it.
- The authenticator's PIN retry lockout (8 attempts on commodity tokens,
  then the FIDO2 application resets and destroys the credential) is the
  only hardware bound on a drive and token stolen together inside a live
  window. It exists **only** for devices registered with
  `uv_required = true`, and only when the PIN is not stored on the same
  medium — `--no-uv` registration and a `Y2QD_FIDO2_PIN` written into a
  unit file beside `keystore_dir` each remove it.
- Roughtime's trust chain is Ed25519 (RFC 10049 §9.5: "the only supported
  signature scheme, Ed25519, is not quantum resistant … will not survive
  the advent of quantum computers"). A quantum adversary holding a stale
  medium could forge time and reopen an expired grant while a grant
  ciphertext still exists on it; the token (and PIN, if `uv_required`)
  requirement still applies, and it buys nothing once the grant is erased.
  Roughtime signatures bind freshness only, not at-rest confidentiality.
- An older copy of `devices.json` verifies under the same state key, and
  RMK is never rotated, so anyone who ever unlocked this registry retains
  RMK and can forge registry state; a restored backup also revives
  already-burned emergency slots. Cutting off a party that has already
  unlocked takes a new RMK, which only a new registry creates: stop the
  daemon → `--rotate-node-key` to an operator-supplied key → delete
  `devices.json` → `y2q admin device init --adopt-existing-node-key`.
  Registry backups carry the same authority as the printed code sheet.
  Node-key rotation does not cut off a holder of RMK.
- On flash media the erased grant ciphertext may survive in unreferenced
  FTL blocks; erasure is a logical revocation, not guaranteed physical
  destruction.
- In a portable deployment `keystore_dir` travels on the same medium, so a
  stolen drive still exposes `users.redb`, whose identity keys are
  Argon2id-wrapped under user passwords; password strength and the
  configured Argon2 cost remain the bound there, independent of this
  feature.
- A grant's expiry is checked against attested time only: a grant is usable
  while `max(L_i) <= not_after_unix`, where `L_i` is the lower bound of
  each usable response. True time may then exceed `not_after_unix` by up to
  `min(U_i) − max(L_i)`, which is at most `2 × MAX_RADIUS_S` = 120 s. This
  slack is accepted.

### TPM sealing boundary

TPM sealing defeats **offline theft of the drive** — a stolen disk cannot
be unsealed on another machine, and a changed boot chain refuses. PCR 7
only separates a trusted boot chain from anything else while **Secure Boot
is enforcing**; with it off, PCR 7 is identical on every boot, so any
bootable medium unseals. `device init` and `add-tpm` therefore refuse a
PCR-7 policy unless Secure Boot is enforcing (`--allow-secure-boot-off`
overrides). Even with Secure Boot on and the default `--pcrs 7`, it does
**not** bound theft of the whole host: an attacker holding the machine can
boot any Secure-Boot-trusted OS on it, satisfy PCR 7 and unseal.
`--pcrs 0,4,7` narrows that at the cost of resealing on every firmware or
kernel update. It does not defeat a root-capable attacker on the live
host, who can invoke the same unseal; in legacy mode the node key is also
in the daemon's memory.

`reseal-tpm` enforces the same Secure Boot precheck as `device init` and
`add-tpm` for a PCR-7 policy, and takes the same `--allow-secure-boot-off`
override.

### What a compromised daemon uid gets

With the **socket-activated key helper** (`y2q-keyd.socket` +
`y2q-keyd@.service`, running `y2qd --key-serve` as uid `y2q-keyd`;
recommended for device deployments; enabled by a non-empty `[crypto.devices]
key_agent_socket`) no resident process holds RMK. Each connection spawns a
fresh helper that handles exactly one request and exits. Root arms it
(`y2qd --key-arm`, peer uid must equal `key_agent_arm_uid`, default 0) by
storing one-time authorization material (empty for unattended hosts; an
optional passcode, FIDO2 PIN or emergency code for attended ones) in a
`0600` file on tmpfs under `/run/y2q-keyd`. The daemon then fetches (peer
uid must equal `key_agent_peer_uid`); the helper reads **and deletes** the
armed file, runs the registry unlock with that material, returns NK once
and exits. The armed file is consumed by every fetch attempt, success or
failure (a refused peer uid does not consume it). `key_agent_peer_uid` has no
default; unset, the helper refuses every fetch.

What a compromised daemon uid therefore gets, stated honestly:

- It holds **one transient raw NK copy** from boot (the daemon needs it for
  the keystore load and key derivation), plus node-derived structural keys,
  live session keys and in-flight object bodies (ordinary heap, see above).
  Anything that already read NK from the daemon's memory keeps it.
- It does **not** get RMK, the TPM, any hardware secret, passcode or PIN, or
  the ability to forge `devices.json` (`y2q-keyd`-owned, `0600`).
- It **cannot re-fetch** NK or RMK: it can connect to the socket, but a
  fetch without a prior arm is refused and only root (the arm uid) can
  arm. Re-fetching would require root.

In **legacy in-process mode** (`key_agent_socket = ""`) the daemon holds
RMK and the state key and has TPM access, so a compromised daemon uid can
re-run the PCR-policy unseal and obtain NK, RMK and registry authority. It
is strictly weaker; use it only where a second uid is impossible.

**Root on the live host gets everything in both modes**: it can arm and
fetch, read in-flight object-body plaintext from ordinary heap, invoke the
TPM unseal, and read process state other than `memfd_secret` pages.

### Home second factor

A Home (TPM) device may carry a second factor (`y2q admin device
set-home-factor`, exactly one of `--passcode`, `--fido2 <label-or-id>` or
`--none`): a passcode, or a registered FIDO2 away token (the same
token can serve both roles). The home KEK is then derived from the TPM
secret **and** the factor secret, so a stolen drive plus a booted copy of
the host no longer unseals without the passcode or the token and PIN. Such a
device cannot be unlocked unattended: the host is armed interactively at
each start, a crash restart fails until re-armed, and the sweep timer logs
and exits without refreshing grants. A lost factor is recoverable only with
an emergency code. Removing a token that a home factor references is
refused.

### `devices.json`: what it exposes

Every secret in `devices.json` (wraps, grants, `nk_wrap`, the factor
blobs) is AEAD-encrypted. The file is not encrypted as a whole, so the
following are readable by anyone holding a copy: device labels and ids,
kinds, `added_at` timestamps, TPM PCR slots and bank, FIDO2 credential ids
and rp id, signature counters, emergency-slot burn flags and burn
timestamps, grant issue and expiry deadlines, `away_grant_seconds`, and the
device count. This is metadata leakage, not key exposure. Encrypting the
file in layers would only *reduce* that leakage; it would not change who
can unlock, since everything that matters is already wrapped. A stale copy
authenticates under the same state key, so it **replays burned emergency
slots** and **revives erased grants**.

### Emergency-code bound

The ten codes cannot be regenerated or replaced inside an existing
registry, because the set is bound into every wrap's AAD. A new set exists
only in a new registry created by `device init`, and over an existing
dataset only with `--adopt-existing-node-key` and the raw node key in hand.
Possession of the raw node key is the bound on "codes cannot be replaced".
An emergency unlock neither mints nor erases grants and reads no attested
time.

### What the authority table is and is not

Mutating operations are gated by the authority that unlocked the registry
(home, away, emergency). That table bounds the stock CLI and daemon and
operator error. It is not a cryptographic bound on a holder of the
authenticator: an away unlock inside its window already yields RMK and the
node key, so anyone able to run a patched binary with the token in hand and
a live grant has everything. The cryptographic bound is the grant's
lifetime: once erased, the away device's secret opens nothing.

### Transport note

The KEKs are symmetric at rest, but the CTAP2 `hmac-secret` exchange
encrypts salt and output under a P-256 ECDH shared secret negotiated with
the token over the local USB bus. That transport is classically asymmetric
and outside the at-rest post-quantum posture; a recorded USB session, not
the drive, would be the exposure. y2q never verifies the FIDO2 assertion
signature (ES256 credential); the secret comes from `hmac-secret` only.
Together with Roughtime's Ed25519, these are the quantum-exposed links.

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
the guarded-memory work above (a default build of `y2q-cli` has no
`y2q-core` dependency and no guarded allocations; a build with
`--features devices` links `y2q-core` and holds device secrets in guarded
allocations, while a default build links no device code). This is a
deliberate, not accidental, boundary: the CLI's
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
| **Guarded memory** (`memfd_secret` pages, `PROT_NONE` at rest, `MADV_DONTDUMP`) | **Yes** | **No — `Zeroizing`-only fallback** | **No — `Zeroizing`-only fallback** |
| **Process hardening** (`PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, refuse-to-start probe) | **Yes** | **No — no-op, always starts** | **No — no-op, always starts** |
| **Device-based node-key unlock** (TPM home / FIDO2 away / Roughtime) | **Yes, with `--features devices`** (not in the container image or the cross-built release artifacts) | **No** | **No** |

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

- A root reader racing a request in flight can recover that request's
  **object body** from ordinary heap, regardless of platform. On Linux,
  secrets held in `SecretBuf`/`SecretVec` (identity keys, bucket keys, the
  process `MemoryKey`, node-derived keys, passwords, bearer tokens) are
  not readable via `ptrace` or `/proc/<pid>/mem`, including while unlocked.
  If `memfd_secret` is unavailable the daemon refuses to start unless
  `[server] allow_unprotected_memory` is set. A kernel compromise or a
  direct read of physical RAM is still out of scope.
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
- The S3 gateway's mid-transfer session recheck (`SessionLeash`) is
  threshold-based, not continuous — a bounded window of already-in-flight
  bytes can be delivered after a session actually died before the next
  check catches it. See [S3 gateway](#s3-gateway) above.
- Cross-architecture data portability is explicitly unsupported — see
  [docs/architecture.md#platform-support](docs/architecture.md#platform-support).
  This is a compatibility statement, not a security one, but is included
  here since it's adjacent to the platform-support caveats above.
- No pre-guarded-memory performance baseline has been published; the
  reasoned-about (not measured) per-request cost is one
  `mmap`+`mlock`+`munmap` pair and two `mprotect` calls against an ML-KEM
  decapsulation already costing tens of microseconds.
