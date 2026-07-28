# TODO

Tracked follow-ups that aren't blocking, but shouldn't be forgotten.

## `SessionInfo::new` has two adjacent same-typed parameters

`crates/y2qd/src/auth/session.rs` — `SessionInfo::new(username, role, created_at, expires_at, persona, revoke_other_sessions, identity_sk)`.

`created_at` and `expires_at` are both `SystemTime` and sit next to each other positionally. Transposing them at a call site would silently corrupt session expiry (not a compile error) — `created_at` is informational only (`#[allow(dead_code)]`), but `expires_at` drives real security-relevant session lifetime enforcement.

Both current call sites (`crates/y2qd/src/auth/handlers.rs:207`, `:291`) are correctly ordered today. Flagged during PR #61 review as the same class of same-typed-positional-argument footgun that caused a real `too_many_arguments` fix elsewhere in this branch (`crates/y2q-core/src/storage/rotation.rs`'s `RotationKeys` struct).

Fix, when convenient: either group `created_at`/`expires_at` into a small `SessionWindow { created_at, expires_at }` struct, or switch to a builder pattern for `SessionInfo::new`. Not urgent — no known bug today, just a risk for the next call site that gets added.
