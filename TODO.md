# TODO

Tracked follow-ups that aren't blocking, but shouldn't be forgotten.

## `SessionInfo::new` has two adjacent same-typed parameters

`crates/y2qd/src/auth/session.rs` — `SessionInfo::new(username, role, created_at, expires_at, persona, revoke_other_sessions, identity_sk)`.

`created_at` and `expires_at` are both `SystemTime` and sit next to each other positionally. Transposing them at a call site would silently corrupt session expiry (not a compile error) — `created_at` is informational only (`#[allow(dead_code)]`), but `expires_at` drives real security-relevant session lifetime enforcement.

All three current call sites (`crates/y2qd/src/auth/handlers.rs:207`, `:291`, and `crates/y2qd/src/auth/session.rs`'s `switch_user_to_persona`) are correctly ordered today. Flagged during PR #61 review as the same class of same-typed-positional-argument footgun that caused a real `too_many_arguments` fix elsewhere in this branch (`crates/y2q-core/src/storage/rotation.rs`'s `RotationKeys` struct).

Fix, when convenient: either group `created_at`/`expires_at` into a small `SessionWindow { created_at, expires_at }` struct, or switch to a builder pattern for `SessionInfo::new`. Not urgent — no known bug today, just a risk for the next call site that gets added.

## Self-service persona endpoints don't replicate in cluster mode

`crates/y2qd/src/auth/handlers.rs` — `create_persona` (`POST /api/v1/personas`)
and `delete_persona` (`DELETE /api/v1/personas/{slot}`) both call
`state.user_store.upsert(&updated)` directly, unlike every other user-record
mutation in the daemon (`reset_identity`, `set_user_role`, add/delete-user),
which route through `cluster::cluster_upsert_user`/`cluster_delete_user` so
the change proposes through Raft and projects to every node via
`project_user`. In a clustered deployment this means a persona created or
deleted through one node is only visible - and only has its session revoked
(`delete_persona`'s `revoke_user_persona`) - on that same node; other nodes
keep serving the old slot's login/decoy indefinitely, until something else
(e.g. a later `reset-identity`) happens to rewrite the whole record.

Not a data-loss or privilege-escalation bug (both endpoints only ever touch
the caller's own record, and each node's copy is internally consistent), but
it silently breaks the "persona works from any node" expectation the rest of
the cluster design promises. Found alongside the PR #61 review's
`reset_identity`/cross-node-session-revocation finding; out of scope for that
fix since it requires each of `create_persona`/`delete_persona` to gain the
same `cluster: Option<web::Data<ClusterRuntime>>` + branch every other
mutating auth handler already has.

Fix, when convenient: thread `cluster: Option<web::Data<ClusterRuntime>>`
into both handlers and call `cluster_upsert_user`/project locally exactly as
`reset_identity` does.
