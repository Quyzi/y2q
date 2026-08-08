//! Bucket-level authorization.
//!
//! Authentication ([`crate::auth`]) answers "who is calling"; this module
//! answers "may they do this to this bucket". Object access is derived entirely
//! from the object's bucket — there is no per-object ACL.
//!
//! Access is modelled as a set of verb [`Caps`] (read / write / admin). The
//! effective capability for an action is the intersection of two ceilings:
//!
//! - the caller's **global role** ([`role_caps`] / [`role_is_global`]), and
//! - their **per-bucket relationship** (owner, ACL grant, or none).
//!
//! Using a set rather than an ordered ladder is what lets `WriteOnly` grant
//! write without read. The resolver is leak-averse (see [`authorize_bucket`]):
//! a caller with no relationship to a bucket cannot tell it apart from one that
//! does not exist.

use y2q_core::crypto::Role;
use y2q_core::{AnyStorage, BucketConfig, BucketPermission, Error as CoreError, Listing};

use crate::auth::Authenticated;
use crate::error::AppError;

/// A set of verb capabilities on a bucket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Caps {
    pub read: bool,
    pub write: bool,
    pub admin: bool,
}

impl Caps {
    const NONE: Caps = Caps {
        read: false,
        write: false,
        admin: false,
    };
    const FULL: Caps = Caps {
        read: true,
        write: true,
        admin: true,
    };

    /// Whether this set permits the verb an action of class `required` needs.
    fn allows(self, required: BucketPermission) -> bool {
        match required {
            // `WriteOnly` is only ever a grant/role level, never an action
            // requirement, but map it to `write` defensively.
            BucketPermission::Read => self.read,
            BucketPermission::Write | BucketPermission::WriteOnly => self.write,
            BucketPermission::Admin => self.admin,
        }
    }

    fn intersect(self, other: Caps) -> Caps {
        Caps {
            read: self.read && other.read,
            write: self.write && other.write,
            admin: self.admin && other.admin,
        }
    }
}

/// Verb ceiling conferred by a global role.
pub(crate) fn role_caps(role: Role) -> Caps {
    match role {
        Role::Admin | Role::User => Caps::FULL,
        Role::ReadOnly | Role::Auditor => Caps {
            read: true,
            ..Caps::NONE
        },
        Role::WriteOnly => Caps {
            write: true,
            ..Caps::NONE
        },
        Role::Disabled => Caps::NONE,
    }
}

/// Whether a role sees every bucket (global visibility) rather than only the
/// buckets it owns or has been granted. Admins act on all buckets; auditors can
/// read all buckets.
pub(crate) fn role_is_global(role: Role) -> bool {
    matches!(role, Role::Admin | Role::Auditor)
}

/// Whether `candidate`'s verb ceiling is fully covered by `ceiling`'s — i.e.
/// `candidate` grants nothing `ceiling` doesn't already grant. Used to stop
/// a persona (phase 5, `POST /api/v1/personas`) from being minted with more
/// power than the account's own global role.
///
/// The capability-triple comparison alone cannot distinguish `Admin` from
/// `User`, or `Auditor` from `ReadOnly` — each pair shares an identical
/// [`Caps`] set. Only [`role_is_global`] tells them apart: `Admin`/`Auditor`
/// additionally grant visibility into every bucket in the deployment, not
/// just ones the account owns or was granted. Without this check, any
/// account (even a plain `user`) could mint an `admin` persona for itself
/// and log in as a global administrator — see the module docs on
/// [`role_is_global`].
pub(crate) fn role_permits(candidate: Role, ceiling: Role) -> bool {
    let c = role_caps(candidate);
    let m = role_caps(ceiling);
    let caps_permitted = (!c.read || m.read) && (!c.write || m.write) && (!c.admin || m.admin);
    let global_permitted = !role_is_global(candidate) || role_is_global(ceiling);
    caps_permitted && global_permitted
}

/// Verb capabilities a bucket grants `username` by ownership or ACL. `None`
/// means no relationship at all (not the owner, not in the ACL).
pub(crate) fn bucket_grant_caps(cfg: &BucketConfig, username: &str) -> Option<Caps> {
    match cfg.owner.as_deref() {
        Some(owner) if owner == username => Some(Caps::FULL),
        Some(_) => cfg.acl.get(username).copied().map(grant_caps),
        None => None,
    }
}

/// Verb capabilities conferred by a per-bucket grant level.
fn grant_caps(level: BucketPermission) -> Caps {
    match level {
        BucketPermission::Read => Caps {
            read: true,
            ..Caps::NONE
        },
        BucketPermission::Write => Caps {
            read: true,
            write: true,
            admin: false,
        },
        BucketPermission::WriteOnly => Caps {
            write: true,
            ..Caps::NONE
        },
        BucketPermission::Admin => Caps::FULL,
    }
}

/// Outcome of a permitted authorization check.
pub enum Decision {
    /// The caller may proceed against an existing (or to-be-read) bucket.
    Allowed,
    /// The bucket does not yet exist; this is a write that will create it. The
    /// handler should record the caller as owner (via [`claim_ownership`])
    /// after the write succeeds. Read-only handlers may treat this exactly like
    /// [`Decision::Allowed`] — the underlying read will simply 404.
    ClaimOwnership,
}

/// Effective capabilities for `auth` on `cfg` (role ceiling ∩ bucket
/// relationship). The bool is whether the caller can *see* the bucket at all
/// (owner, ACL grant, or a globally-scoped role) — used to choose 403 vs 404.
///
/// `read` and `admin` are additionally gated on `auth`'s *persona* actually
/// holding a working cryptographic bucket-key grant (see
/// [`crate::bucket_keys::is_visible`]): the ACL/ownership fields are
/// username-keyed and persona-agnostic, but the sealed bucket-key grants
/// are per-persona, so a duress persona whose slot was sealed with a decoy
/// must not read — or administer (rotate keys, manage the ACL, delete the
/// bucket) — here even when the ACL says the *user* can. `write` is
/// unaffected by this gate — writing only needs the bucket's public key,
/// never a persona-specific secret-key grant, so a `WriteOnly` drop-box
/// grantee (who never gets a real grant row at all) keeps working.
fn effective_caps(auth: &Authenticated, cfg: &BucketConfig, bucket: &str) -> (Caps, bool) {
    let rc = role_caps(auth.role);
    if role_is_global(auth.role) {
        return (rc.intersect(Caps::FULL), true);
    }
    match bucket_grant_caps(cfg, &auth.username) {
        Some(mut bc) => {
            let real_grant = crate::bucket_keys::is_visible(&auth.session, cfg, bucket);
            if bc.read && !real_grant {
                bc.read = false;
            }
            if bc.admin && !real_grant {
                bc.admin = false;
            }
            (rc.intersect(bc), true)
        }
        None => (Caps::NONE, false),
    }
}

/// Resolve and enforce the caller's permission on `bucket`.
///
/// On success returns whether the caller is acting on an existing bucket
/// ([`Decision::Allowed`]) or creating a brand-new one they implicitly own
/// ([`Decision::ClaimOwnership`]). On denial returns an [`AppError`] carrying
/// the correct status:
/// - **404** when the caller has no relationship to the bucket and cannot see
///   it — never reveal that such a bucket exists. This also covers a Read
///   request denied *purely* because this persona's cryptographic bucket-key
///   grant doesn't cover it while the username-keyed ACL says it should: that
///   case is indistinguishable from the bucket not existing (the duress
///   deniability property — see [`effective_caps`]).
/// - **403** when the caller can see the bucket but lacks the verb (because of
///   their role ceiling, their grant level, or both).
pub async fn authorize_bucket(
    auth: &Authenticated,
    storage: &AnyStorage,
    bucket: &str,
    required: BucketPermission,
) -> Result<Decision, AppError> {
    if !auth.authz_enforced {
        // Authorization disabled -> no ACL/ownership gate on an *existing*
        // bucket, but a brand-new one still needs its owner/key material
        // seeded (there is no group/escrow key to encrypt against
        // otherwise) — so a Write against a not-yet-existing bucket still
        // reports `ClaimOwnership` regardless of the flag.
        return if matches!(required, BucketPermission::Write)
            && !storage
                .bucket_exists(bucket)
                .await
                .map_err(AppError::from)?
        {
            Ok(Decision::ClaimOwnership)
        } else {
            Ok(Decision::Allowed)
        };
    }

    let cfg = storage
        .get_bucket_config(bucket)
        .await
        .map_err(AppError::from)?;

    let (eff, visible) = effective_caps(auth, &cfg, bucket);
    if eff.allows(required) {
        // A globally-scoped role (Admin/Auditor) "sees" every bucket via its
        // role ceiling, including one that doesn't exist yet — that
        // ceiling is about visibility into *other* users' buckets, not an
        // exemption from becoming the actual crypto owner of a bucket it
        // creates itself. Without this, an admin's first write to a new
        // bucket would never seed key material for anyone at all, leaving
        // an object nobody — not even the admin who wrote it — can decrypt.
        if cfg.owner.is_none()
            && matches!(required, BucketPermission::Write)
            && !storage
                .bucket_exists(bucket)
                .await
                .map_err(AppError::from)?
        {
            return Ok(Decision::ClaimOwnership);
        }
        return Ok(Decision::Allowed);
    }

    let denied_only_by_missing_crypto_grant = !role_is_global(auth.role)
        && bucket_grant_caps(&cfg, &auth.username).is_some_and(|bc| match required {
            BucketPermission::Read => bc.read,
            BucketPermission::Admin => bc.admin,
            _ => false,
        });
    if visible && !denied_only_by_missing_crypto_grant {
        // Caller can see the bucket but lacks the verb.
        return Err(AppError(CoreError::Forbidden {
            bucket: bucket.to_owned(),
        }));
    }

    // No relationship to the bucket. A write to a not-yet-created, unowned
    // bucket claims it — but only if the caller's role permits writing.
    let role_can_write = role_caps(auth.role).write;
    if cfg.owner.is_none()
        && matches!(required, BucketPermission::Write)
        && role_can_write
        && !storage
            .bucket_exists(bucket)
            .await
            .map_err(AppError::from)?
    {
        Ok(Decision::ClaimOwnership)
    } else {
        Err(AppError(CoreError::NotFound {
            bucket: bucket.to_owned(),
            key: String::new(),
        }))
    }
}

/// Record `auth`'s persona as the bucket's owner if it has none yet, seeding
/// its epoch-0 key material at the same time (real access for this persona,
/// decoy access for the claiming user's other personas — see
/// [`crate::bucket_keys::new_owner_key`]). Idempotent: if another writer
/// already claimed the bucket, the existing owner and key material are left
/// untouched and this returns the config *they* wrote, not a
/// caller-generated one — a caller must never encrypt against key material
/// it generated but lost the race to persist. Called by write handlers
/// after a [`Decision::ClaimOwnership`] PUT/create.
///
/// Race-narrowing, not race-*proof*: [`Listing::create_bucket`]'s
/// create-if-absent is itself a check-then-act on the filesystem/uring
/// backends (no bucket-level lock exists below this layer), so this can
/// only shrink the window two concurrent first-writers race through, not
/// close it — the same limitation the pre-existing plain `create_bucket`
/// path already has. A closed race needs a real per-bucket lock in the
/// storage layer, out of scope here.
///
/// Returns the resulting (possibly pre-existing) [`BucketConfig`] plus
/// whether *this call* physically created the bucket directory (from
/// [`Listing::create_bucket`]'s own return), so callers that need that
/// signal (the explicit create endpoint's `created` response field) don't
/// have to call `create_bucket` a second time themselves — doing so would
/// always observe `false` (the directory now exists) and silently skip
/// seeding owner/key material entirely.
pub async fn claim_ownership(
    storage: &AnyStorage,
    user_store: &y2q_core::crypto::UserStore,
    bucket: &str,
    session: &crate::auth::session::SessionInfo,
) -> Result<(BucketConfig, bool), AppError> {
    // `create_bucket` reports `true` only to whichever caller's directory
    // creation the filesystem actually observed first; a caller that gets
    // `false` (bucket already existed) never generates key material at all,
    // narrowing — though not eliminating, see above — the window where two
    // racing writers each mint their own epoch-0 keypair.
    let created = storage
        .create_bucket(bucket)
        .await
        .map_err(AppError::from)?;
    let mut cfg = storage
        .get_bucket_config(bucket)
        .await
        .map_err(AppError::from)?;
    if created && cfg.owner.is_none() {
        let key =
            crate::bucket_keys::new_owner_key(user_store, bucket, session).map_err(AppError)?;
        cfg.owner = Some(session.username.clone());
        cfg.keys.push(key);
        storage
            .set_bucket_config(bucket, &cfg)
            .await
            .map_err(AppError::from)?;
        // Read back rather than trusting our own locally-mutated `cfg`: if
        // another caller also observed `created` (the underlying
        // create-if-absent isn't a true CAS — see above) and its
        // `set_bucket_config` physically landed after ours, our own key
        // material is already orphaned and encrypting against it here would
        // silently produce an object nothing can ever decrypt. Trusting
        // whatever is on disk *now* means every racing caller converges on
        // the same (whoever-landed-last) owner and key material.
        cfg = storage
            .get_bucket_config(bucket)
            .await
            .map_err(AppError::from)?;
    }
    Ok((cfg, created))
}

/// Whether `auth` may at least read `bucket`. Used to filter listings and
/// search results without erroring.
pub async fn bucket_readable(
    auth: &Authenticated,
    storage: &AnyStorage,
    bucket: &str,
) -> Result<bool, AppError> {
    if !auth.authz_enforced {
        return Ok(true);
    }
    // Globally-scoped read roles (admin, auditor) short-circuit without a config
    // read when their ceiling already grants read.
    if role_is_global(auth.role) {
        return Ok(role_caps(auth.role).read);
    }
    let cfg = storage
        .get_bucket_config(bucket)
        .await
        .map_err(AppError::from)?;
    let (eff, _) = effective_caps(auth, &cfg, bucket);
    Ok(eff.read)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn cfg_owned(owner: &str, acl: &[(&str, BucketPermission)]) -> BucketConfig {
        let mut map = BTreeMap::new();
        for (u, p) in acl {
            map.insert((*u).to_owned(), *p);
        }
        BucketConfig {
            owner: Some(owner.to_owned()),
            acl: map,
            ..Default::default()
        }
    }

    #[test]
    fn owner_has_full_caps() {
        let cfg = cfg_owned("alice", &[]);
        assert_eq!(bucket_grant_caps(&cfg, "alice"), Some(Caps::FULL));
    }

    #[test]
    fn write_grant_implies_read() {
        let cfg = cfg_owned("alice", &[("bob", BucketPermission::Write)]);
        let c = bucket_grant_caps(&cfg, "bob").unwrap();
        assert!(c.read && c.write && !c.admin);
    }

    #[test]
    fn writeonly_grant_has_no_read() {
        let cfg = cfg_owned("alice", &[("bob", BucketPermission::WriteOnly)]);
        let c = bucket_grant_caps(&cfg, "bob").unwrap();
        assert!(!c.read && c.write && !c.admin);
    }

    #[test]
    fn non_grantee_has_no_relationship() {
        let cfg = cfg_owned("alice", &[("bob", BucketPermission::Write)]);
        assert_eq!(bucket_grant_caps(&cfg, "carol"), None);
    }

    #[test]
    fn readonly_role_caps_out_write() {
        // Owner-level bucket caps, but a ReadOnly role ceiling removes write/admin.
        let bc = Caps::FULL;
        let eff = role_caps(Role::ReadOnly).intersect(bc);
        assert!(eff.read && !eff.write && !eff.admin);
    }

    #[test]
    fn writeonly_role_caps_out_read() {
        let bc = Caps::FULL;
        let eff = role_caps(Role::WriteOnly).intersect(bc);
        assert!(!eff.read && eff.write && !eff.admin);
    }

    #[test]
    fn disabled_role_has_nothing() {
        assert_eq!(role_caps(Role::Disabled), Caps::NONE);
        assert!(!role_is_global(Role::Disabled));
    }

    #[test]
    fn auditor_is_global_read_only() {
        assert!(role_is_global(Role::Auditor));
        let c = role_caps(Role::Auditor);
        assert!(c.read && !c.write && !c.admin);
    }

    #[test]
    fn writeonly_role_with_read_grant_still_cannot_read() {
        // Role ceiling dominates: even a read grant can't restore read for a
        // WriteOnly account.
        let eff = role_caps(Role::WriteOnly).intersect(grant_caps(BucketPermission::Read));
        assert!(!eff.read && !eff.write);
    }

    #[test]
    fn role_permits_rejects_a_persona_role_exceeding_the_account_ceiling() {
        // A ReadOnly account may not mint an Admin (or User, which has full
        // caps) persona - the persona would grant write/admin the account
        // itself doesn't have.
        assert!(!role_permits(Role::Admin, Role::ReadOnly));
        assert!(!role_permits(Role::User, Role::ReadOnly));
        // Same-or-narrower is fine.
        assert!(role_permits(Role::ReadOnly, Role::ReadOnly));
        assert!(role_permits(Role::User, Role::Admin));
        // WriteOnly and ReadOnly are incomparable (disjoint caps) - neither
        // permits the other.
        assert!(!role_permits(Role::WriteOnly, Role::ReadOnly));
        assert!(!role_permits(Role::ReadOnly, Role::WriteOnly));
        // Disabled permits nothing but is itself permitted by anything.
        assert!(role_permits(Role::Disabled, Role::ReadOnly));
    }

    #[test]
    fn role_permits_rejects_global_role_escalation_from_a_non_global_ceiling() {
        // Regression test: `role_caps` gives `Admin`/`User` (and
        // `Auditor`/`ReadOnly`) identical capability sets, so the cap-triple
        // comparison alone cannot stop a plain `user` account from minting
        // an `admin` persona and logging in as a global administrator.
        assert!(
            !role_permits(Role::Admin, Role::User),
            "a User-ceiling account must not be able to mint an Admin persona"
        );
        assert!(
            !role_permits(Role::Auditor, Role::User),
            "a User-ceiling account must not be able to mint an Auditor persona"
        );
        assert!(
            !role_permits(Role::Auditor, Role::ReadOnly),
            "a ReadOnly-ceiling account must not gain Auditor's global visibility"
        );
        // A global ceiling may still mint global personas.
        assert!(role_permits(Role::Admin, Role::Admin));
        assert!(role_permits(Role::Auditor, Role::Admin));
        // Sanity: role_caps really does conflate these pairs, which is
        // exactly why the cap check alone is insufficient.
        assert_eq!(role_caps(Role::Admin), role_caps(Role::User));
        assert_eq!(role_caps(Role::Auditor), role_caps(Role::ReadOnly));
    }
}
