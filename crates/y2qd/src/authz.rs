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
fn effective_caps(auth: &Authenticated, cfg: &BucketConfig) -> (Caps, bool) {
    let rc = role_caps(auth.role);
    if role_is_global(auth.role) {
        return (rc.intersect(Caps::FULL), true);
    }
    match bucket_grant_caps(cfg, &auth.username) {
        Some(bc) => (rc.intersect(bc), true),
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
///   it — never reveal that such a bucket exists.
/// - **403** when the caller can see the bucket but lacks the verb (because of
///   their role ceiling, their grant level, or both).
pub async fn authorize_bucket(
    auth: &Authenticated,
    storage: &AnyStorage,
    bucket: &str,
    required: BucketPermission,
) -> Result<Decision, AppError> {
    // Authorization disabled → full access.
    if !auth.authz_enforced {
        return Ok(Decision::Allowed);
    }

    let cfg = storage
        .get_bucket_config(bucket)
        .await
        .map_err(AppError::from)?;

    let (eff, visible) = effective_caps(auth, &cfg);
    if eff.allows(required) {
        return Ok(Decision::Allowed);
    }
    if visible {
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

/// Record `owner` as the bucket's owner if it has none yet. Idempotent and
/// race-safe: if another writer claimed the bucket first, the existing owner is
/// left untouched. Called by write handlers after a [`Decision::ClaimOwnership`]
/// PUT/create succeeds.
pub async fn claim_ownership(
    storage: &AnyStorage,
    bucket: &str,
    owner: &str,
) -> Result<(), AppError> {
    let mut cfg = storage
        .get_bucket_config(bucket)
        .await
        .map_err(AppError::from)?;
    if cfg.owner.is_none() {
        cfg.owner = Some(owner.to_owned());
        storage
            .set_bucket_config(bucket, &cfg)
            .await
            .map_err(AppError::from)?;
    }
    Ok(())
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
    let (eff, _) = effective_caps(auth, &cfg);
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
}
