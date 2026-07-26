//! `GET`/`PUT /api/v1/buckets/{bucket}/acl` — read and replace a bucket's
//! owner and access-control list.
//!
//! Ownership and ACL are deliberately kept out of the generic bucket-config
//! body (`/api/v1/buckets/{bucket}/config`) so that the config endpoint cannot
//! be used to escalate privileges. They are managed only here, behind a bucket
//! `Admin` (owner) or global-admin check. Transferring ownership additionally
//! requires being the current owner or a global admin.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use y2q_core::crypto::CREDENTIAL_SLOTS;
use y2q_core::{AnyStorage, BucketPermission, Listing};

use crate::auth::{AuthState, Authenticated};
use crate::authz::authorize_bucket;
use crate::bucket_keys::{self, GranteeSlots};
use crate::cluster::{self, ClusterRuntime};
use crate::error::{AppError, ErrorBody};

/// Owner + grants view returned by `GET` and accepted by `PUT`.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AclBody {
    /// Bucket owner (full control). `null` only for unclaimed legacy buckets,
    /// which are admin-only until an admin assigns an owner here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Per-user grants. Keys are usernames; values are `"read"`, `"write"`, or
    /// `"admin"`. The owner is never listed (they have implicit full control).
    #[serde(default)]
    #[schema(value_type = std::collections::HashMap<String, String>)]
    pub grants: BTreeMap<String, BucketPermission>,
    /// Retained bucket key epochs, ascending. Read-only: ignored on `PUT`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_epochs: Vec<u32>,
}

/// Read a bucket's owner and ACL. Requires bucket `Admin` (owner) or global admin.
#[utoipa::path(
    get,
    operation_id = "get_bucket_acl",
    path = "/api/v1/buckets/{bucket}/acl",
    params(("bucket" = String, Path, description = "Bucket name")),
    responses(
        (status = 200, description = "Bucket owner and ACL", body = AclBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 403, description = "Caller is not the owner / a global admin", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Bucket not found (or not visible to the caller)", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "buckets",
)]
pub async fn get_acl(
    path: web::Path<String>,
    storage: web::Data<Arc<AnyStorage>>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let bucket = path.into_inner();
    // Global admins and auditors may view any bucket's ACL; otherwise the
    // caller must be the bucket's owner or a bucket-admin grantee.
    if !auth.is_admin_or_auditor() {
        authorize_bucket(&auth, &storage, &bucket, BucketPermission::Admin).await?;
    }
    if !storage
        .bucket_exists(&bucket)
        .await
        .map_err(AppError::from)?
    {
        return Err(not_found(&bucket));
    }
    let cfg = storage
        .get_bucket_config(&bucket)
        .await
        .map_err(AppError::from)?;
    Ok(HttpResponse::Ok().json(AclBody {
        owner: cfg.owner,
        grants: cfg.acl,
        key_epochs: cfg.keys.iter().map(|k| k.epoch).collect(),
    }))
}

/// Replace a bucket's ACL (and optionally transfer ownership). Requires bucket
/// `Admin` (owner) or global admin; assigning a new `owner` additionally
/// requires being the current owner or a global admin.
#[utoipa::path(
    put,
    operation_id = "set_bucket_acl",
    path = "/api/v1/buckets/{bucket}/acl",
    params(("bucket" = String, Path, description = "Bucket name")),
    request_body(content = AclBody, content_type = "application/json"),
    responses(
        (status = 200, description = "Updated owner and ACL", body = AclBody, content_type = "application/json"),
        (status = 400, description = "Unknown grantee, empty username, or redundant owner grant", body = ErrorBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 403, description = "Caller may not manage this ACL or transfer ownership", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Bucket not found (or not visible to the caller)", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "buckets",
)]
pub async fn set_acl(
    path: web::Path<String>,
    body: web::Json<AclBody>,
    storage: web::Data<Arc<AnyStorage>>,
    state: web::Data<AuthState>,
    cluster: Option<web::Data<ClusterRuntime>>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let bucket = path.into_inner();
    authorize_bucket(&auth, &storage, &bucket, BucketPermission::Admin).await?;
    if !storage
        .bucket_exists(&bucket)
        .await
        .map_err(AppError::from)?
    {
        return Err(not_found(&bucket));
    }

    let body = body.into_inner();
    // Read-modify-write the bucket config. Clustered: read the raft
    // *authoritative* in-memory state, not the local filesystem projection
    // — the projector that mirrors raft-committed changes onto disk runs
    // asynchronously, so a local read can lag behind a claim/config change
    // another node just committed. Proposing a full-replace `SetBucketConfig`
    // built from a stale local read would silently roll back whatever
    // fields it hadn't caught up to yet — most dangerously `keys`, wiping
    // out a bucket's just-claimed key material.
    let mut cfg = match cluster.as_ref() {
        Some(rt) => rt.controller.control_state().await.buckets.get(&bucket).cloned().unwrap_or_default(),
        None => storage.get_bucket_config(&bucket).await.map_err(AppError::from)?,
    };

    // Ownership transfer / assignment: only the current owner or a global admin
    // may change the owner (a mere bucket-`Admin` grantee may not).
    if let Some(new_owner) = body.owner {
        let is_current_owner = cfg.owner.as_deref() == Some(auth.username.as_str());
        if !auth.is_admin() && !is_current_owner {
            return Err(AppError(y2q_core::Error::Forbidden {
                bucket: bucket.clone(),
            }));
        }
        ensure_user_exists(&state, &new_owner)?;
        cfg.owner = Some(new_owner);
    }

    // Validate the proposed grants before applying. Grantee existence is NOT
    // checked: a grant to an unknown username is inert (it can never match a
    // real login), and validating it would turn this endpoint into a
    // username-enumeration oracle for any bucket owner. Owner *transfer* is
    // still validated above — but probing it costs the prober their bucket, so
    // it is not a usable enumeration vector.
    for user in body.grants.keys() {
        if user.trim().is_empty() {
            return Err(invalid_acl("grant username must not be empty"));
        }
        if cfg.owner.as_deref() == Some(user.as_str()) {
            return Err(invalid_acl(&format!(
                "user `{user}` is the bucket owner and already has full access"
            )));
        }
    }

    // Grants that imply *read* (Read/Write/Admin, not WriteOnly) additionally
    // carry a cryptographic bucket-key grant on top of the authz-layer ACL
    // entry — writing alone never needs one (WriteOnly grantees stay
    // decoy-only forever), but reading needs the real secret key. Diff the
    // old and new read-implying grantee sets so we only touch slots that
    // actually changed.
    let old_read_grantees = read_implying_grantees(&cfg.acl);
    let new_read_grantees = read_implying_grantees(&body.grants);
    cfg.acl = body.grants;

    if old_read_grantees != new_read_grantees
        && let Some(kv) = bucket_keys::current_key(&cfg).cloned()
    {
        // Sealing a *new* grant requires the bucket wrap key, which only an
        // existing real grantee's own persona can recover — the caller must
        // already hold real crypto access (owner, or a bucket-admin grantee
        // sealed earlier). A global admin with no grant on this bucket
        // cannot conjure one here either: that would make the "global admin"
        // role a de facto escrow key, exactly what strict admin exclusion
        // rules out. Their ACL edit still applies below for write-only
        // grants; a read-implying change from such a caller is rejected
        // outright rather than silently landing as crypto-inert.
        let bwk = bucket_keys::open_bwk(
            &cfg,
            &bucket,
            kv.epoch,
            &auth.username,
            auth.session.persona as usize,
            &auth.session.identity_sk,
        )
        .map_err(|_| {
            AppError(y2q_core::Error::Forbidden {
                bucket: bucket.clone(),
            })
        })?;

        let mut new_kv = kv;
        for user in new_read_grantees.difference(&old_read_grantees) {
            reseal_grantee(&state, &bucket, &mut new_kv, user, &bwk, true)?;
        }
        for user in old_read_grantees.difference(&new_read_grantees) {
            // Revoked: reseal every slot as decoy, and drop this user's live
            // sessions so a token minted under the old grant can't keep
            // reading from an in-memory cache after the grant is gone.
            reseal_grantee(&state, &bucket, &mut new_kv, user, &bwk, false)?;
            state.sessions.revoke_user(user);
        }
        if let Some(slot) = cfg.keys.iter_mut().find(|k| k.epoch == new_kv.epoch) {
            *slot = new_kv;
        }
    } else if old_read_grantees != new_read_grantees {
        // No key material exists yet (bucket registered but never claimed/
        // written to) — nothing to seal a grant against. The ACL-only
        // change still applies; the entries just stay crypto-inert until a
        // write creates key material and a crypto-capable caller re-grants.
        tracing::warn!(
            bucket = %bucket,
            "set_acl: read-implying grant changed on a bucket with no key material yet; ACL updated, no grant sealed"
        );
    }

    // Clustered: replicate owner+ACL through raft so every node enforces one view.
    if let Some(rt) = cluster.as_ref() {
        cluster::cluster_set_bucket_config(rt, &bucket, &cfg).await?;
    } else {
        storage
            .set_bucket_config(&bucket, &cfg)
            .await
            .map_err(AppError::from)?;
    }
    let key_epochs = cfg.keys.iter().map(|k| k.epoch).collect();
    Ok(HttpResponse::Ok().json(AclBody {
        owner: cfg.owner,
        grants: cfg.acl,
        key_epochs,
    }))
}

/// Users whose grant level implies read access (`Read`, `Write`, `Admin`) —
/// the ones that need a real cryptographic bucket-key grant, as opposed to
/// `WriteOnly` which never opens the secret key.
pub(crate) fn read_implying_grantees(acl: &BTreeMap<String, BucketPermission>) -> BTreeSet<String> {
    acl.iter()
        .filter(|(_, perm)| !matches!(perm, BucketPermission::WriteOnly))
        .map(|(user, _)| user.clone())
        .collect()
}

/// Re-seal `user`'s full grant row on `kv`: real BWK to their primary
/// persona (credential slot 0) when `authorized`, decoys to every slot
/// otherwise. Slot 0 is the only slot a third party can grant directly —
/// granting to someone else's *alternate* persona would require knowing it
/// exists, which defeats the point of it being a duress persona (phase 5's
/// persona-to-persona sharing is self-service for exactly this reason).
/// Unknown usernames are silently skipped: the caller already validated
/// grantee existence is deliberately not enforced (see `set_acl`'s comment),
/// so an ACL entry for a nonexistent user simply never gets crypto material.
fn reseal_grantee(
    state: &AuthState,
    bucket: &str,
    kv: &mut y2q_core::BucketKeyVersion,
    user: &str,
    bwk: &[u8; 32],
    authorized: bool,
) -> Result<(), AppError> {
    let Some(rec) = state.user_store.get(user).map_err(|e| {
        AppError(y2q_core::Error::Index {
            message: e.to_string(),
        })
    })?
    else {
        return Ok(());
    };
    let identity_pks_b64: Vec<String> = rec.slots.iter().map(|s| s.identity_pk_b64.clone()).collect();
    let mut slots_authorized = vec![false; CREDENTIAL_SLOTS];
    if authorized {
        slots_authorized[0] = true;
    }
    let slots = GranteeSlots {
        identity_pks_b64,
        authorized: slots_authorized,
    };
    bucket_keys::put_grant_slot(kv, bucket, user, &slots, bwk).map_err(AppError)
}

/// Reject the request if `username` is not a known user.
fn ensure_user_exists(state: &AuthState, username: &str) -> Result<(), AppError> {
    let exists = state
        .user_store
        .get(username)
        .map_err(|e| {
            AppError(y2q_core::Error::Index {
                message: e.to_string(),
            })
        })?
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(invalid_acl(&format!("unknown user `{username}`")))
    }
}

fn invalid_acl(reason: &str) -> AppError {
    AppError(y2q_core::Error::InvalidAcl {
        reason: reason.to_owned(),
    })
}

fn not_found(bucket: &str) -> AppError {
    AppError(y2q_core::Error::NotFound {
        bucket: bucket.to_owned(),
        key: String::new(),
    })
}
