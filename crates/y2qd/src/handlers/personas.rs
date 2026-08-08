//! `POST`/`DELETE /api/v1/personas/{slot}/grant` — share (or revoke) the
//! caller's own current bucket access with one of their own personas.
//!
//! Self-service only: a grantor may only extend access to *their own*
//! alternate persona, never a third party's — granting someone else's
//! alternate persona directly would require knowing it exists, which
//! defeats the point of the duress-deniability property (see
//! `crate::bucket_keys`'s module docs and phase 5's plan notes).
//!
//! For each named bucket and each retained key epoch, the caller's own BWK
//! is recovered fresh from their *own* currently-authenticated persona's
//! sealed grant (never persisted — see [`bucket_keys::open_bwk`]) and used
//! to re-seal that same grant row so both the caller's own persona and the
//! target slot hold real access. A bucket, or an epoch within it, where the
//! caller holds no real grant at all is silently skipped rather than
//! errored: there's nothing of the caller's own to share there.

use std::sync::Arc;

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use utoipa::ToSchema;
use y2q_core::crypto::CREDENTIAL_SLOTS;
use y2q_core::{AnyStorage, BucketPermission, Error as CoreError, Listing};

use crate::auth::{AuthState, Authenticated};
use crate::authz::authorize_bucket;
use crate::bucket_keys::{self, GranteeSlots};
use crate::error::AppError;

/// `POST`/`DELETE /api/v1/personas/{slot}/grant` request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PersonaGrantBody {
    /// Bucket names to share (or unshare) with `slot`. A bucket the caller
    /// doesn't currently hold real access to is silently skipped, not
    /// errored.
    pub buckets: Vec<String>,
}

fn validate_slot(slot: usize) -> Result<(), AppError> {
    if (0..CREDENTIAL_SLOTS).contains(&slot) {
        Ok(())
    } else {
        Err(AppError(CoreError::InvalidPersonaRequest {
            reason: format!("invalid persona slot {slot}: must be 0..{CREDENTIAL_SLOTS}"),
        }))
    }
}

/// `POST /api/v1/personas/{slot}/grant` — share every bucket in the body
/// that the caller's *current* persona really holds with `slot`, one of
/// the caller's own other personas. `slot` may be any credential slot
/// except the caller's own currently-authenticated one.
#[utoipa::path(
    post,
    path = "/api/v1/personas/{slot}/grant",
    params(("slot" = u8, Path, description = "Credential slot, 0..CREDENTIAL_SLOTS, excluding the caller's own active slot, to grant")),
    request_body = PersonaGrantBody,
    responses(
        (status = 204, description = "Buckets shared with the target persona"),
        (status = 400, description = "Slot out of range"),
        (status = 401, description = "Token missing/invalid"),
    ),
    security(("bearer" = [])),
    tag = "personas",
)]
#[tracing::instrument(skip(storage, state, auth, body), fields(username = %auth.username))]
pub async fn grant_persona(
    path: web::Path<u8>,
    body: web::Json<PersonaGrantBody>,
    storage: web::Data<Arc<AnyStorage>>,
    state: web::Data<AuthState>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    share_or_revoke(
        path.into_inner(),
        body.into_inner(),
        storage.get_ref(),
        state.get_ref(),
        &auth,
        true,
    )
    .await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `DELETE /api/v1/personas/{slot}/grant` — re-seal every bucket in the body
/// so `slot` no longer holds real access, leaving the grant array the same
/// shape and size. The caller's own persona keeps its access.
#[utoipa::path(
    delete,
    path = "/api/v1/personas/{slot}/grant",
    params(("slot" = u8, Path, description = "Credential slot, 0..CREDENTIAL_SLOTS, excluding the caller's own active slot, to revoke")),
    request_body = PersonaGrantBody,
    responses(
        (status = 204, description = "Buckets unshared from the target persona"),
        (status = 400, description = "Slot out of range"),
        (status = 401, description = "Token missing/invalid"),
    ),
    security(("bearer" = [])),
    tag = "personas",
)]
#[tracing::instrument(skip(storage, state, auth, body), fields(username = %auth.username))]
pub async fn revoke_persona_grant(
    path: web::Path<u8>,
    body: web::Json<PersonaGrantBody>,
    storage: web::Data<Arc<AnyStorage>>,
    state: web::Data<AuthState>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    share_or_revoke(
        path.into_inner(),
        body.into_inner(),
        storage.get_ref(),
        state.get_ref(),
        &auth,
        false,
    )
    .await?;
    Ok(HttpResponse::NoContent().finish())
}

async fn share_or_revoke(
    slot: u8,
    body: PersonaGrantBody,
    storage: &AnyStorage,
    state: &AuthState,
    auth: &Authenticated,
    authorize_target: bool,
) -> Result<(), AppError> {
    let target_slot = slot as usize;
    validate_slot(target_slot)?;
    if target_slot == auth.session.persona as usize {
        return Err(AppError(CoreError::InvalidPersonaRequest {
            reason: "cannot target the caller's own currently-authenticated slot".to_owned(),
        }));
    }

    let rec = state
        .user_store
        .get(&auth.username)
        .map_err(|e| {
            AppError(CoreError::Index {
                message: e.to_string(),
            })
        })?
        .ok_or_else(|| {
            AppError(CoreError::InvalidPersonaRequest {
                reason: "caller's own record is missing".to_owned(),
            })
        })?;
    let identity_pks_b64: Vec<String> = rec
        .slots
        .iter()
        .map(|s| s.identity_pk_b64.clone())
        .collect();

    for bucket in &body.buckets {
        let cfg = if storage
            .bucket_exists(bucket)
            .await
            .map_err(AppError::from)?
        {
            Some(
                storage
                    .get_bucket_config(bucket)
                    .await
                    .map_err(AppError::from)?,
            )
        } else {
            None
        };
        let Some(mut cfg) = cfg else { continue }; // no such bucket: nothing to share
        if cfg.keys.is_empty() {
            continue; // registered but never claimed/written to: nothing to share
        }

        let mut changed = false;
        for i in 0..cfg.keys.len() {
            let epoch = cfg.keys[i].epoch;
            // The caller must still hold an active, authorized relationship
            // to this bucket — not merely a stale cryptographic grant on an
            // old epoch left over from before an ACL revocation. Skip
            // (rather than error) so a partial bucket list still processes
            // every bucket the caller genuinely can act on.
            if authorize_bucket(auth, storage, bucket, BucketPermission::Read)
                .await
                .is_err()
            {
                continue;
            }
            // Recover the caller's own BWK at this epoch, verifying it's a
            // REAL grant and not a decoy — `open_bwk` alone cannot tell the
            // two apart (see its doc comment), and a decoy/duress persona
            // passing this gate could otherwise overwrite the real
            // grantee's row with garbage. If the caller has no real grant
            // here, there's nothing of theirs to share/revoke at this
            // epoch — skip it rather than error.
            let Ok(bwk) = bucket_keys::open_verified_bwk(
                &cfg,
                bucket,
                epoch,
                &auth.username,
                auth.session.persona as usize,
                &auth.session.identity_sk,
            ) else {
                continue;
            };
            let mut authorized = vec![false; CREDENTIAL_SLOTS];
            authorized[auth.session.persona as usize] = true; // never drop the caller's own access
            authorized[target_slot] = authorize_target;
            let slots = GranteeSlots {
                identity_pks_b64: identity_pks_b64.clone(),
                authorized,
            };
            bucket_keys::put_grant_slot(&mut cfg.keys[i], bucket, &auth.username, &slots, &bwk)
                .map_err(AppError)?;
            changed = true;
        }
        if !changed {
            continue;
        }
        storage
            .set_bucket_config(bucket, &cfg)
            .await
            .map_err(AppError::from)?;
    }
    if !authorize_target {
        // Withdrawing access: a session already opened through the target
        // persona holds the plaintext bucket secret key in its per-session
        // cache (see `bucket_keys::resolve_read_key`), which a config
        // change alone does not invalidate. Drop its sessions so a token
        // minted under the old grant can't keep reading from cache.
        state.sessions.revoke_user_persona(&auth.username, slot);
    }
    Ok(())
}
