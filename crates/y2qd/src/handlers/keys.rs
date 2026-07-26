//! `POST /api/v1/buckets/{bucket}/rotate-key` and
//! `POST`/`GET /api/v1/buckets/{bucket}/rekey` — bucket key epoch rotation
//! and the background job that migrates existing objects onto the newest
//! epoch and prunes retired ones.
//!
//! Revocation only fully takes effect after all three steps run in order:
//! `set_acl` (drop the ACL entry — kills live sessions, but old epochs the
//! revoked user already held a real grant on are untouched), `rotate-key`
//! (new writes move to an epoch the revoked user never held), then `rekey`
//! (existing objects move to the new epoch and the old one is pruned, so
//! the revoked user's now-decoy-only re-seal on the newest epoch is the
//! *only* copy of their grant that survives — and it's a decoy).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use actix_web::{HttpResponse, web};
use bytes::BytesMut;
use serde::Serialize;
use utoipa::ToSchema;
use y2q_core::{AnyStorage, BucketConfig, BucketPermission, ListOptions, Listing, PutOptions, Storage, SyncLevel};
use zeroize::Zeroizing;

use crate::auth::{AuthState, Authenticated};
use crate::authz::authorize_bucket;
use crate::bucket_keys::{self, MAX_RETAINED_EPOCHS};
use crate::cipher;
use crate::cluster::{self, ClusterRuntime};
use crate::error::{AppError, ErrorBody};

/// State of a bucket's rekey job. Mirrors [`y2q_core::CacheRebuildStatus`],
/// scoped per bucket (unlike the whole-deployment index rebuild, rekey walks
/// one bucket's objects at a time) — an absent entry means `Idle`.
#[derive(Debug, Clone)]
enum RekeyState {
    Running(u8),
    Completed,
    Failed(String),
}

/// Shared registry of in-flight/finished rekey jobs, keyed by bucket name.
/// Registered as `web::Data` alongside the other daemon-lifetime state.
#[derive(Default, Clone)]
pub struct RekeyRegistry {
    inner: Arc<Mutex<BTreeMap<String, RekeyState>>>,
}

impl RekeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self, bucket: &str) -> Option<RekeyState> {
        self.inner.lock().expect("rekey registry poisoned").get(bucket).cloned()
    }

    fn set(&self, bucket: String, state: RekeyState) {
        self.inner.lock().expect("rekey registry poisoned").insert(bucket, state);
    }

    /// Claim the right to start a rekey job for `bucket`. Fails if one is
    /// already running — never silently overlaps two runs against the same
    /// bucket, which could race on which epoch ends up pruned.
    fn try_start(&self, bucket: &str) -> Result<(), AppError> {
        let mut map = self.inner.lock().expect("rekey registry poisoned");
        if matches!(map.get(bucket), Some(RekeyState::Running(_))) {
            return Err(AppError(y2q_core::Error::RekeyAlreadyRunning {
                bucket: bucket.to_owned(),
            }));
        }
        map.insert(bucket.to_owned(), RekeyState::Running(0));
        Ok(())
    }
}

/// Response body for `POST /api/v1/buckets/{bucket}/rotate-key`.
#[derive(Debug, Serialize, ToSchema)]
pub struct RotateKeyResponse {
    /// The newly created epoch. New writes use it immediately.
    pub epoch: u32,
    /// Every retained epoch, ascending, after the rotation.
    pub key_epochs: Vec<u32>,
}

/// Append a fresh bucket key epoch. Requires bucket `Admin` (owner or an
/// admin-level ACL grantee) **and** that the caller currently holds a real
/// cryptographic grant on the newest existing epoch — an ACL entry alone is
/// not enough, since sealing the new epoch's grants requires the bucket wrap
/// key, which only a real grantee's own persona can recover.
///
/// New writes use the new epoch immediately; existing objects keep
/// decrypting under whichever epoch they were written under until a
/// `rekey` migrates them.
#[utoipa::path(
    post,
    operation_id = "rotate_bucket_key",
    path = "/api/v1/buckets/{bucket}/rotate-key",
    params(("bucket" = String, Path, description = "Bucket name")),
    responses(
        (status = 200, description = "New epoch created", body = RotateKeyResponse, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 403, description = "Caller lacks bucket-admin or a real grant on the newest epoch", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Bucket not found (or not visible to the caller)", body = ErrorBody, content_type = "application/json"),
        (status = 409, description = "Bucket already holds the maximum retained epochs; run rekey first", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "buckets",
)]
pub async fn rotate_key(
    path: web::Path<String>,
    storage: web::Data<Arc<AnyStorage>>,
    state: web::Data<AuthState>,
    cluster: Option<web::Data<ClusterRuntime>>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let bucket = path.into_inner();
    authorize_bucket(&auth, &storage, &bucket, BucketPermission::Admin).await?;
    if !storage.bucket_exists(&bucket).await.map_err(AppError::from)? {
        return Err(not_found(&bucket));
    }

    // Clustered: read the raft *authoritative* in-memory state, not the
    // local filesystem projection — same reasoning as `set_acl`.
    let mut cfg = authoritative_config(&storage, cluster.as_ref().map(|d| d.get_ref()), &bucket).await?;

    let newest = bucket_keys::current_key(&cfg).cloned().ok_or_else(|| {
        AppError(y2q_core::Error::InternalError {
            bucket: bucket.clone(),
            key: String::new(),
            operation: "rotate_key".to_owned(),
            message: "bucket has no key material yet".to_owned(),
        })
    })?;
    if cfg.keys.len() >= MAX_RETAINED_EPOCHS {
        return Err(AppError(y2q_core::Error::TooManyBucketKeyEpochs {
            bucket: bucket.clone(),
            count: cfg.keys.len(),
            max: MAX_RETAINED_EPOCHS,
        }));
    }

    // Precondition: the caller must already hold real crypto access on the
    // newest epoch — sealing the new epoch's grants needs the BWK, which
    // only a real grantee's own persona can recover. A global admin with no
    // grant on this bucket cannot conjure one here either (see `set_acl`'s
    // matching comment on the strict-admin-exclusion property).
    bucket_keys::open_bwk(
        &cfg,
        &bucket,
        newest.epoch,
        &auth.username,
        auth.session.persona as usize,
        &auth.session.identity_sk,
    )
    .map_err(|_| AppError(y2q_core::Error::Forbidden { bucket: bucket.clone() }))?;

    let grantees = bucket_keys::current_grantees(&state.user_store, &cfg, &bucket, &auth.username, auth.session.persona)
        .map_err(AppError)?;
    let new_epoch = newest.epoch + 1;
    let (kv, _bwk) = bucket_keys::new_bucket_key_version(new_epoch, &bucket, &grantees).map_err(AppError)?;
    cfg.keys.push(kv);
    let key_epochs: Vec<u32> = cfg.keys.iter().map(|k| k.epoch).collect();

    persist_config(&storage, cluster.as_ref().map(|d| d.get_ref()), &bucket, &cfg).await?;

    Ok(HttpResponse::Ok().json(RotateKeyResponse {
        epoch: new_epoch,
        key_epochs,
    }))
}

/// Response body for `POST /api/v1/buckets/{bucket}/rekey`.
#[derive(Debug, Serialize, ToSchema)]
pub struct RekeyStartResponse {
    /// Always `"running"`.
    pub status: &'static str,
}

/// Start a background job that re-encrypts every object in `bucket` still on
/// an older key epoch onto the newest one, then prunes every epoch below the
/// newest. Same authorization precondition as [`rotate_key`]: bucket `Admin`
/// plus a real grant on the newest epoch. A per-object decrypt/encrypt
/// failure — including one caused by the caller not actually holding a real
/// grant on some *older* epoch an object was written under — aborts the
/// whole run without pruning anything; already-migrated objects stay on
/// their new epoch (idempotent to re-run).
#[utoipa::path(
    post,
    operation_id = "start_bucket_rekey",
    path = "/api/v1/buckets/{bucket}/rekey",
    params(("bucket" = String, Path, description = "Bucket name")),
    responses(
        (status = 202, description = "Rekey started", body = RekeyStartResponse, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 403, description = "Caller lacks bucket-admin or a real grant on the newest epoch", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Bucket not found (or not visible to the caller)", body = ErrorBody, content_type = "application/json"),
        (status = 409, description = "A rekey is already running for this bucket", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "buckets",
)]
pub async fn start_rekey(
    path: web::Path<String>,
    storage: web::Data<Arc<AnyStorage>>,
    cluster: Option<web::Data<ClusterRuntime>>,
    registry: web::Data<RekeyRegistry>,
    auth: Authenticated,
    encryption: web::Data<crate::config::EncryptionParams>,
) -> Result<HttpResponse, AppError> {
    let bucket = path.into_inner();
    authorize_bucket(&auth, &storage, &bucket, BucketPermission::Admin).await?;
    if !storage.bucket_exists(&bucket).await.map_err(AppError::from)? {
        return Err(not_found(&bucket));
    }
    let cfg = authoritative_config(&storage, cluster.as_ref().map(|d| d.get_ref()), &bucket).await?;
    let newest = bucket_keys::current_key(&cfg).cloned().ok_or_else(|| {
        AppError(y2q_core::Error::InternalError {
            bucket: bucket.clone(),
            key: String::new(),
            operation: "rekey".to_owned(),
            message: "bucket has no key material yet".to_owned(),
        })
    })?;
    bucket_keys::open_bwk(
        &cfg,
        &bucket,
        newest.epoch,
        &auth.username,
        auth.session.persona as usize,
        &auth.session.identity_sk,
    )
    .map_err(|_| AppError(y2q_core::Error::Forbidden { bucket: bucket.clone() }))?;

    registry.try_start(&bucket)?;

    // Resolve every retained epoch's bucket secret key up front, using the
    // caller's identity secret key, then drop that identity key immediately
    // — the spawned job only ever touches the (much narrower-blast-radius)
    // bucket epoch keys it resolved here, not the caller's broader identity
    // key, so a session revocation racing the job's completion cannot widen
    // what the job still holds beyond keys for the very epochs it's already
    // committed to migrating away from.
    let mut epoch_sks: BTreeMap<u32, Zeroizing<Vec<u8>>> = BTreeMap::new();
    for kv in &cfg.keys {
        if kv.epoch < newest.epoch {
            let sk = bucket_keys::read_key(
                &cfg,
                &bucket,
                kv.epoch,
                &auth.username,
                auth.session.persona as usize,
                &auth.session.identity_sk,
            )
            .map_err(AppError)?;
            epoch_sks.insert(kv.epoch, sk);
        }
    }

    let storage = Arc::clone(storage.get_ref());
    let cluster: Option<web::Data<ClusterRuntime>> = cluster.clone();
    let registry_bg = registry.get_ref().clone();
    let chunk_size = encryption.chunk_size_bytes;
    let bucket_bg = bucket.clone();

    tokio::spawn(async move {
        let result = run_rekey(
            &storage,
            cluster.as_ref().map(|d| d.get_ref()),
            &bucket_bg,
            &epoch_sks,
            chunk_size,
            &registry_bg,
        )
        .await;
        drop(epoch_sks);
        match result {
            Ok(()) => registry_bg.set(bucket_bg, RekeyState::Completed),
            Err(msg) => {
                tracing::error!(bucket = %bucket_bg, error = %msg, "rekey failed");
                registry_bg.set(bucket_bg, RekeyState::Failed(msg));
            }
        }
    });

    Ok(HttpResponse::Accepted().json(RekeyStartResponse { status: "running" }))
}

/// The rekey job body. Returns `Err(reason)` on the first per-object
/// failure, having already committed any earlier object's re-encryption
/// (those stay on their new epoch — safe to re-run, since already-current
/// objects are skipped by their `key_epoch`). On success, prunes every
/// epoch below the newest and persists the config. Updates `registry`'s
/// `Running(percent)` entry as each object completes.
async fn run_rekey(
    storage: &AnyStorage,
    cluster: Option<&ClusterRuntime>,
    bucket: &str,
    epoch_sks: &BTreeMap<u32, Zeroizing<Vec<u8>>>,
    chunk_size: usize,
    registry: &RekeyRegistry,
) -> Result<(), String> {
    let cfg = authoritative_config(storage, cluster, bucket)
        .await
        .map_err(|e| e.to_string())?;
    let newest = bucket_keys::current_key(&cfg).cloned().ok_or("bucket has no key material")?;
    let new_pk = base64_decode(&newest.public_key_b64).map_err(|_| "malformed bucket public key".to_owned())?;

    let stale = collect_stale_keys(storage, bucket, newest.epoch).await.map_err(|e| e.to_string())?;
    let total = stale.len();

    for (i, (key, old_epoch)) in stale.iter().enumerate() {
        let old_sk = epoch_sks
            .get(old_epoch)
            .ok_or_else(|| format!("no cached key for epoch {old_epoch} (object {key})"))?;

        let obj = storage.get(bucket, key).await.map_err(|e| e.to_string())?;
        let existing = storage.describe(bucket, key).await.map_err(|e| e.to_string())?;
        let padded = cipher::decrypt_after_get(old_sk, bucket, key, BytesMut::from(obj.into_inner().as_ref()))
            .map_err(|e| e.to_string())?;
        // `decrypt_after_get` returns the Padmé-padded plaintext (padding is
        // stripped on GET using `Metadata::size`, not by the decrypt call
        // itself) — trim to the recorded true size before re-encrypting, or
        // the object would gain trailing null padding on every rekey.
        let true_size = existing.size as usize;
        let plaintext = if padded.len() > true_size {
            padded.slice(0..true_size)
        } else {
            padded
        };

        let (guard, sink, write_offset) = storage.begin_streaming_put(bucket, key).await.map_err(|e| e.to_string())?;
        let (sink, plaintext_metrics, cipher_metadata) =
            cipher::encrypt_bytes_for_put(&new_pk, newest.epoch, &plaintext, sink, bucket, key, write_offset, chunk_size)
                .await
                .map_err(|e| e.to_string())?;
        guard
            .commit(
                sink,
                PutOptions {
                    labels: existing.labels,
                    sync: SyncLevel::Durable,
                    ..Default::default()
                },
                plaintext_metrics,
                cipher_metadata,
            )
            .await
            .map_err(|e| e.to_string())?;

        let percent = (((i + 1) * 100) / total.max(1)) as u8;
        registry.set(bucket.to_owned(), RekeyState::Running(percent));
    }

    // Prune every epoch below the newest and persist.
    let mut cfg = authoritative_config(storage, cluster, bucket).await.map_err(|e| e.to_string())?;
    cfg.keys.retain(|k| k.epoch == newest.epoch);
    persist_config(storage, cluster, bucket, &cfg).await.map_err(|e| e.to_string())?;
    Ok(())
}


/// Enumerate every `(key, key_epoch)` pair in `bucket` whose recorded epoch
/// is older than `current_epoch`. Buffers the whole (typically small,
/// shrinking-over-time) stale set in memory up front so [`run_rekey`] can
/// report a real percentage rather than an unbounded running count.
async fn collect_stale_keys(storage: &AnyStorage, bucket: &str, current_epoch: u32) -> Result<Vec<(String, u32)>, y2q_core::Error> {
    let mut out = Vec::new();
    let mut after = None;
    loop {
        let page = storage
            .list_objects(
                bucket,
                ListOptions {
                    prefix: None,
                    after,
                    limit: Some(y2q_core::MAX_LIST_LIMIT),
                },
            )
            .await?;
        for item in &page.items {
            let epoch = item.key_epoch.unwrap_or(0);
            if epoch < current_epoch {
                out.push((item.key.clone(), epoch));
            }
        }
        match page.next {
            Some(cursor) => after = Some(cursor),
            None => break,
        }
    }
    Ok(out)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD.decode(s)
}

/// Read `bucket`'s config from the authoritative source: raft in-memory
/// state when clustered (the local filesystem projection can lag), the local
/// sidecar otherwise. Same pattern `set_acl` uses.
async fn authoritative_config(storage: &AnyStorage, cluster: Option<&ClusterRuntime>, bucket: &str) -> Result<BucketConfig, AppError> {
    match cluster {
        Some(rt) => Ok(rt.controller.control_state().await.buckets.get(bucket).cloned().unwrap_or_default()),
        None => storage.get_bucket_config(bucket).await.map_err(AppError::from),
    }
}

/// Persist `cfg` for `bucket` through the same path `set_acl` uses: raft
/// `SetBucketConfig` when clustered, the local sidecar otherwise.
async fn persist_config(storage: &AnyStorage, cluster: Option<&ClusterRuntime>, bucket: &str, cfg: &BucketConfig) -> Result<(), AppError> {
    match cluster {
        Some(rt) => cluster::cluster_set_bucket_config(rt, bucket, cfg).await,
        None => storage.set_bucket_config(bucket, cfg).await.map_err(AppError::from),
    }
}

/// Response body for `GET /api/v1/buckets/{bucket}/rekey`.
#[derive(Debug, Serialize, ToSchema)]
pub struct RekeyStatusResponse {
    /// `idle`, `running`, `completed`, or `failed`.
    pub state: &'static str,
    /// Percent complete (0..=100). Only present while running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
    /// Short human description of the failure. Only present after a failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Query the current state of `bucket`'s rekey job.
#[utoipa::path(
    get,
    operation_id = "bucket_rekey_status",
    path = "/api/v1/buckets/{bucket}/rekey",
    params(("bucket" = String, Path, description = "Bucket name")),
    responses(
        (status = 200, description = "Current rekey state", body = RekeyStatusResponse, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 403, description = "Caller lacks bucket-admin", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Bucket not found (or not visible to the caller)", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "buckets",
)]
pub async fn rekey_status(
    path: web::Path<String>,
    storage: web::Data<Arc<AnyStorage>>,
    registry: web::Data<RekeyRegistry>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let bucket = path.into_inner();
    authorize_bucket(&auth, &storage, &bucket, BucketPermission::Admin).await?;
    let state = registry.get(&bucket);
    Ok(HttpResponse::Ok().json(match state {
        None => RekeyStatusResponse {
            state: "idle",
            percent: None,
            reason: None,
        },
        Some(RekeyState::Running(p)) => RekeyStatusResponse {
            state: "running",
            percent: Some(p),
            reason: None,
        },
        Some(RekeyState::Completed) => RekeyStatusResponse {
            state: "completed",
            percent: None,
            reason: None,
        },
        Some(RekeyState::Failed(r)) => RekeyStatusResponse {
            state: "failed",
            percent: None,
            reason: Some(r),
        },
    }))
}

fn not_found(bucket: &str) -> AppError {
    AppError(y2q_core::Error::NotFound {
        bucket: bucket.to_owned(),
        key: String::new(),
    })
}
