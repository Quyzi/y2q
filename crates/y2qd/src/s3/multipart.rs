//! Multipart upload: `CreateMultipartUpload`, `UploadPart`, `ListParts`,
//! `ListMultipartUploads`, `CompleteMultipartUpload`, `AbortMultipartUpload`.
//!
//! Parts are stored as ordinary encrypted objects at
//! `.y2q-mpu/<upload_id>/<part_number:05>` inside the target bucket, so they
//! ride the bucket's own key epoch and quota. `CompleteMultipartUpload`
//! decrypts each part with [`cipher::plaintext_stream`] and re-encrypts the
//! concatenated plaintext into the final object — peak memory is one
//! envelope chunk, not one part, and the session leash is re-checked before
//! every part, since a 10 000-part assembly can easily outlive a session.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, web};
use bytes::Bytes;
use futures_util::StreamExt;
use y2q_core::{
    AnyStorage, BucketConfig, BucketPermission, Listing, PutOptions, Storage, SyncLevel,
};

use crate::auth::session::SessionInfo;
use crate::authz::authorize_bucket;
use crate::bucket_keys;
use crate::cipher;
use crate::config::LabelLimits;
use crate::error::AppError;
use crate::s3::auth::S3Authenticated;
use crate::s3::body::{self, AppByteStream, ErrorSideband};
use crate::s3::error::S3Error;
use crate::s3::meta;
use crate::s3::object::{etag, reject_multipart_namespace};
use crate::s3::routes::SubResource;
use crate::s3::state::{MultipartUpload, S3State};
use crate::s3::xml::{self, XmlError};

fn xml_error_to_s3(e: XmlError) -> S3Error {
    match e {
        XmlError::TooLarge => S3Error::malformed_xml("request body too large"),
        XmlError::Unterminated(tag) => {
            S3Error::malformed_xml(format!("malformed XML: unterminated <{tag}>"))
        }
    }
}

fn part_key(upload_id: &str, part_number: u16) -> String {
    format!(".y2q-mpu/{upload_id}/{part_number:05}")
}

/// Ownership check shared by every per-upload endpoint: the upload must
/// exist and belong to *this exact session* — a different session (even the
/// same user) cannot contribute parts, list, complete, or abort it. Unknown
/// and foreign-owned ids return the identical error so upload ids are not
/// enumerable.
fn owned_upload(
    s3_state: &S3State,
    upload_id: &str,
    bucket: &str,
    key: &str,
    auth: &S3Authenticated,
) -> Result<Arc<MultipartUpload>, S3Error> {
    let upload = s3_state
        .uploads
        .get(upload_id)
        .ok_or_else(S3Error::no_such_upload)?;
    if upload.token_hash != auth.auth.token_hash || upload.bucket != bucket || upload.key != key {
        return Err(S3Error::no_such_upload());
    }
    Ok(upload)
}

/// `POST /{bucket}/{key}?uploads` — `CreateMultipartUpload`.
pub async fn create(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    storage: web::Data<Arc<AnyStorage>>,
    limits: web::Data<LabelLimits>,
    s3_state: web::Data<S3State>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let (bucket, key) = path.into_inner();
    reject_multipart_namespace(&key)?;
    authorize_bucket(&auth.auth, &storage, &bucket, BucketPermission::Write).await?;

    let labels = meta::labels_from_request(&req, limits.get_ref())?;
    let upload = MultipartUpload {
        upload_id: String::new(), // overwritten by `MultipartRegistry::create`
        bucket: bucket.clone(),
        key: key.clone(),
        token_hash: auth.auth.token_hash,
        username: auth.auth.username.clone(),
        created_at: SystemTime::now(),
        labels,
        parts: Mutex::new(BTreeMap::new()),
    };
    let created = s3_state.uploads.create(upload);

    let mut body = String::new();
    xml::header(&mut body);
    body.push_str(
        r#"<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    xml::tag(&mut body, "Bucket", &bucket);
    xml::tag(&mut body, "Key", &key);
    xml::tag(&mut body, "UploadId", &created.upload_id);
    body.push_str("</InitiateMultipartUploadResult>");
    Ok(HttpResponse::Ok()
        .content_type("application/xml")
        .body(body))
}

/// `PUT /{bucket}/{key}?partNumber=N&uploadId=X` — `UploadPart`. Reuses the
/// same `PutObject` pipeline (`resolve_write_key`, leash, encryption) for
/// the part object.
pub async fn upload_part(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    payload: web::Payload,
    storage: web::Data<Arc<AnyStorage>>,
    encryption: web::Data<crate::config::EncryptionParams>,
    s3_state: web::Data<S3State>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let (bucket, key) = path.into_inner();
    let sub = SubResource::parse(req.query_string());
    let upload_id = sub
        .get("uploadId")
        .ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?
        .to_owned();
    let part_number: u16 = sub
        .get("partNumber")
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|&n| (1..=10_000).contains(&n))
        .ok_or_else(|| S3Error::invalid_argument("partNumber must be between 1 and 10000"))?
        as u16;

    let upload = owned_upload(&s3_state, &upload_id, &bucket, &key, &auth)?;
    authorize_bucket(&auth.auth, &storage, &bucket, BucketPermission::Write).await?;

    let max_part_bytes = s3_state.config.max_part_bytes;
    if let Some(len) = req
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        && len > max_part_bytes
    {
        return Err(S3Error::new(
            "EntityTooLarge",
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("part exceeds the configured max_part_bytes ({max_part_bytes})"),
        ));
    }

    let cfg = storage.get_bucket_config(&bucket).await?;
    let (epoch, pk) = bucket_keys::resolve_write_key(&cfg, &bucket)?;
    let stored_key = part_key(&upload_id, part_number);
    let (guard, sink, write_offset) = storage.begin_streaming_put(&bucket, &stored_key).await?;

    let sideband = ErrorSideband::new();
    let headers = req.headers().clone();
    let stream = body::upload_stream(
        payload,
        auth,
        &headers,
        max_part_bytes,
        sideband.clone(),
        bucket.clone(),
        stored_key.clone(),
    )?;

    let (sink, plaintext_metrics, cipher_metadata) = match cipher::stream_encrypt_for_put(
        &pk,
        epoch,
        stream,
        sink,
        &bucket,
        &stored_key,
        write_offset,
        encryption.chunk_size_bytes,
        Some(max_part_bytes),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return Err(sideband.take().unwrap_or_else(|| S3Error::from(e))),
    };

    let part_size = plaintext_metrics.size;
    guard
        .commit(
            sink,
            PutOptions::default(),
            plaintext_metrics,
            cipher_metadata,
        )
        .await?;

    let md = storage.describe(&bucket, &stored_key).await?;
    let part_etag = etag(&md);
    upload
        .parts
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(part_number, (part_size, part_etag.clone()));

    Ok(HttpResponse::Ok()
        .insert_header(("ETag", part_etag))
        .finish())
}

/// `GET /{bucket}/{key}?uploadId=X` — `ListParts`.
pub async fn list_parts(
    bucket: &str,
    key: &str,
    sub: &SubResource,
    storage: &AnyStorage,
    s3_state: &S3State,
    auth: &S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let upload_id = sub
        .get("uploadId")
        .ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?;
    let upload = owned_upload(s3_state, upload_id, bucket, key, auth)?;
    authorize_bucket(&auth.auth, storage, bucket, BucketPermission::Read).await?;

    let parts = upload
        .parts
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let mut body = String::new();
    xml::header(&mut body);
    body.push_str(r#"<ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#);
    xml::tag(&mut body, "Bucket", bucket);
    xml::tag(&mut body, "Key", key);
    xml::tag(&mut body, "UploadId", upload_id);
    for (num, (size, part_etag)) in &parts {
        body.push_str("<Part>");
        xml::tag_num(&mut body, "PartNumber", *num);
        xml::tag(&mut body, "ETag", part_etag);
        xml::tag_num(&mut body, "Size", *size);
        body.push_str("</Part>");
    }
    body.push_str("</ListPartsResult>");
    Ok(HttpResponse::Ok()
        .content_type("application/xml")
        .body(body))
}

/// `GET /{bucket}?uploads` — `ListMultipartUploads`. Only uploads whose
/// `token_hash` matches the caller's session are listed, so the registry
/// cannot be used to observe other sessions' in-flight uploads.
pub async fn list_uploads(
    bucket: &str,
    storage: &AnyStorage,
    s3_state: &S3State,
    auth: &S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    authorize_bucket(&auth.auth, storage, bucket, BucketPermission::Read).await?;
    let uploads: Vec<_> = s3_state
        .uploads
        .list_for_bucket(bucket)
        .into_iter()
        .filter(|u| u.token_hash == auth.auth.token_hash)
        .collect();

    let mut body = String::new();
    xml::header(&mut body);
    body.push_str(
        r#"<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    xml::tag(&mut body, "Bucket", bucket);
    xml::tag(&mut body, "IsTruncated", "false");
    for u in &uploads {
        body.push_str("<Upload>");
        xml::tag(&mut body, "Key", &u.key);
        xml::tag(&mut body, "UploadId", &u.upload_id);
        xml::tag(
            &mut body,
            "Initiated",
            &crate::s3::httpdate::iso8601_from(u.created_at),
        );
        body.push_str("</Upload>");
    }
    body.push_str("</ListMultipartUploadsResult>");
    Ok(HttpResponse::Ok()
        .content_type("application/xml")
        .body(body))
}

/// State for the part-by-part decrypt/re-encrypt assembly stream driving
/// `complete`. Re-checks the session leash before starting each part.
struct AssemblyState {
    storage: Arc<AnyStorage>,
    bucket: String,
    upload_id: String,
    cfg: BucketConfig,
    session: Arc<SessionInfo>,
    leash: crate::s3::auth::SessionLeash,
    remaining: std::collections::VecDeque<u16>,
    current: Option<AppByteStream>,
    sideband: ErrorSideband,
}

fn assembly_abort(bucket: &str) -> AppError {
    AppError(y2q_core::Error::Forbidden {
        bucket: bucket.to_owned(),
    })
}

async fn advance_assembly(
    mut state: AssemblyState,
) -> Result<Option<(Bytes, AssemblyState)>, AppError> {
    loop {
        if let Some(cur) = state.current.as_mut() {
            match cur.next().await {
                Some(Ok(chunk)) => return Ok(Some((chunk, state))),
                Some(Err(e)) => return Err(e),
                None => state.current = None,
            }
        }
        let Some(num) = state.remaining.pop_front() else {
            return Ok(None);
        };
        if let Err(e) = state.leash.checkpoint() {
            state.sideband.set(e);
            return Err(assembly_abort(&state.bucket));
        }
        let key = part_key(&state.upload_id, num);
        let md = state.storage.describe(&state.bucket, &key).await?;
        let epoch = md.key_epoch.unwrap_or(0);
        let sk = bucket_keys::resolve_read_key(&state.session, &state.cfg, &state.bucket, epoch)?;
        state.current = Some(if md.size == 0 {
            Box::pin(futures_util::stream::empty())
        } else {
            Box::pin(cipher::plaintext_stream(
                Arc::clone(&state.storage),
                state.bucket.clone(),
                key,
                md.clone(),
                sk,
                0,
                md.size - 1,
            ))
        });
    }
}

/// `POST /{bucket}/{key}?uploadId=X` — `CompleteMultipartUpload`. Validates
/// strictly-ascending part numbers, matching ETags, and the 5 MiB minimum
/// size on every part but the last, then assembles the object by streaming
/// each part's plaintext into a fresh `EncryptSession` — peak memory one
/// envelope chunk, not one part.
#[allow(clippy::too_many_arguments)]
pub async fn complete(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    body: web::Bytes,
    storage: web::Data<Arc<AnyStorage>>,
    encryption: web::Data<crate::config::EncryptionParams>,
    default_sync: web::Data<SyncLevel>,
    s3_state: web::Data<S3State>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let (bucket, key) = path.into_inner();
    let sub = SubResource::parse(req.query_string());
    let upload_id = sub
        .get("uploadId")
        .ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?
        .to_owned();

    let upload = owned_upload(&s3_state, &upload_id, &bucket, &key, &auth)?;
    authorize_bucket(&auth.auth, &storage, &bucket, BucketPermission::Write).await?;

    let xml_body = std::str::from_utf8(&body)
        .map_err(|_| S3Error::malformed_xml("request body is not valid UTF-8"))?;
    let rows =
        xml::nested_elements(xml_body, "Part", &["PartNumber", "ETag"]).map_err(xml_error_to_s3)?;
    if rows.is_empty() {
        return Err(S3Error::invalid_request(
            "CompleteMultipartUpload requires at least one part",
        ));
    }
    let mut requested: Vec<(u16, String)> = Vec::with_capacity(rows.len());
    for row in rows {
        let num: u16 = row
            .first()
            .cloned()
            .flatten()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| S3Error::malformed_xml("missing or invalid PartNumber"))?;
        let part_etag = row
            .get(1)
            .cloned()
            .flatten()
            .ok_or_else(|| S3Error::malformed_xml("missing ETag"))?;
        requested.push((num, part_etag));
    }
    for w in requested.windows(2) {
        if w[1].0 <= w[0].0 {
            return Err(S3Error::invalid_request(
                "part numbers must be strictly ascending",
            ));
        }
    }

    let recorded = upload
        .parts
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let n = requested.len();
    for (i, (num, part_etag)) in requested.iter().enumerate() {
        let Some((size, recorded_etag)) = recorded.get(num) else {
            return Err(S3Error::new(
                "InvalidPart",
                StatusCode::BAD_REQUEST,
                format!("part {num} was not uploaded"),
            ));
        };
        if recorded_etag != part_etag {
            return Err(S3Error::new(
                "InvalidPart",
                StatusCode::BAD_REQUEST,
                format!("part {num} ETag does not match the uploaded part"),
            ));
        }
        if i + 1 < n && *size < 5 * 1024 * 1024 {
            return Err(S3Error::new(
                "EntityTooSmall",
                StatusCode::BAD_REQUEST,
                format!("part {num} is smaller than the 5 MiB minimum for a non-final part"),
            ));
        }
    }

    let cfg = storage.get_bucket_config(&bucket).await?;
    let (epoch, pk) = bucket_keys::resolve_write_key(&cfg, &bucket)?;
    let (guard, sink, write_offset) = storage.begin_streaming_put(&bucket, &key).await?;

    let sideband = ErrorSideband::new();
    let assembly_state = AssemblyState {
        storage: Arc::clone(storage.get_ref()),
        bucket: bucket.clone(),
        upload_id: upload_id.clone(),
        cfg,
        session: Arc::clone(&auth.auth.session),
        leash: auth.leash,
        remaining: requested.iter().map(|(n, _)| *n).collect(),
        current: None,
        sideband: sideband.clone(),
    };
    let assembled: AppByteStream = Box::pin(futures_util::stream::try_unfold(
        assembly_state,
        advance_assembly,
    ));

    let (sink, plaintext_metrics, cipher_metadata) = match cipher::stream_encrypt_for_put(
        &pk,
        epoch,
        assembled,
        sink,
        &bucket,
        &key,
        write_offset,
        encryption.chunk_size_bytes,
        None,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return Err(sideband.take().unwrap_or_else(|| S3Error::from(e))),
    };

    let mut labels = upload.labels.clone();
    labels.insert(("amz-mpu-parts".to_owned(), n.to_string()));
    guard
        .commit(
            sink,
            PutOptions {
                labels,
                sync: *default_sync.get_ref(),
                ..Default::default()
            },
            plaintext_metrics,
            cipher_metadata,
        )
        .await?;

    // Best-effort part cleanup; the upload is already committed regardless
    // of whether this fully succeeds — a leftover part is reclaimed by the
    // background sweeper the next time it runs (the registry entry below is
    // removed either way, so `orphans()` will pick up any survivors).
    for (num, _) in &requested {
        let _ = storage.delete(&bucket, &part_key(&upload_id, *num)).await;
    }
    s3_state.uploads.remove(&upload_id);

    let dest_md = storage.describe(&bucket, &key).await?;
    let mut out = String::new();
    xml::header(&mut out);
    out.push_str(
        r#"<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    xml::tag(&mut out, "Location", &format!("/{bucket}/{key}"));
    xml::tag(&mut out, "Bucket", &bucket);
    xml::tag(&mut out, "Key", &key);
    xml::tag(&mut out, "ETag", &etag(&dest_md));
    out.push_str("</CompleteMultipartUploadResult>");
    Ok(HttpResponse::Ok().content_type("application/xml").body(out))
}

/// `DELETE /{bucket}/{key}?uploadId=X` — `AbortMultipartUpload`.
pub async fn abort(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    storage: web::Data<Arc<AnyStorage>>,
    s3_state: web::Data<S3State>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let (bucket, key) = path.into_inner();
    let sub = SubResource::parse(req.query_string());
    let upload_id = sub
        .get("uploadId")
        .ok_or_else(|| S3Error::invalid_argument("missing uploadId"))?;

    let upload = owned_upload(&s3_state, upload_id, &bucket, &key, &auth)?;
    authorize_bucket(&auth.auth, &storage, &bucket, BucketPermission::Write).await?;

    abort_upload_parts(&storage, &upload).await;
    s3_state.uploads.remove(upload_id);
    Ok(HttpResponse::NoContent().finish())
}

/// Delete every stored part of `upload` and drop it from the registry.
/// Called both by [`abort`] and by the background sweeper for uploads whose
/// owning session has expired — session-free, best effort: logs failures
/// and continues rather than leaving other parts undeleted.
pub async fn abort_upload_parts(storage: &AnyStorage, upload: &MultipartUpload) {
    let numbers: Vec<u16> = upload
        .parts
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .copied()
        .collect();
    for num in numbers {
        let key = part_key(&upload.upload_id, num);
        if let Err(e) = storage.delete(&upload.bucket, &key).await
            && !matches!(e, y2q_core::Error::NotFound { .. })
        {
            tracing::warn!(
                bucket = %upload.bucket,
                upload_id = %upload.upload_id,
                username = %upload.username,
                part = num,
                error = %e,
                "failed to delete orphaned multipart part"
            );
        }
    }
}

/// Sweeper entry point: abort every upload in `registry` whose owning
/// session is no longer live, deleting their parts. Session-free by
/// design — the session is already gone by the time this runs.
pub async fn sweep_orphaned_uploads(
    storage: &AnyStorage,
    registry: &crate::s3::state::MultipartRegistry,
    sessions: &crate::auth::session::SessionStore,
) {
    for upload in registry.orphans(sessions) {
        abort_upload_parts(storage, &upload).await;
        registry.remove(&upload.upload_id);
    }
}
