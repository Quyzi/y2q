//! Object-level S3 verbs: `GetObject`, `HeadObject`, `DeleteObject`,
//! `PutObject`, `CopyObject`.

use std::sync::Arc;

use actix_web::http::StatusCode;
use actix_web::http::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_LANGUAGE, CONTENT_TYPE, EXPIRES,
};
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, web};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use futures_util::StreamExt;
use y2q_core::{AnyStorage, BucketPermission, Listing, Metadata, PutOptions, Storage, SyncLevel};

use crate::auth::AuthState;
use crate::authz::{Decision, authorize_bucket, claim_ownership};
use crate::bucket_keys;
use crate::cipher;
use crate::config::LabelLimits;
use crate::s3::auth::S3Authenticated;
use crate::s3::body::{self, ErrorSideband, LeashedDownload};
use crate::s3::error::S3Error;
use crate::s3::httpdate::{http_date, parse_http_date};
use crate::s3::meta;
use crate::s3::routes::SubResource;
use crate::s3::sigv4::percent_decode;
use crate::s3::state::S3State;
use crate::s3::xml;

/// Reserved key prefix for multipart-upload part storage (see
/// `crate::s3::multipart`). No client request may read, write, or delete a
/// key under this prefix directly.
const MULTIPART_PREFIX: &str = ".y2q-mpu/";

/// Compute the S3-shaped ETag for an object: `"<16 lowercase hex>"` (the
/// standard-base64-decoded gxhash64 checksum, hex-encoded) for a
/// single-part object, or `"<16 hex>-<part count>"` for a
/// multipart-assembled one (part count from the `amz-mpu-parts` label
/// written at `CompleteMultipartUpload`). Deliberately not MD5-shaped (32
/// hex chars) so clients treat it as opaque rather than attempt to verify
/// it as a content hash.
pub fn etag(md: &Metadata) -> String {
    let raw = BASE64_STANDARD
        .decode(&md.checksum_gxhash)
        .unwrap_or_default();
    let mut hex = String::with_capacity(raw.len() * 2);
    for b in &raw {
        hex.push_str(&format!("{b:02x}"));
    }
    match find_label(md, "amz-mpu-parts") {
        Some(n) => format!("\"{hex}-{n}\""),
        None => format!("\"{hex}\""),
    }
}

fn find_label<'a>(md: &'a Metadata, name: &str) -> Option<&'a str> {
    md.labels
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Apply the full `amz-*`-labels-plus-system-metadata header set a
/// GET/HEAD response carries. `sub`'s `response-content-type` etc.
/// overrides (used by presigned download links) take precedence over the
/// object's own stored labels.
fn apply_object_headers(builder: &mut HttpResponseBuilder, md: &Metadata, sub: &SubResource) {
    let content_type = sub
        .get("response-content-type")
        .or_else(|| find_label(md, "amz-content-type"))
        .unwrap_or("binary/octet-stream");
    builder.insert_header((CONTENT_TYPE, content_type.to_owned()));

    if let Some(v) = sub
        .get("response-content-encoding")
        .or_else(|| find_label(md, "amz-content-encoding"))
    {
        builder.insert_header((CONTENT_ENCODING, v.to_owned()));
    }
    if let Some(v) = sub
        .get("response-content-disposition")
        .or_else(|| find_label(md, "amz-content-disposition"))
    {
        builder.insert_header((CONTENT_DISPOSITION, v.to_owned()));
    }
    if let Some(v) = sub
        .get("response-content-language")
        .or_else(|| find_label(md, "amz-content-language"))
    {
        builder.insert_header((CONTENT_LANGUAGE, v.to_owned()));
    }
    if let Some(v) = sub
        .get("response-cache-control")
        .or_else(|| find_label(md, "amz-cache-control"))
    {
        builder.insert_header((CACHE_CONTROL, v.to_owned()));
    }
    if let Some(v) = sub
        .get("response-expires")
        .or_else(|| find_label(md, "amz-expires"))
    {
        builder.insert_header((EXPIRES, v.to_owned()));
    }

    for (name, value) in &md.labels {
        if let Some(meta_name) = name.strip_prefix("amz-meta-") {
            builder.append_header((format!("x-amz-meta-{meta_name}"), value.clone()));
        }
    }

    builder.insert_header(("ETag", etag(md)));
    builder.insert_header(("Last-Modified", http_date(md.modified / 1_000_000_000)));
    builder.insert_header(("Accept-Ranges", "bytes"));
    builder.insert_header(("x-amz-server-side-encryption", "AES256"));
}

/// Evaluate `If-Match` / `If-Unmodified-Since` / `If-None-Match` /
/// `If-Modified-Since` in RFC 9110 order. Returns the short-circuit
/// response (412 or 304) when a precondition applies, `None` to proceed.
fn check_conditionals(req: &HttpRequest, md: &Metadata) -> Option<HttpResponse> {
    let current_etag = etag(md);
    let last_modified = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(md.modified);
    let header_str = |name: &str| req.headers().get(name).and_then(|v| v.to_str().ok());

    if let Some(v) = header_str("if-match")
        && v != "*"
        && !v.split(',').any(|t| t.trim() == current_etag)
    {
        return Some(HttpResponse::PreconditionFailed().finish());
    }
    if let Some(v) = header_str("if-unmodified-since")
        && let Some(t) = parse_http_date(v)
        && last_modified > t
    {
        return Some(HttpResponse::PreconditionFailed().finish());
    }
    if let Some(v) = header_str("if-none-match") {
        if v == "*" || v.split(',').any(|t| t.trim() == current_etag) {
            return Some(HttpResponse::NotModified().finish());
        }
    } else if let Some(v) = header_str("if-modified-since")
        && let Some(t) = parse_http_date(v)
        && last_modified <= t
    {
        return Some(HttpResponse::NotModified().finish());
    }
    None
}

/// Parse a `Range: bytes=...` header into an inclusive `[start, end]`
/// plaintext byte range, supporting all three S3-recognized forms:
/// `bytes=N-M`, `bytes=N-` (to end), and `bytes=-M` (last M bytes). Returns
/// `None` for a missing, malformed, empty-object, or otherwise
/// unsatisfiable header — callers fall back to a full-object response
/// rather than reject the request, per RFC 9110's guidance for a malformed
/// `Range`.
fn parse_range(req: &HttpRequest, size: u64) -> Option<(u64, u64)> {
    let raw = req.headers().get("range")?.to_str().ok()?;
    let spec = raw.strip_prefix("bytes=")?;
    let (start_s, end_s) = spec.split_once('-')?;
    if size == 0 {
        return None;
    }
    if start_s.is_empty() {
        let suffix_len: u64 = end_s.parse().ok()?;
        if suffix_len == 0 {
            return None;
        }
        let start = size.saturating_sub(suffix_len);
        return Some((start, size - 1));
    }
    let start: u64 = start_s.parse().ok()?;
    let end = if end_s.is_empty() {
        size - 1
    } else {
        end_s.parse().ok()?
    };
    if start > end || start >= size {
        return None;
    }
    Some((start, end.min(size - 1)))
}

pub(crate) fn reject_multipart_namespace(key: &str) -> Result<(), S3Error> {
    if key.starts_with(MULTIPART_PREFIX) {
        return Err(S3Error::invalid_argument(
            "keys under .y2q-mpu/ are reserved for multipart upload parts",
        ));
    }
    Ok(())
}

/// `GetObject`, `GetObjectTagging` when `?tagging` is present, or
/// `ListParts` when `?uploadId=` is present.
pub async fn get(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    storage: web::Data<Arc<AnyStorage>>,
    s3_state: web::Data<S3State>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let (bucket, key) = path.into_inner();
    reject_multipart_namespace(&key)?;

    let sub = SubResource::parse(req.query_string());
    if sub.has("tagging") {
        return get_tagging(&bucket, &key, &storage, &auth).await;
    }
    if sub.has("uploadId") {
        return crate::s3::multipart::list_parts(&bucket, &key, &sub, &storage, &s3_state, &auth)
            .await;
    }

    authorize_bucket(&auth.auth, &storage, &bucket, BucketPermission::Read).await?;

    let md = storage.describe(&bucket, &key).await?;
    if let Some(resp) = check_conditionals(&req, &md) {
        return Ok(resp);
    }

    let cfg = storage.get_bucket_config(&bucket).await?;
    let epoch = md.key_epoch.unwrap_or(0);
    let bucket_sk = bucket_keys::resolve_read_key(&auth.auth.session, &cfg, &bucket, epoch)?;

    let (status, start, end) = match parse_range(&req, md.size) {
        Some((s, e)) => (StatusCode::PARTIAL_CONTENT, s, e),
        None => (StatusCode::OK, 0, md.size.saturating_sub(1)),
    };

    let storage_arc = Arc::clone(storage.get_ref());
    let content_len = if md.size == 0 { 0 } else { end - start + 1 };
    let plaintext = if md.size == 0 {
        futures_util::stream::empty().boxed_local()
    } else {
        cipher::plaintext_stream(
            storage_arc,
            bucket.clone(),
            key.clone(),
            md.clone(),
            bucket_sk,
            start,
            end,
        )
        .boxed_local()
    };
    let leashed = LeashedDownload::new(plaintext, auth.leash);

    let mut builder = HttpResponse::build(status);
    apply_object_headers(&mut builder, &md, &sub);
    builder.insert_header(("Content-Length", content_len.to_string()));
    if status == StatusCode::PARTIAL_CONTENT {
        builder.insert_header(("Content-Range", format!("bytes {start}-{end}/{}", md.size)));
    }
    Ok(builder.streaming(leashed))
}

/// `HeadObject` — identical header set to `GetObject`, no body. A missing
/// object returns a bare 404 with no XML body, unlike every other verb.
pub async fn head(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    storage: web::Data<Arc<AnyStorage>>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let (bucket, key) = path.into_inner();
    reject_multipart_namespace(&key)?;

    authorize_bucket(&auth.auth, &storage, &bucket, BucketPermission::Read).await?;

    let md = match storage.describe(&bucket, &key).await {
        Ok(md) => md,
        Err(_) => return Ok(HttpResponse::NotFound().finish()),
    };
    if let Some(resp) = check_conditionals(&req, &md) {
        return Ok(resp);
    }
    let sub = SubResource::parse(req.query_string());
    let mut builder = HttpResponse::Ok();
    apply_object_headers(&mut builder, &md, &sub);
    Ok(builder.body(crate::s3::body::SizedEmptyBody(md.size)))
}

/// `DeleteObject`, `DeleteObjectTagging` when `?tagging` is present, or
/// `AbortMultipartUpload` when `?uploadId=` is present. A missing key is
/// not an error either way (S3 semantics; idempotent deletes are
/// load-bearing for `aws s3 rm`). A missing *bucket* still surfaces as
/// `NoSuchBucket`.
pub async fn delete(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    storage: web::Data<Arc<AnyStorage>>,
    limits: web::Data<LabelLimits>,
    s3_state: web::Data<S3State>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let (bucket, key) = path.into_inner();
    reject_multipart_namespace(&key)?;

    let sub = SubResource::parse(req.query_string());
    if sub.has("tagging") {
        return delete_tagging(&bucket, &key, &storage, limits.get_ref(), &auth).await;
    }
    if sub.has("uploadId") {
        return crate::s3::multipart::abort(
            web::Path::from((bucket, key)),
            req,
            storage,
            s3_state,
            auth,
        )
        .await;
    }

    authorize_bucket(&auth.auth, &storage, &bucket, BucketPermission::Write).await?;

    match storage.delete(&bucket, &key).await {
        Ok(_) => {}
        Err(y2q_core::Error::NotFound { key: ref k, .. }) if !k.is_empty() => {}
        Err(e) => return Err(S3Error::from(e)),
    }
    Ok(HttpResponse::NoContent().finish())
}

/// `GET .../key?tagging` — `GetObjectTagging`. Never returns a secret; just
/// the object's non-`amz-*` labels.
async fn get_tagging(
    bucket: &str,
    key: &str,
    storage: &AnyStorage,
    auth: &S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    authorize_bucket(&auth.auth, storage, bucket, BucketPermission::Read).await?;
    let md = storage.describe(bucket, key).await?;
    let tags = meta::tag_set(&md);

    let mut body = String::new();
    xml::header(&mut body);
    body.push_str(r#"<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet>"#);
    for (k, v) in tags {
        body.push_str("<Tag>");
        xml::tag(&mut body, "Key", &k);
        xml::tag(&mut body, "Value", &v);
        body.push_str("</Tag>");
    }
    body.push_str("</TagSet></Tagging>");
    Ok(HttpResponse::Ok()
        .content_type("application/xml")
        .body(body))
}

/// `PUT .../key?tagging` — `PutObjectTagging`. Replaces the object's tag
/// set wholesale without disturbing its `amz-*` system-metadata labels.
async fn put_tagging(
    bucket: &str,
    key: &str,
    body: &[u8],
    storage: &AnyStorage,
    limits: &LabelLimits,
    auth: &S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    authorize_bucket(&auth.auth, storage, bucket, BucketPermission::Write).await?;
    let md = storage.describe(bucket, key).await?;
    let xml_body = std::str::from_utf8(body)
        .map_err(|_| S3Error::malformed_xml("tagging body is not valid UTF-8"))?;
    let rows = xml::nested_elements(xml_body, "Tag", &["Key", "Value"]).map_err(xml_error_to_s3)?;
    let mut tags = Vec::with_capacity(rows.len());
    for row in rows {
        let key_name = row
            .first()
            .cloned()
            .flatten()
            .ok_or_else(|| S3Error::malformed_xml("Tag element missing Key"))?;
        let value = row.get(1).cloned().flatten().unwrap_or_default();
        tags.push((key_name, value));
    }
    let new_labels = meta::replace_tags(&md, tags, limits)?;
    storage.set_labels(bucket, key, new_labels).await?;
    Ok(HttpResponse::Ok().finish())
}

/// `DELETE .../key?tagging` — `DeleteObjectTagging`. Clears every tag,
/// leaving `amz-*` system-metadata labels untouched.
async fn delete_tagging(
    bucket: &str,
    key: &str,
    storage: &AnyStorage,
    limits: &LabelLimits,
    auth: &S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    authorize_bucket(&auth.auth, storage, bucket, BucketPermission::Write).await?;
    let md = storage.describe(bucket, key).await?;
    let new_labels = meta::replace_tags(&md, Vec::new(), limits)?;
    storage.set_labels(bucket, key, new_labels).await?;
    Ok(HttpResponse::NoContent().finish())
}

fn xml_error_to_s3(e: xml::XmlError) -> S3Error {
    match e {
        xml::XmlError::TooLarge => S3Error::malformed_xml("request body too large"),
        xml::XmlError::Unterminated(tag) => {
            S3Error::malformed_xml(format!("malformed XML: unterminated <{tag}>"))
        }
    }
}

/// `POST /{bucket}/{key}` — `CreateMultipartUpload` (`?uploads`) or
/// `CompleteMultipartUpload` (`?uploadId=`). S3 defines no other object
/// POST operation.
#[allow(clippy::too_many_arguments)]
pub async fn post(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    body: web::Bytes,
    storage: web::Data<Arc<AnyStorage>>,
    limits: web::Data<LabelLimits>,
    encryption: web::Data<crate::config::EncryptionParams>,
    default_sync: web::Data<SyncLevel>,
    s3_state: web::Data<S3State>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let sub = SubResource::parse(req.query_string());
    if sub.has("uploads") {
        return crate::s3::multipart::create(path, req, storage, limits, s3_state, auth).await;
    }
    if sub.has("uploadId") {
        return crate::s3::multipart::complete(
            path,
            req,
            body,
            storage,
            encryption,
            default_sync,
            s3_state,
            auth,
        )
        .await;
    }
    Err(S3Error::not_implemented(
        "unsupported object POST sub-resource",
    ))
}

/// `PutObject` (`x-amz-copy-source` absent) or `CopyObject`
/// (`x-amz-copy-source` present) — S3 dispatches both to `PUT`, not a
/// separate verb.
#[allow(clippy::too_many_arguments)]
pub async fn put(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    payload: web::Payload,
    storage: web::Data<Arc<AnyStorage>>,
    auth_state: web::Data<AuthState>,
    limits: web::Data<LabelLimits>,
    default_sync: web::Data<SyncLevel>,
    encryption: web::Data<crate::config::EncryptionParams>,
    s3_state: web::Data<S3State>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let (bucket, key) = path.into_inner();
    reject_multipart_namespace(&key)?;

    let sub = SubResource::parse(req.query_string());
    if sub.has("uploadId") {
        return crate::s3::multipart::upload_part(
            web::Path::from((bucket, key)),
            req,
            payload,
            storage,
            encryption,
            s3_state,
            auth,
        )
        .await;
    }
    if sub.has("tagging") {
        let mut buf = bytes::BytesMut::new();
        let mut payload = payload;
        while let Some(chunk) = payload.next().await {
            let chunk = chunk
                .map_err(|e| S3Error::invalid_argument(format!("failed to read body: {e}")))?;
            buf.extend_from_slice(&chunk);
        }
        return put_tagging(&bucket, &key, &buf, &storage, limits.get_ref(), &auth).await;
    }

    if let Some(copy_source) = req
        .headers()
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    {
        return copy_object(
            bucket,
            key,
            copy_source,
            req,
            storage,
            auth_state,
            limits,
            default_sync,
            encryption,
            auth,
        )
        .await;
    }

    put_object(
        bucket,
        key,
        req,
        payload,
        storage,
        auth_state,
        limits,
        default_sync,
        encryption,
        s3_state,
        auth,
    )
    .await
}

/// `PutObject` proper. Mirrors `handlers::put::handle`'s pipeline —
/// `authorize_bucket` → `claim_ownership` → quota → `resolve_write_key` →
/// `begin_streaming_put` → `stream_encrypt_for_put` → `commit` — with S3
/// header-derived labels and the `aws-chunked`/checksum/leash upload
/// adapter chain in place of the plain REST payload.
#[allow(clippy::too_many_arguments)]
async fn put_object(
    bucket: String,
    key: String,
    req: HttpRequest,
    payload: web::Payload,
    storage: web::Data<Arc<AnyStorage>>,
    auth_state: web::Data<AuthState>,
    limits: web::Data<LabelLimits>,
    default_sync: web::Data<SyncLevel>,
    encryption: web::Data<crate::config::EncryptionParams>,
    s3_state: web::Data<S3State>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let labels = meta::labels_from_request(&req, limits.get_ref())?;
    let sync = *default_sync.get_ref();

    let decision = authorize_bucket(&auth.auth, &storage, &bucket, BucketPermission::Write).await?;
    let cfg = match decision {
        Decision::ClaimOwnership => {
            claim_ownership(
                &storage,
                &auth_state.user_store,
                &bucket,
                &auth.auth.session,
            )
            .await?
            .0
        }
        Decision::Allowed => storage.get_bucket_config(&bucket).await?,
    };

    let mut max_bytes = encryption.max_body_bytes;
    if let Some(limit) = cfg.quota_bytes {
        let incoming = req
            .headers()
            .get("x-amz-decoded-content-length")
            .or_else(|| req.headers().get("content-length"))
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let used = storage.bucket_usage(&bucket).await?;
        if used + incoming > limit {
            return Err(S3Error::new(
                "QuotaExceeded",
                StatusCode::PAYLOAD_TOO_LARGE,
                "The bucket quota would be exceeded by this request.",
            ));
        }
        max_bytes = max_bytes.min(limit.saturating_sub(used));
    }

    let (bucket_epoch, bucket_pk) = bucket_keys::resolve_write_key(&cfg, &bucket)?;
    let (guard, sink, write_offset) = storage.begin_streaming_put(&bucket, &key).await?;

    let sideband = ErrorSideband::new();
    let max_part_bytes = s3_state.config.max_part_bytes;
    let headers = req.headers().clone();
    let stream = body::upload_stream(
        payload,
        auth,
        &headers,
        max_part_bytes,
        sideband.clone(),
        bucket.clone(),
        key.clone(),
    )?;

    let (sink, plaintext_metrics, cipher_metadata) = match cipher::stream_encrypt_for_put(
        &bucket_pk,
        bucket_epoch,
        stream,
        sink,
        &bucket,
        &key,
        write_offset,
        encryption.chunk_size_bytes,
        Some(max_bytes),
    )
    .await
    {
        Ok(v) => v,
        Err(app_err) => return Err(sideband.take().unwrap_or_else(|| S3Error::from(app_err))),
    };

    guard
        .commit(
            sink,
            PutOptions {
                labels,
                sync,
                ..Default::default()
            },
            plaintext_metrics,
            cipher_metadata,
        )
        .await?;

    let md = storage.describe(&bucket, &key).await?;
    Ok(HttpResponse::Ok()
        .insert_header(("ETag", etag(&md)))
        .insert_header(("x-amz-server-side-encryption", "AES256"))
        .finish())
}

/// `CopyObject`. Requires `Read` on the source and `Write` on the
/// destination through two independent `authorize_bucket` calls — a
/// cross-bucket copy needs this persona to hold real grants on both, with
/// no shortcut through the destination's write access alone.
#[allow(clippy::too_many_arguments)]
async fn copy_object(
    dest_bucket: String,
    dest_key: String,
    copy_source: String,
    req: HttpRequest,
    storage: web::Data<Arc<AnyStorage>>,
    auth_state: web::Data<AuthState>,
    limits: web::Data<LabelLimits>,
    default_sync: web::Data<SyncLevel>,
    encryption: web::Data<crate::config::EncryptionParams>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    reject_multipart_namespace(&dest_key)?;

    let trimmed = copy_source.trim_start_matches('/');
    if trimmed.contains('?') {
        return Err(S3Error::invalid_argument(
            "object versioning (?versionId=) is not supported",
        ));
    }
    let decoded = percent_decode(trimmed);
    let (src_bucket, src_key) = decoded
        .split_once('/')
        .ok_or_else(|| S3Error::invalid_argument("malformed x-amz-copy-source"))?;
    let (src_bucket, src_key) = (src_bucket.to_owned(), src_key.to_owned());
    reject_multipart_namespace(&src_key)?;

    let metadata_directive = req
        .headers()
        .get("x-amz-metadata-directive")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("COPY")
        .to_owned();
    if src_bucket == dest_bucket && src_key == dest_key && metadata_directive != "REPLACE" {
        return Err(S3Error::invalid_request(
            "copy source and destination must differ unless x-amz-metadata-directive: REPLACE",
        ));
    }

    authorize_bucket(&auth.auth, &storage, &src_bucket, BucketPermission::Read).await?;
    let src_md = storage.describe(&src_bucket, &src_key).await?;
    let src_cfg = storage.get_bucket_config(&src_bucket).await?;
    let src_epoch = src_md.key_epoch.unwrap_or(0);
    let src_sk =
        bucket_keys::resolve_read_key(&auth.auth.session, &src_cfg, &src_bucket, src_epoch)?;

    let decision =
        authorize_bucket(&auth.auth, &storage, &dest_bucket, BucketPermission::Write).await?;
    let dest_cfg = match decision {
        Decision::ClaimOwnership => {
            claim_ownership(
                &storage,
                &auth_state.user_store,
                &dest_bucket,
                &auth.auth.session,
            )
            .await?
            .0
        }
        Decision::Allowed => storage.get_bucket_config(&dest_bucket).await?,
    };
    let (dest_epoch, dest_pk) = bucket_keys::resolve_write_key(&dest_cfg, &dest_bucket)?;

    let labels = if metadata_directive == "REPLACE" {
        meta::labels_from_request(&req, limits.get_ref())?
    } else {
        src_md.labels.clone()
    };

    let (guard, sink, write_offset) = storage.begin_streaming_put(&dest_bucket, &dest_key).await?;

    let storage_arc = Arc::clone(storage.get_ref());
    let src_stream: crate::s3::body::AppByteStream = if src_md.size == 0 {
        Box::pin(futures_util::stream::empty())
    } else {
        Box::pin(cipher::plaintext_stream(
            storage_arc,
            src_bucket.clone(),
            src_key.clone(),
            src_md.clone(),
            src_sk,
            0,
            src_md.size - 1,
        ))
    };
    let leashed = body::leashed_upload(
        src_stream,
        auth.leash,
        ErrorSideband::new(),
        dest_bucket.clone(),
        dest_key.clone(),
    );

    let (sink, plaintext_metrics, cipher_metadata) = cipher::stream_encrypt_for_put(
        &dest_pk,
        dest_epoch,
        leashed,
        sink,
        &dest_bucket,
        &dest_key,
        write_offset,
        encryption.chunk_size_bytes,
        Some(encryption.max_body_bytes),
    )
    .await?;

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

    let dest_md = storage.describe(&dest_bucket, &dest_key).await?;
    let mut body = String::new();
    xml::header(&mut body);
    body.push_str("<CopyObjectResult>");
    xml::tag(&mut body, "ETag", &etag(&dest_md));
    xml::tag(
        &mut body,
        "LastModified",
        &crate::s3::httpdate::iso8601(dest_md.modified / 1_000_000_000),
    );
    body.push_str("</CopyObjectResult>");
    Ok(HttpResponse::Ok()
        .content_type("application/xml")
        .body(body))
}
