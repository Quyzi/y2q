//! Object-level S3 verbs: `GetObject`, `HeadObject`, `DeleteObject`,
//! `PutObject`, `CopyObject`.

use std::sync::Arc;

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, web};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use futures_util::StreamExt;
use y2q_core::{AnyStorage, BucketPermission, Listing, Metadata, PutOptions, Storage};

use crate::authz::authorize_bucket;

use crate::bucket_keys;
use crate::cipher;
use crate::config::LabelLimits;
use crate::s3::auth::S3Authenticated;
use crate::s3::body::{self, ErrorSideband, LeashedDownload};
use crate::s3::ctx::WriteCtx;
use crate::s3::error::S3Error;
use crate::s3::httpdate::parse_http_date;
use crate::s3::meta;
use crate::s3::routes::SubResource;
use crate::s3::sigv4::percent_decode;
use crate::s3::state::S3State;
use crate::s3::xml;

/// Compute the S3-shaped ETag for an object: `"<16 lowercase hex>"` (the
/// standard-base64-decoded gxhash64 checksum, hex-encoded) for a
/// single-part object, or `"<16 hex>-<part count>"` for a
/// multipart-assembled one (part count from the `amz-mpu-parts` label
/// written at `CompleteMultipartUpload`). Deliberately not MD5-shaped (32
/// hex chars) so clients treat it as opaque rather than attempt to verify
/// it as a content hash.
pub fn etag(md: &Metadata) -> String {
    match meta::find_label(md, meta::MPU_PARTS_LABEL) {
        Some(n) => {
            let raw = BASE64_STANDARD
                .decode(&md.checksum_gxhash)
                .unwrap_or_default();
            format!("\"{}-{n}\"", crate::s3::sigv4::hex_encode(&raw))
        }
        None => etag_from_checksum_b64(&md.checksum_gxhash),
    }
}

/// Build a single-part object's ETag directly from its standard-base64
/// gxhash64 checksum, without needing the stored [`Metadata`] at all — lets
/// `put_object` answer from the write it just performed
/// (`PlaintextMetrics::checksum_gxhash_b64`) instead of a redundant
/// `describe` round-trip. Never multipart-shaped: a freshly written
/// single-part object cannot carry [`meta::MPU_PARTS_LABEL`].
pub(crate) fn etag_from_checksum_b64(b64: &str) -> String {
    let raw = BASE64_STANDARD.decode(b64).unwrap_or_default();
    format!("\"{}\"", crate::s3::sigv4::hex_encode(&raw))
}

/// Evaluate `If-Match` / `If-Unmodified-Since` / `If-None-Match` /
/// `If-Modified-Since` in RFC 9110 order. Returns the short-circuit
/// response (412 or 304) when a precondition applies, `None` to proceed.
fn check_conditionals(req: &HttpRequest, md: &Metadata) -> Option<HttpResponse> {
    let current_etag = etag(md);
    let last_modified = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(md.modified);
    let header_str = |name: &str| req.headers().get(name).and_then(|v| v.to_str().ok());

    if let Some(v) = header_str("if-match") {
        if v != "*" && !v.split(',').any(|t| t.trim() == current_etag) {
            return Some(HttpResponse::PreconditionFailed().finish());
        }
    } else if let Some(v) = header_str("if-unmodified-since")
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
    crate::s3::multipart::reject_reserved_key(&key)?;

    let sub = SubResource::parse(req.query_string());
    if sub.has("tagging") {
        return get_tagging(&bucket, &key, &storage, &auth).await;
    }
    if sub.has("uploadId") {
        return crate::s3::multipart::list_parts(&bucket, &key, &sub, &storage, &s3_state, &auth)
            .await;
    }
    crate::s3::bucket::reject_unimplemented_subresources(&sub)?;
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
    meta::apply_object_headers(&mut builder, &md, &sub);
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
    crate::s3::multipart::reject_reserved_key(&key)?;

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
    meta::apply_object_headers(&mut builder, &md, &sub);
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
    crate::s3::multipart::reject_reserved_key(&key)?;

    let sub = SubResource::parse(req.query_string());
    if sub.has("tagging") {
        return delete_tagging(&bucket, &key, &storage, limits.get_ref(), &auth).await;
    }
    if sub.has("uploadId") {
        return crate::s3::multipart::abort(&bucket, &key, &sub, storage, s3_state, auth).await;
    }
    crate::s3::bucket::reject_unimplemented_subresources(&sub)?;
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
    let rows = xml::nested_elements(xml_body, "Tag", &["Key", "Value"])?;
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

/// `POST /{bucket}/{key}` — `CreateMultipartUpload` (`?uploads`) or
/// `CompleteMultipartUpload` (`?uploadId=`). S3 defines no other object
/// POST operation.
pub async fn post(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    body: web::Bytes,
    ctx: WriteCtx,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let sub = SubResource::parse(req.query_string());
    if sub.has("uploads") {
        return crate::s3::multipart::create(path, req, ctx.storage, ctx.limits, ctx.s3, auth)
            .await;
    }
    if sub.has("uploadId") {
        return crate::s3::multipart::complete(path, req, body, ctx, auth).await;
    }
    Err(S3Error::not_implemented(
        "unsupported object POST sub-resource",
    ))
}

/// `PutObject` (`x-amz-copy-source` absent) or `CopyObject`
/// (`x-amz-copy-source` present) — S3 dispatches both to `PUT`, not a
/// separate verb.
pub async fn put(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    payload: web::Payload,
    ctx: WriteCtx,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let (bucket, key) = path.into_inner();
    crate::s3::multipart::reject_reserved_key(&key)?;

    let sub = SubResource::parse(req.query_string());
    if sub.has("uploadId") {
        return crate::s3::multipart::upload_part(&bucket, &key, &sub, req, payload, ctx, auth)
            .await;
    }
    if sub.has("tagging") {
        let mut buf = bytes::BytesMut::new();
        let mut payload = payload;
        while let Some(chunk) = payload.next().await {
            let chunk = chunk
                .map_err(|e| S3Error::invalid_argument(format!("failed to read body: {e}")))?;
            buf.extend_from_slice(&chunk);
            if buf.len() > xml::MAX_XML_BYTES {
                return Err(S3Error::entity_too_large(
                    "tagging document exceeds the maximum XML size (1 MiB)",
                ));
            }
        }
        return put_tagging(
            &bucket,
            &key,
            &buf,
            &ctx.storage,
            ctx.limits.get_ref(),
            &auth,
        )
        .await;
    }
    crate::s3::bucket::reject_unimplemented_subresources(&sub)?;

    if let Some(copy_source) = req
        .headers()
        .get("x-amz-copy-source")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    {
        return copy_object(bucket, key, copy_source, req, ctx, auth).await;
    }

    put_object(bucket, key, req, payload, ctx, auth).await
}

/// `PutObject` proper. Mirrors `handlers::put::handle`'s pipeline —
/// `authorize_bucket` → `claim_ownership` → quota → `resolve_write_key` →
/// `begin_streaming_put` → `stream_encrypt_for_put` → `commit` — with S3
/// header-derived labels and the `aws-chunked`/checksum/leash upload
/// adapter chain in place of the plain REST payload.
async fn put_object(
    bucket: String,
    key: String,
    req: HttpRequest,
    payload: web::Payload,
    ctx: WriteCtx,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let labels = meta::labels_from_request(&req, ctx.limits.get_ref())?;
    let sync = *ctx.default_sync.get_ref();

    let decision =
        authorize_bucket(&auth.auth, &ctx.storage, &bucket, BucketPermission::Write).await?;
    let cfg = crate::authz::resolve_bucket_config(
        decision,
        &ctx.storage,
        &ctx.auth_state.user_store,
        &bucket,
        &auth.auth.session,
    )
    .await?;

    let incoming = req
        .headers()
        .get("x-amz-decoded-content-length")
        .or_else(|| req.headers().get("content-length"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let max_bytes = crate::quota::write_budget(
        &ctx.storage,
        &cfg,
        &bucket,
        incoming,
        ctx.encryption.max_body_bytes,
    )
    .await?;

    let (bucket_epoch, bucket_pk) = bucket_keys::resolve_write_key(&cfg, &bucket)?;
    let (guard, sink, write_offset) = ctx.storage.begin_streaming_put(&bucket, &key).await?;

    let sideband = ErrorSideband::new();
    let max_part_bytes = ctx.s3.config.max_part_bytes;
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
        ctx.encryption.chunk_size_bytes,
        Some(max_bytes),
    )
    .await
    {
        Ok(v) => v,
        Err(app_err) => return Err(sideband.take().unwrap_or_else(|| S3Error::from(app_err))),
    };

    let response_etag = etag_from_checksum_b64(&plaintext_metrics.checksum_gxhash_b64);
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

    Ok(HttpResponse::Ok()
        .insert_header(("ETag", response_etag))
        .insert_header(("x-amz-server-side-encryption", "AES256"))
        .finish())
}

/// `CopyObject`. Requires `Read` on the source and `Write` on the
/// destination through two independent `authorize_bucket` calls — a
/// cross-bucket copy needs this persona to hold real grants on both, with
/// no shortcut through the destination's write access alone.
async fn copy_object(
    dest_bucket: String,
    dest_key: String,
    copy_source: String,
    req: HttpRequest,
    ctx: WriteCtx,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    crate::s3::multipart::reject_reserved_key(&dest_key)?;

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
    crate::s3::multipart::reject_reserved_key(&src_key)?;

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

    authorize_bucket(
        &auth.auth,
        &ctx.storage,
        &src_bucket,
        BucketPermission::Read,
    )
    .await?;
    let src_md = ctx.storage.describe(&src_bucket, &src_key).await?;
    let src_cfg = ctx.storage.get_bucket_config(&src_bucket).await?;
    let src_epoch = src_md.key_epoch.unwrap_or(0);
    let src_sk =
        bucket_keys::resolve_read_key(&auth.auth.session, &src_cfg, &src_bucket, src_epoch)?;

    let decision = authorize_bucket(
        &auth.auth,
        &ctx.storage,
        &dest_bucket,
        BucketPermission::Write,
    )
    .await?;
    let dest_cfg = crate::authz::resolve_bucket_config(
        decision,
        &ctx.storage,
        &ctx.auth_state.user_store,
        &dest_bucket,
        &auth.auth.session,
    )
    .await?;
    let max_bytes = crate::quota::write_budget(
        &ctx.storage,
        &dest_cfg,
        &dest_bucket,
        src_md.size,
        ctx.encryption.max_body_bytes,
    )
    .await?;
    let (dest_epoch, dest_pk) = bucket_keys::resolve_write_key(&dest_cfg, &dest_bucket)?;

    let labels = if metadata_directive == "REPLACE" {
        meta::labels_from_request(&req, ctx.limits.get_ref())?
    } else {
        meta::labels_for_copy(&src_md)
    };

    let (guard, sink, write_offset) = ctx
        .storage
        .begin_streaming_put(&dest_bucket, &dest_key)
        .await?;

    let storage_arc = Arc::clone(ctx.storage.get_ref());
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
    let sideband = ErrorSideband::new();
    let leashed = body::leashed_upload(
        src_stream,
        auth.leash,
        sideband.clone(),
        dest_bucket.clone(),
    );

    let (sink, plaintext_metrics, cipher_metadata) = match cipher::stream_encrypt_for_put(
        &dest_pk,
        dest_epoch,
        leashed,
        sink,
        &dest_bucket,
        &dest_key,
        write_offset,
        ctx.encryption.chunk_size_bytes,
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
                sync: *ctx.default_sync.get_ref(),
                ..Default::default()
            },
            plaintext_metrics,
            cipher_metadata,
        )
        .await?;

    let dest_md = ctx.storage.describe(&dest_bucket, &dest_key).await?;
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

#[cfg(test)]
mod tests {
    use actix_web::test::TestRequest;

    use super::*;

    fn md_at(modified_secs: u64) -> Metadata {
        Metadata {
            created: 0,
            modified: modified_secs * 1_000_000_000,
            size: 0,
            checksum_gxhash: String::new(),
            bucket: "b".to_owned(),
            key: "k".to_owned(),
            disk_path: std::path::PathBuf::new(),
            url_path: "b/k".to_owned(),
            labels: Default::default(),
            cipher_size: None,
            cipher_checksum: None,
            kem_alg: None,
            aead_alg: None,
            envelope_version: None,
            version: None,
            committed_at: None,
            key_epoch: None,
        }
    }

    /// Regression proof for RFC 9110 conditional precedence: a matching
    /// `If-Match` must make the request proceed even when `If-Unmodified-
    /// Since` is stale — before the fix, the two were evaluated
    /// independently and this combination produced a spurious 412.
    #[test]
    fn matching_if_match_suppresses_a_stale_if_unmodified_since() {
        // `etag()` of a zero-length checksum is the two-character quoted
        // empty string `""`.
        let md = md_at(2_000_000_000); // ~2033, well after the stale date below.
        let current_etag = etag(&md);
        assert_eq!(current_etag, "\"\"");

        let req = TestRequest::default()
            .insert_header(("if-match", current_etag.as_str()))
            .insert_header(("if-unmodified-since", "Sat, 01 Jan 2000 00:00:00 GMT"))
            .to_http_request();
        assert!(
            check_conditionals(&req, &md).is_none(),
            "a matching If-Match must short-circuit If-Unmodified-Since entirely"
        );
    }

    /// Negative control: with `If-Match` absent, a stale `If-Unmodified-
    /// Since` alone still applies and yields 412.
    #[test]
    fn stale_if_unmodified_since_alone_still_yields_412() {
        let md = md_at(2_000_000_000);
        let req = TestRequest::default()
            .insert_header(("if-unmodified-since", "Sat, 01 Jan 2000 00:00:00 GMT"))
            .to_http_request();
        let resp = check_conditionals(&req, &md).expect("stale If-Unmodified-Since must apply");
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    }
}
