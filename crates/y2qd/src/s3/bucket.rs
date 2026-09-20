//! Bucket-level S3 verbs: `HeadBucket`, `CreateBucket`, `DeleteBucket`,
//! `GetBucketLocation`, `GetBucketVersioning`, `ListObjects`/`ListObjectsV2`,
//! `DeleteObjects`.

use std::collections::BTreeSet;
use std::sync::Arc;

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, web};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use y2q_core::{
    AnyStorage, BucketPermission, ListOptions, Listing, MAX_LIST_LIMIT, Metadata, Storage,
};

use crate::auth::AuthState;
use crate::authz::{Decision, authorize_bucket, claim_ownership};
use crate::s3::auth::S3Authenticated;
use crate::s3::error::S3Error;
use crate::s3::httpdate::iso8601;
use crate::s3::object::etag;
use crate::s3::routes::SubResource;
use crate::s3::xml::{self, XmlError};

/// Multipart-upload part storage namespace; never surfaced in a listing.
const MULTIPART_PREFIX: &str = ".y2q-mpu/";

/// S3 sub-resources y2q recognizes but does not implement. Any of these
/// present on a bucket request yields 501 rather than being silently
/// ignored or misinterpreted as a plain listing/create.
const UNIMPLEMENTED_SUBRESOURCES: &[&str] = &[
    "acl",
    "policy",
    "lifecycle",
    "cors",
    "website",
    "encryption",
    "replication",
    "object-lock",
    "legal-hold",
    "retention",
    "select",
    "restore",
    "accelerate",
    "logging",
    "notification",
    "requestPayment",
    "analytics",
    "inventory",
    "metrics",
    "intelligent-tiering",
    "ownershipControls",
    "publicAccessBlock",
];

fn reject_unimplemented_subresources(sub: &SubResource) -> Result<(), S3Error> {
    for name in UNIMPLEMENTED_SUBRESOURCES {
        if sub.has(name) {
            return Err(S3Error::not_implemented(format!(
                "the {name} sub-resource is not implemented"
            )));
        }
    }
    Ok(())
}

fn encode_cursor(s: &str) -> String {
    URL_SAFE_NO_PAD.encode(s.as_bytes())
}

fn decode_cursor(s: &str) -> Option<String> {
    URL_SAFE_NO_PAD
        .decode(s)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
}

/// `GET /{bucket}` / `GET /{bucket}/` — dispatches on sub-resource, since
/// actix cannot route on query parameters.
pub async fn get(
    path: web::Path<String>,
    req: HttpRequest,
    storage: web::Data<Arc<AnyStorage>>,
    s3_state: web::Data<crate::s3::state::S3State>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let bucket = path.into_inner();
    let sub = SubResource::parse(req.query_string());

    if sub.has("location") {
        return get_bucket_location(&bucket, &storage, &s3_state, &auth).await;
    }
    if sub.has("versioning") {
        return get_bucket_versioning(&bucket, &storage, &auth).await;
    }
    if sub.has("uploads") {
        return crate::s3::multipart::list_uploads(&bucket, &storage, &s3_state, &auth).await;
    }
    reject_unimplemented_subresources(&sub)?;

    if sub.get("list-type") == Some("2") {
        list_objects_v2(&bucket, &sub, &storage, &auth).await
    } else {
        list_objects_v1(&bucket, &sub, &storage, &auth).await
    }
}

/// `HEAD /{bucket}` — existence + visibility check only.
pub async fn head(
    path: web::Path<String>,
    storage: web::Data<Arc<AnyStorage>>,
    s3_state: web::Data<crate::s3::state::S3State>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let bucket = path.into_inner();
    match authorize_bucket(&auth.auth, &storage, &bucket, BucketPermission::Read).await {
        Ok(_) => Ok(HttpResponse::Ok()
            .insert_header(("x-amz-bucket-region", s3_state.config.region.clone()))
            .finish()),
        Err(e) => {
            let s3_err = S3Error::from(e);
            Ok(HttpResponse::build(s3_err.status).finish())
        }
    }
}

/// `PUT /{bucket}` — `CreateBucket`. Idempotent: an already-owned bucket
/// returns 200 (S3's `BucketAlreadyOwnedByYou` behavior for same-region
/// creates); owned by someone else and visible → 409; invisible → the
/// existence-hiding 404 `authorize_bucket` already produces.
pub async fn put(
    path: web::Path<String>,
    storage: web::Data<Arc<AnyStorage>>,
    auth_state: web::Data<AuthState>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let bucket = path.into_inner();
    let decision = authorize_bucket(&auth.auth, &storage, &bucket, BucketPermission::Write).await?;
    match decision {
        Decision::ClaimOwnership => {
            claim_ownership(
                &storage,
                &auth_state.user_store,
                &bucket,
                &auth.auth.session,
            )
            .await?;
        }
        Decision::Allowed => {}
    }
    Ok(HttpResponse::Ok()
        .insert_header(("Location", format!("/{bucket}")))
        .finish())
}

/// `DELETE /{bucket}` — requires the bucket to be empty (S3 semantics).
pub async fn delete(
    path: web::Path<String>,
    storage: web::Data<Arc<AnyStorage>>,
    s3_state: web::Data<crate::s3::state::S3State>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let bucket = path.into_inner();
    authorize_bucket(&auth.auth, &storage, &bucket, BucketPermission::Admin).await?;

    let page = storage
        .list_objects(
            &bucket,
            ListOptions {
                prefix: None,
                after: None,
                // Large enough to see past any pending multipart parts
                // (which sort before ordinary keys under `.y2q-mpu/`) to a
                // real object, without paying for a full bucket scan.
                limit: Some(1000),
            },
        )
        .await?;
    if page
        .items
        .iter()
        .any(|md| !md.key.starts_with(MULTIPART_PREFIX))
        || page.next.is_some()
    {
        return Err(S3Error::new(
            "BucketNotEmpty",
            StatusCode::CONFLICT,
            "The bucket you tried to delete is not empty.",
        ));
    }

    for upload in s3_state.uploads.list_for_bucket(&bucket) {
        crate::s3::multipart::abort_upload_parts(&storage, &upload).await;
        s3_state.uploads.remove(&upload.upload_id);
    }

    storage.delete_bucket(&bucket).await?;
    Ok(HttpResponse::NoContent().finish())
}

async fn get_bucket_location(
    bucket: &str,
    storage: &AnyStorage,
    s3_state: &crate::s3::state::S3State,
    auth: &S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    authorize_bucket(&auth.auth, storage, bucket, BucketPermission::Read).await?;
    let mut body = String::new();
    xml::header(&mut body);
    body.push_str(r#"<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#);
    body.push_str(&xml::escape(&s3_state.config.region));
    body.push_str("</LocationConstraint>");
    Ok(HttpResponse::Ok()
        .content_type("application/xml")
        .body(body))
}

/// `POST /{bucket}?delete` — `DeleteObjects` (bulk delete).
pub async fn post(
    path: web::Path<String>,
    req: HttpRequest,
    body: web::Bytes,
    storage: web::Data<Arc<AnyStorage>>,
    mut auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let bucket = path.into_inner();
    let sub = SubResource::parse(req.query_string());
    if !sub.has("delete") {
        return Err(S3Error::not_implemented(
            "unsupported bucket POST sub-resource",
        ));
    }

    authorize_bucket(&auth.auth, &storage, &bucket, BucketPermission::Write).await?;

    let xml_body = std::str::from_utf8(&body)
        .map_err(|_| S3Error::malformed_xml("request body is not valid UTF-8"))?;
    let keys = xml::text_elements(xml_body, "Key").map_err(xml_error_to_s3)?;
    if keys.len() > 1000 {
        return Err(S3Error::malformed_xml(
            "DeleteObjects accepts at most 1000 keys",
        ));
    }
    let quiet = !xml::text_elements(xml_body, "Quiet")
        .unwrap_or_default()
        .first()
        .map(|v| v == "false")
        .unwrap_or(true);

    let mut out = String::new();
    xml::header(&mut out);
    out.push_str("<DeleteResult>");
    for (i, key) in keys.iter().enumerate() {
        if i % 100 == 0 {
            auth.leash.checkpoint()?;
        }
        if key.starts_with(MULTIPART_PREFIX) {
            out.push_str("<Error>");
            xml::tag(&mut out, "Key", key);
            xml::tag(&mut out, "Code", "AccessDenied");
            xml::tag(&mut out, "Message", "reserved key namespace");
            out.push_str("</Error>");
            continue;
        }
        match storage.delete(&bucket, key).await {
            Ok(_) | Err(y2q_core::Error::NotFound { .. }) => {
                if !quiet {
                    out.push_str("<Deleted>");
                    xml::tag(&mut out, "Key", key);
                    out.push_str("</Deleted>");
                }
            }
            Err(e) => {
                let s3_err = S3Error::from(e);
                out.push_str("<Error>");
                xml::tag(&mut out, "Key", key);
                xml::tag(&mut out, "Code", s3_err.code);
                xml::tag(&mut out, "Message", &s3_err.message);
                out.push_str("</Error>");
            }
        }
    }
    out.push_str("</DeleteResult>");
    Ok(HttpResponse::Ok().content_type("application/xml").body(out))
}

fn xml_error_to_s3(e: XmlError) -> S3Error {
    match e {
        XmlError::TooLarge => S3Error::malformed_xml("request body too large"),
        XmlError::Unterminated(tag) => {
            S3Error::malformed_xml(format!("malformed XML: unterminated <{tag}>"))
        }
    }
}

async fn get_bucket_versioning(
    bucket: &str,
    storage: &AnyStorage,
    auth: &S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    authorize_bucket(&auth.auth, storage, bucket, BucketPermission::Read).await?;
    let mut body = String::new();
    xml::header(&mut body);
    body.push_str(r#"<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>"#);
    Ok(HttpResponse::Ok()
        .content_type("application/xml")
        .body(body))
}

/// Shared cursor-driven, delimiter-aware listing loop used by both
/// `ListObjects` and `ListObjectsV2`. Returns `(results, common_prefixes,
/// truncated, next_cursor)`.
async fn list_page(
    storage: &AnyStorage,
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    max_keys: usize,
    start_after: Option<String>,
) -> Result<(Vec<Metadata>, Vec<String>, bool, Option<String>), S3Error> {
    let mut results: Vec<Metadata> = Vec::new();
    let mut common: BTreeSet<String> = BTreeSet::new();
    let mut after = start_after;
    let mut truncated = false;
    let mut next_cursor: Option<String> = None;
    let page_size = max_keys
        .clamp(1, MAX_LIST_LIMIT)
        .max(1000.min(MAX_LIST_LIMIT));

    'outer: loop {
        let page = storage
            .list_objects(
                bucket,
                ListOptions {
                    prefix: Some(prefix.to_owned()),
                    after: after.clone(),
                    limit: Some(page_size),
                },
            )
            .await?;
        if page.items.is_empty() && page.next.is_none() {
            break;
        }
        for md in &page.items {
            if md.key.starts_with(MULTIPART_PREFIX) {
                after = Some(md.key.clone());
                continue;
            }
            let rest = md.key.strip_prefix(prefix).unwrap_or(&md.key);
            if let Some(delim) = delimiter
                && let Some(idx) = rest.find(delim)
            {
                let cp = format!("{prefix}{}", &rest[..idx + delim.len()]);
                let inserted = common.insert(cp.clone());
                if inserted && results.len() + common.len() > max_keys {
                    truncated = true;
                    next_cursor = Some(cp);
                    break 'outer;
                }
                after = Some(format!("{cp}\u{10FFFF}"));
                continue;
            }
            if results.len() + common.len() >= max_keys {
                truncated = true;
                next_cursor = after.clone().or_else(|| Some(md.key.clone()));
                break 'outer;
            }
            results.push(md.clone());
            after = Some(md.key.clone());
        }
        if page.next.is_none() {
            break;
        }
    }
    Ok((
        results,
        common.into_iter().collect(),
        truncated,
        next_cursor,
    ))
}

fn encode_key(key: &str, url_encode: bool) -> String {
    if url_encode {
        percent_encode_key(key)
    } else {
        key.to_owned()
    }
}

/// Percent-encode a key/prefix for `EncodingType=url` responses, per S3's
/// convention: unreserved characters plus `/` pass through unescaped.
fn percent_encode_key(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(*b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

async fn list_objects_v2(
    bucket: &str,
    sub: &SubResource,
    storage: &AnyStorage,
    auth: &S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    authorize_bucket(&auth.auth, storage, bucket, BucketPermission::Read).await?;

    let prefix = sub.get("prefix").unwrap_or("").to_owned();
    let delimiter = sub.get("delimiter").map(str::to_owned);
    let max_keys = sub
        .get("max-keys")
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(1000)
        .min(1000);
    let url_encode = sub.get("encoding-type") == Some("url");
    let start_after = sub
        .get("continuation-token")
        .and_then(decode_cursor)
        .or_else(|| sub.get("start-after").map(str::to_owned));

    let (items, common, truncated, next_cursor) = list_page(
        storage,
        bucket,
        &prefix,
        delimiter.as_deref(),
        max_keys,
        start_after,
    )
    .await?;

    let mut body = String::new();
    xml::header(&mut body);
    body.push_str(r#"<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#);
    xml::tag(&mut body, "Name", bucket);
    xml::tag(&mut body, "Prefix", &encode_key(&prefix, url_encode));
    if let Some(d) = &delimiter {
        xml::tag(&mut body, "Delimiter", d);
    }
    xml::tag_num(&mut body, "MaxKeys", max_keys);
    xml::tag_num(&mut body, "KeyCount", items.len() + common.len());
    xml::tag(
        &mut body,
        "IsTruncated",
        if truncated { "true" } else { "false" },
    );
    if url_encode {
        xml::tag(&mut body, "EncodingType", "url");
    }
    if let Some(cursor) = &next_cursor
        && truncated
    {
        xml::tag(&mut body, "NextContinuationToken", &encode_cursor(cursor));
    }
    for md in &items {
        body.push_str("<Contents>");
        xml::tag(&mut body, "Key", &encode_key(&md.key, url_encode));
        xml::tag(
            &mut body,
            "LastModified",
            &iso8601(md.modified / 1_000_000_000),
        );
        xml::tag(&mut body, "ETag", &etag(md));
        xml::tag_num(&mut body, "Size", md.size);
        xml::tag(&mut body, "StorageClass", "STANDARD");
        body.push_str("</Contents>");
    }
    for cp in &common {
        body.push_str("<CommonPrefixes>");
        xml::tag(&mut body, "Prefix", &encode_key(cp, url_encode));
        body.push_str("</CommonPrefixes>");
    }
    body.push_str("</ListBucketResult>");
    Ok(HttpResponse::Ok()
        .content_type("application/xml")
        .body(body))
}

async fn list_objects_v1(
    bucket: &str,
    sub: &SubResource,
    storage: &AnyStorage,
    auth: &S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    authorize_bucket(&auth.auth, storage, bucket, BucketPermission::Read).await?;

    let prefix = sub.get("prefix").unwrap_or("").to_owned();
    let delimiter = sub.get("delimiter").map(str::to_owned);
    let max_keys = sub
        .get("max-keys")
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(1000)
        .min(1000);
    let url_encode = sub.get("encoding-type") == Some("url");
    let marker = sub.get("marker").map(str::to_owned);

    let (items, common, truncated, next_cursor) = list_page(
        storage,
        bucket,
        &prefix,
        delimiter.as_deref(),
        max_keys,
        marker,
    )
    .await?;

    let mut body = String::new();
    xml::header(&mut body);
    body.push_str(r#"<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#);
    xml::tag(&mut body, "Name", bucket);
    xml::tag(&mut body, "Prefix", &encode_key(&prefix, url_encode));
    if let Some(d) = &delimiter {
        xml::tag(&mut body, "Delimiter", d);
    }
    xml::tag_num(&mut body, "MaxKeys", max_keys);
    xml::tag(
        &mut body,
        "IsTruncated",
        if truncated { "true" } else { "false" },
    );
    if url_encode {
        xml::tag(&mut body, "EncodingType", "url");
    }
    if let Some(cursor) = &next_cursor
        && truncated
    {
        xml::tag(&mut body, "NextMarker", &encode_key(cursor, url_encode));
    }
    for md in &items {
        body.push_str("<Contents>");
        xml::tag(&mut body, "Key", &encode_key(&md.key, url_encode));
        xml::tag(
            &mut body,
            "LastModified",
            &iso8601(md.modified / 1_000_000_000),
        );
        xml::tag(&mut body, "ETag", &etag(md));
        xml::tag_num(&mut body, "Size", md.size);
        xml::tag(&mut body, "StorageClass", "STANDARD");
        body.push_str("</Contents>");
    }
    for cp in &common {
        body.push_str("<CommonPrefixes>");
        xml::tag(&mut body, "Prefix", &encode_key(cp, url_encode));
        body.push_str("</CommonPrefixes>");
    }
    body.push_str("</ListBucketResult>");
    Ok(HttpResponse::Ok()
        .content_type("application/xml")
        .body(body))
}
