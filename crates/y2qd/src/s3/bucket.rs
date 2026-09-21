//! Bucket-level S3 verbs: `HeadBucket`, `CreateBucket`, `DeleteBucket`,
//! `GetBucketLocation`, `GetBucketVersioning`, `ListObjects`/`ListObjectsV2`,
//! `DeleteObjects`.

use std::collections::BTreeSet;
use std::sync::Arc;

use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, web};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use y2q_core::{AnyStorage, BucketPermission, ListOptions, Listing, Metadata, Storage};

use crate::auth::AuthState;
use crate::authz::{Decision, authorize_bucket, claim_ownership};
use crate::s3::auth::S3Authenticated;
use crate::s3::error::S3Error;
use crate::s3::httpdate::iso8601;
use crate::s3::object::etag;
use crate::s3::routes::SubResource;
use crate::s3::xml;

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
    "tagging",
    "versioning",
];

pub(crate) fn reject_unimplemented_subresources(sub: &SubResource) -> Result<(), S3Error> {
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
        list_objects(&bucket, &sub, &storage, &auth, ListDialect::V2).await
    } else {
        list_objects(&bucket, &sub, &storage, &auth, ListDialect::V1).await
    }
}

/// `HEAD /{bucket}` — existence + visibility check only.
pub async fn head(
    path: web::Path<String>,
    req: HttpRequest,
    storage: web::Data<Arc<AnyStorage>>,
    s3_state: web::Data<crate::s3::state::S3State>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let bucket = path.into_inner();
    let sub = SubResource::parse(req.query_string());
    reject_unimplemented_subresources(&sub)?;

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
    req: HttpRequest,
    storage: web::Data<Arc<AnyStorage>>,
    auth_state: web::Data<AuthState>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let bucket = path.into_inner();
    let sub = SubResource::parse(req.query_string());
    reject_unimplemented_subresources(&sub)?;

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
    req: HttpRequest,
    storage: web::Data<Arc<AnyStorage>>,
    s3_state: web::Data<crate::s3::state::S3State>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let bucket = path.into_inner();
    let sub = SubResource::parse(req.query_string());
    reject_unimplemented_subresources(&sub)?;
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
        .any(|md| !crate::s3::multipart::is_reserved_key(&md.key))
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
    xml::escape_into(&mut body, &s3_state.config.region);
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
    let keys = xml::text_elements(xml_body, "Key")?;
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
        if let Err(s3_err) = crate::s3::multipart::reject_reserved_key(key) {
            out.push_str("<Error>");
            xml::tag(&mut out, "Key", key);
            xml::tag(&mut out, "Code", s3_err.code);
            xml::tag(&mut out, "Message", &s3_err.message);
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

/// Cursor-driven, delimiter-aware listing loop result.
struct ListPage {
    items: Vec<Metadata>,
    common_prefixes: Vec<String>,
    truncated: bool,
    /// Internal resume point fed back as `list_page`'s own `start_after`;
    /// may carry the `\u{10FFFF}` group-skip sentinel that lets a
    /// truncated common-prefix group be skipped wholesale on the next
    /// call. Never shown to a client directly.
    resume_cursor: Option<String>,
    /// Client-visible resume point: the last key or common prefix actually
    /// returned in this page (or, when truncation lands exactly on an
    /// unreturned common prefix, that prefix) — never carries the internal
    /// sentinel.
    next_marker: Option<String>,
}

/// `list_objects`'s internal page-fetch window. Independent of `max_keys`
/// (both callers already clamp that to 1000; `MAX_LIST_LIMIT` is 10_000) —
/// this only bounds how many keys `list_page` pulls from storage per
/// underlying `list_objects` call while filtering out reserved multipart
/// parts and grouping by delimiter.
const LIST_PAGE_SIZE: usize = 1000;

/// Shared cursor-driven, delimiter-aware listing loop used by both
/// `ListObjects` and `ListObjectsV2`.
async fn list_page(
    storage: &AnyStorage,
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    max_keys: usize,
    start_after: Option<String>,
) -> Result<ListPage, S3Error> {
    let mut results: Vec<Metadata> = Vec::new();
    let mut common: BTreeSet<String> = BTreeSet::new();
    let mut after = start_after;
    let mut truncated = false;
    let mut resume_cursor: Option<String> = None;
    let mut next_marker: Option<String> = None;
    let mut last_emitted: Option<String> = None;

    'outer: loop {
        let page = storage
            .list_objects(
                bucket,
                ListOptions {
                    prefix: Some(prefix.to_owned()),
                    after: after.clone(),
                    limit: Some(LIST_PAGE_SIZE),
                },
            )
            .await?;
        if page.items.is_empty() && page.next.is_none() {
            break;
        }
        for md in &page.items {
            if crate::s3::multipart::is_reserved_key(&md.key) {
                after = Some(md.key.clone());
                continue;
            }
            let rest = md.key.strip_prefix(prefix).unwrap_or(&md.key);
            if let Some(delim) = delimiter
                && let Some(idx) = rest.find(delim)
            {
                let cp = format!("{prefix}{}", &rest[..idx + delim.len()]);
                // Checked *before* inserting: an already-known group never
                // trips truncation (it costs no new slot), and a genuinely
                // new group that would overflow `max_keys` is truncated
                // without ever entering `common` — so it never counts
                // toward this page's `KeyCount`/`CommonPrefixes`. The
                // resume cursor reuses `after` (the last-safely-skippable
                // point from whatever came before this group), not
                // `cp`+sentinel — `cp` itself hasn't been seen yet here,
                // and a sentinel appended to it would sort past every key
                // in this very group, skipping it entirely on resume
                // instead of re-discovering it fresh.
                if !common.contains(&cp) && results.len() + common.len() >= max_keys {
                    truncated = true;
                    resume_cursor = after.clone().or_else(|| Some(cp.clone()));
                    next_marker = Some(cp);
                    break 'outer;
                }
                if common.insert(cp.clone()) {
                    last_emitted = Some(cp.clone());
                }
                after = Some(format!("{cp}\u{10FFFF}"));
                continue;
            }
            if results.len() + common.len() >= max_keys {
                truncated = true;
                resume_cursor = after.clone().or_else(|| Some(md.key.clone()));
                next_marker = last_emitted.clone().or(resume_cursor.clone());
                break 'outer;
            }
            results.push(md.clone());
            after = Some(md.key.clone());
            last_emitted = Some(md.key.clone());
        }
        if page.next.is_none() {
            break;
        }
    }
    Ok(ListPage {
        items: results,
        common_prefixes: common.into_iter().collect(),
        truncated,
        resume_cursor,
        next_marker,
    })
}

fn encode_key(key: &str, url_encode: bool) -> String {
    if url_encode {
        crate::s3::sigv4::percent_encode_path(key)
    } else {
        key.to_owned()
    }
}

/// `ListObjects` (V1) vs `ListObjectsV2` — the two verbs differ only in
/// cursor source (`marker` vs `continuation-token`/`start-after`), the
/// `KeyCount` element (V2 only), and the truncation element (`NextMarker`
/// vs `NextContinuationToken`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum ListDialect {
    V1,
    V2,
}

async fn list_objects(
    bucket: &str,
    sub: &SubResource,
    storage: &AnyStorage,
    auth: &S3Authenticated,
    dialect: ListDialect,
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

    let start_after = match dialect {
        ListDialect::V1 => sub.get("marker").map(str::to_owned),
        ListDialect::V2 => match sub.get("continuation-token") {
            Some(token) => Some(
                decode_cursor(token)
                    .ok_or_else(|| S3Error::invalid_argument("invalid continuation-token"))?,
            ),
            None => sub.get("start-after").map(str::to_owned),
        },
    };

    let page = list_page(
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
    if dialect == ListDialect::V2 {
        xml::tag_num(
            &mut body,
            "KeyCount",
            page.items.len() + page.common_prefixes.len(),
        );
    }
    xml::tag(
        &mut body,
        "IsTruncated",
        if page.truncated { "true" } else { "false" },
    );
    if url_encode {
        xml::tag(&mut body, "EncodingType", "url");
    }
    if page.truncated {
        match dialect {
            ListDialect::V1 => {
                if let Some(marker) = &page.next_marker {
                    xml::tag(&mut body, "NextMarker", &encode_key(marker, url_encode));
                }
            }
            ListDialect::V2 => {
                if let Some(cursor) = &page.resume_cursor {
                    xml::tag(&mut body, "NextContinuationToken", &encode_cursor(cursor));
                }
            }
        }
    }
    for md in &page.items {
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
    for cp in &page.common_prefixes {
        body.push_str("<CommonPrefixes>");
        xml::tag(&mut body, "Prefix", &encode_key(cp, url_encode));
        body.push_str("</CommonPrefixes>");
    }
    body.push_str("</ListBucketResult>");
    Ok(HttpResponse::Ok()
        .content_type("application/xml")
        .body(body))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use tempfile::TempDir;
    use y2q_core::{FilesystemStorage, Object, PutOptions};

    use super::*;

    const TEST_NODE_KEY: [u8; 32] = [7u8; 32];

    fn make_storage() -> (AnyStorage, TempDir) {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("data");
        let index = dir.path().join("index.redb");
        let storage = FilesystemStorage::new(base, index).unwrap();
        storage.install_node_key(TEST_NODE_KEY);
        (AnyStorage::Filesystem(storage), dir)
    }

    async fn put(storage: &AnyStorage, bucket: &str, key: &str) {
        storage.create_bucket(bucket).await.unwrap_or_default();
        storage
            .put(
                bucket,
                key,
                Object::new(Bytes::new()),
                PutOptions::default(),
            )
            .await
            .unwrap();
    }

    /// Regression proof for the delimiter-group truncation bug: before the
    /// fix, the budget check ran *after* inserting a would-be-3rd common
    /// prefix into the page, so `max_keys = 2` returned 3 prefixes on the
    /// first page and then repeated the last one on the next page.
    #[tokio::test]
    async fn delimiter_truncation_returns_exactly_max_keys_prefixes_then_the_rest_once() {
        let (storage, _dir) = make_storage();
        for key in ["a/1", "a/2", "b/1", "b/2", "c/1"] {
            put(&storage, "bkt", key).await;
        }

        let first = list_page(&storage, "bkt", "", Some("/"), 2, None)
            .await
            .unwrap();
        assert_eq!(
            first.common_prefixes,
            vec!["a/".to_owned(), "b/".to_owned()]
        );
        assert!(first.truncated);
        let resume = first
            .resume_cursor
            .clone()
            .expect("truncated page must carry a resume cursor");

        let second = list_page(&storage, "bkt", "", Some("/"), 2, Some(resume))
            .await
            .unwrap();
        assert_eq!(second.common_prefixes, vec!["c/".to_owned()]);
        assert!(!second.truncated);
    }
}
