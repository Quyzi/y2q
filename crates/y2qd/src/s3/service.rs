//! Service-level S3 verb: `ListBuckets` (`GET /`).

use std::sync::Arc;

use actix_web::{HttpResponse, web};
use y2q_core::{AnyStorage, Listing};

use crate::authz::bucket_readable;
use crate::s3::auth::S3Authenticated;
use crate::s3::error::S3Error;
use crate::s3::httpdate::iso8601;
use crate::s3::xml;

/// `GET /` — enumerate every bucket visible to the caller.
///
/// y2q stores no bucket creation timestamp, so `CreationDate` is the Unix
/// epoch for every bucket — a visible but harmless divergence from real S3,
/// not a fabricated value.
pub async fn list_buckets(
    storage: web::Data<Arc<AnyStorage>>,
    auth: S3Authenticated,
) -> Result<HttpResponse, S3Error> {
    let all = storage.list_buckets().await?;
    let mut visible = Vec::with_capacity(all.len());
    for b in all {
        if bucket_readable(&auth.auth, &storage, &b).await? {
            visible.push(b);
        }
    }
    visible.sort();

    let mut body = String::with_capacity(256 + visible.len() * 96);
    xml::header(&mut body);
    body.push_str(r#"<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#);
    body.push_str("<Owner>");
    xml::tag(&mut body, "ID", &auth.auth.username);
    xml::tag(&mut body, "DisplayName", &auth.auth.username);
    body.push_str("</Owner><Buckets>");
    for name in visible {
        body.push_str("<Bucket>");
        xml::tag(&mut body, "Name", &name);
        xml::tag(&mut body, "CreationDate", &iso8601(0));
        body.push_str("</Bucket>");
    }
    body.push_str("</Buckets></ListAllMyBucketsResult>");

    Ok(HttpResponse::Ok()
        .content_type("application/xml")
        .body(body))
}
