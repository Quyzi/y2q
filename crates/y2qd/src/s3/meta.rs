//! S3 header/metadata/tag mapping onto y2q's label namespace.
//!
//! Reserved label-name prefix `amz-`: `amz-content-type` etc. map to HTTP
//! system headers, `amz-meta-<name>` maps to `x-amz-meta-<name>`, and
//! `amz-mpu-parts` records a multipart-assembled object's part count (see
//! `crate::s3::multipart::complete`). Everything else stored on the object
//! is an S3 object tag. Centralizing the mapping here — both directions,
//! request headers to labels and labels back to response headers — is what
//! keeps it from drifting between `PutObject`, `GetObject`, `CopyObject`,
//! and the tagging endpoints.

use actix_web::http::StatusCode;
use actix_web::http::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_LANGUAGE, CONTENT_TYPE, EXPIRES,
    HeaderName,
};
use actix_web::{HttpRequest, HttpResponseBuilder};
use y2q_core::{LabelSet, Metadata};

use crate::config::LabelLimits;
use crate::s3::error::S3Error;
use crate::s3::httpdate::http_date;
use crate::s3::routes::SubResource;
use crate::s3::sigv4::percent_decode;

/// `(request/response header, y2q label name, `response-*` query-override
/// name)` for every S3 system-metadata header the gateway maps onto a
/// label. Drives both directions: `labels_from_request`'s forward loop
/// (header -> label, on write) and `apply_object_headers`'s reverse loop
/// (label -> header, on read), so the two can't drift apart.
const S3_SYSTEM_HEADERS: &[(&HeaderName, &str, &str)] = &[
    (&CONTENT_TYPE, "amz-content-type", "response-content-type"),
    (
        &CONTENT_ENCODING,
        "amz-content-encoding",
        "response-content-encoding",
    ),
    (
        &CONTENT_DISPOSITION,
        "amz-content-disposition",
        "response-content-disposition",
    ),
    (
        &CONTENT_LANGUAGE,
        "amz-content-language",
        "response-content-language",
    ),
    (
        &CACHE_CONTROL,
        "amz-cache-control",
        "response-cache-control",
    ),
    (&EXPIRES, "amz-expires", "response-expires"),
];

/// S3's own cap on the number of tags a single object may carry.
const MAX_TAGS: usize = 10;
/// Label recording a multipart-assembled object's part count, written only
/// by `crate::s3::multipart::complete`. Never copied forward by
/// `CopyObject`'s `COPY` metadata directive — a single-part copy of a
/// multipart-assembled source is not itself multipart-shaped.
pub const MPU_PARTS_LABEL: &str = "amz-mpu-parts";

fn invalid_tag(message: impl Into<String>) -> S3Error {
    S3Error::new("InvalidTag", StatusCode::BAD_REQUEST, message)
}

fn metadata_too_large(name: &str) -> S3Error {
    S3Error::new(
        "MetadataTooLarge",
        StatusCode::BAD_REQUEST,
        format!("metadata value too long: {name}"),
    )
}

fn validate_tag_name(name: &str) -> Result<(), S3Error> {
    if name.starts_with("amz-") || crate::handlers::labels::RESERVED.contains(&name) {
        return Err(invalid_tag(format!("reserved tag name: {name}")));
    }
    Ok(())
}

/// Validate a label's name/value byte lengths against `limits`, producing
/// `on_name`/`on_value`'s error on overflow. Shared by
/// `labels_from_request`'s header-derived `push` and `replace_tags`'s
/// per-tag validation, which differ only in which error each constructs.
fn check_len(
    name: &str,
    value: &str,
    limits: &LabelLimits,
    on_name: impl FnOnce(&str) -> S3Error,
    on_value: impl FnOnce(&str) -> S3Error,
) -> Result<(), S3Error> {
    if name.len() > limits.max_label_name_bytes {
        return Err(on_name(name));
    }
    if value.len() > limits.max_label_value_bytes {
        return Err(on_value(name));
    }
    Ok(())
}

/// Parse `x-amz-tagging`'s URL-encoded-query-string value (`a=1&b=2`) into
/// lowercase-named `(name, value)` pairs.
fn parse_tagging_header(s: &str) -> Result<Vec<(String, String)>, S3Error> {
    let mut out = Vec::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| invalid_tag("malformed x-amz-tagging"))?;
        out.push((percent_decode(k).to_ascii_lowercase(), percent_decode(v)));
    }
    Ok(out)
}

/// Build the label set for a write from S3 request headers: system
/// headers, `x-amz-meta-*`, and the `x-amz-tagging` query-string header.
pub fn labels_from_request(req: &HttpRequest, limits: &LabelLimits) -> Result<LabelSet, S3Error> {
    let mut out: LabelSet = LabelSet::new();

    let mut push =
        |name: String, value: &str, oversized: fn(&str) -> S3Error| -> Result<(), S3Error> {
            check_len(
                &name,
                value,
                limits,
                |n| invalid_tag(format!("label name too long: {n}")),
                oversized,
            )?;
            out.insert((name, value.to_owned()));
            Ok(())
        };

    for &(header, label, _) in S3_SYSTEM_HEADERS {
        if let Some(v) = req.headers().get(header).and_then(|v| v.to_str().ok()) {
            push(label.to_owned(), v, metadata_too_large)?;
        }
    }

    for (name, value) in req.headers().iter() {
        let lower = name.as_str().to_ascii_lowercase();
        let Some(meta_name) = lower.strip_prefix("x-amz-meta-") else {
            continue;
        };
        if meta_name.is_empty() {
            continue;
        }
        let value_str = value
            .to_str()
            .map_err(|_| invalid_tag(format!("invalid value for x-amz-meta-{meta_name}")))?;
        push(
            format!("amz-meta-{meta_name}"),
            value_str,
            metadata_too_large,
        )?;
    }

    if let Some(tagging) = req
        .headers()
        .get("x-amz-tagging")
        .and_then(|v| v.to_str().ok())
    {
        let tags = parse_tagging_header(tagging)?;
        if tags.len() > MAX_TAGS {
            return Err(invalid_tag("too many tags (max 10)"));
        }
        for (name, value) in tags {
            validate_tag_name(&name)?;
            push(name, &value, |n| {
                invalid_tag(format!("tag value too long: {n}"))
            })?;
        }
    }

    if out.len() > limits.max_labels {
        return Err(invalid_tag("too many labels"));
    }
    Ok(out)
}

pub(crate) fn find_label<'a>(md: &'a Metadata, name: &str) -> Option<&'a str> {
    md.labels
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Apply the full `amz-*`-labels-plus-system-metadata header set a
/// GET/HEAD response carries. `sub`'s `response-content-type` etc.
/// overrides (used by presigned download links) take precedence over the
/// object's own stored labels. `Content-Type` alone falls back to
/// `binary/octet-stream` when neither is present; the other system
/// headers are simply omitted.
pub fn apply_object_headers(builder: &mut HttpResponseBuilder, md: &Metadata, sub: &SubResource) {
    for &(header, label, response_override) in S3_SYSTEM_HEADERS {
        let value = sub.get(response_override).or_else(|| find_label(md, label));
        if *header == CONTENT_TYPE {
            builder.insert_header((
                header.clone(),
                value.unwrap_or("binary/octet-stream").to_owned(),
            ));
        } else if let Some(v) = value {
            builder.insert_header((header.clone(), v.to_owned()));
        }
    }

    for (name, value) in &md.labels {
        if let Some(meta_name) = name.strip_prefix("amz-meta-") {
            builder.append_header((format!("x-amz-meta-{meta_name}"), value.clone()));
        }
    }

    builder.insert_header(("ETag", crate::s3::object::etag(md)));
    builder.insert_header(("Last-Modified", http_date(md.modified / 1_000_000_000)));
    builder.insert_header(("Accept-Ranges", "bytes"));
    builder.insert_header(("x-amz-server-side-encryption", "AES256"));
}

/// Label set for `CopyObject`'s default `COPY` metadata directive: every
/// label of the source object except [`MPU_PARTS_LABEL`], which only
/// `multipart::complete` may write.
pub fn labels_for_copy(src: &Metadata) -> LabelSet {
    src.labels
        .iter()
        .filter(|(k, _)| k != MPU_PARTS_LABEL)
        .cloned()
        .collect()
}

/// The object's S3 tag set: every label whose name does not start `amz-`.
pub fn tag_set(md: &Metadata) -> Vec<(String, String)> {
    md.labels
        .iter()
        .filter(|(k, _)| !k.starts_with("amz-"))
        .cloned()
        .collect()
}

/// Merge a replacement tag set with the object's existing `amz-*` labels —
/// for `PutObjectTagging`, which must not disturb system metadata.
pub fn replace_tags(
    md: &Metadata,
    tags: Vec<(String, String)>,
    limits: &LabelLimits,
) -> Result<LabelSet, S3Error> {
    if tags.len() > MAX_TAGS {
        return Err(invalid_tag("too many tags (max 10)"));
    }
    let mut out: LabelSet = md
        .labels
        .iter()
        .filter(|(k, _)| k.starts_with("amz-"))
        .cloned()
        .collect();
    for (name, value) in tags {
        let name = name.to_ascii_lowercase();
        validate_tag_name(&name)?;
        check_len(
            &name,
            &value,
            limits,
            |n| invalid_tag(format!("tag name too long: {n}")),
            |n| invalid_tag(format!("tag value too long: {n}")),
        )?;
        out.insert((name, value));
    }
    Ok(out)
}
