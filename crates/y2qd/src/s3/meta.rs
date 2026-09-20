//! S3 header/metadata/tag mapping onto y2q's label namespace.
//!
//! Reserved label-name prefix `amz-`: `amz-content-type` etc. map to HTTP
//! system headers, `amz-meta-<name>` maps to `x-amz-meta-<name>`, and
//! `amz-mpu-parts` records a multipart-assembled object's part count (see
//! `crate::s3::multipart::complete`). Everything else stored on the object
//! is an S3 object tag. Centralizing the mapping here is what keeps it from
//! drifting between `PutObject`, `GetObject`, `CopyObject`, and the tagging
//! endpoints.

use actix_web::HttpRequest;
use actix_web::http::StatusCode;
use actix_web::http::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_LANGUAGE, CONTENT_TYPE, EXPIRES,
};
use y2q_core::{LabelSet, Metadata};

use crate::config::LabelLimits;
use crate::s3::error::S3Error;
use crate::s3::sigv4::percent_decode;

/// y2q's own reserved label names (system metadata surfaced on REST HEAD).
/// An S3 tag colliding with one of these, or with the `amz-` prefix, is
/// rejected rather than silently shadowing system metadata.
const RESERVED_TAG_NAMES: &[&str] = &["created", "modified", "checksum-gxhash"];
/// S3's own cap on the number of tags a single object may carry.
const MAX_TAGS: usize = 10;

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
    if name.starts_with("amz-") || RESERVED_TAG_NAMES.contains(&name) {
        return Err(invalid_tag(format!("reserved tag name: {name}")));
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
            if name.len() > limits.max_label_name_bytes {
                return Err(invalid_tag(format!("label name too long: {name}")));
            }
            if value.len() > limits.max_label_value_bytes {
                return Err(oversized(&name));
            }
            out.insert((name, value.to_owned()));
            Ok(())
        };

    for (header, label) in [
        (&CONTENT_TYPE, "amz-content-type"),
        (&CONTENT_ENCODING, "amz-content-encoding"),
        (&CONTENT_DISPOSITION, "amz-content-disposition"),
        (&CONTENT_LANGUAGE, "amz-content-language"),
        (&CACHE_CONTROL, "amz-cache-control"),
        (&EXPIRES, "amz-expires"),
    ] {
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
        if name.len() > limits.max_label_name_bytes {
            return Err(invalid_tag(format!("tag name too long: {name}")));
        }
        if value.len() > limits.max_label_value_bytes {
            return Err(invalid_tag(format!("tag value too long: {name}")));
        }
        out.insert((name, value));
    }
    Ok(out)
}
