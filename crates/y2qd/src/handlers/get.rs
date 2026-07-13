//! `GET /{bucket}/{key}` — retrieve a stored object.
//!
//! Range requests are served from the chunk-addressable v2 envelope: only the
//! ciphertext chunks covering the requested plaintext bytes are read from
//! storage and decrypted (206 Partial Content). Every object is always
//! encrypted; there is no unauthenticated plaintext passthrough.

use std::sync::Arc;

use actix_web::http::header;
use actix_web::{HttpRequest, HttpResponse, web};
use bytes::{Bytes, BytesMut};
use y2q_core::crypto::envelope;
use y2q_core::{AnyStorage, BucketPermission, Storage};

use crate::auth::Authenticated;
use crate::authz::authorize_bucket;
use crate::cipher;
use crate::cluster::{self, ClusterRuntime};
use crate::error::{AppError, ErrorBody};
use crate::observability;

/// AES-256-GCM authentication tag length appended to each v2 chunk on disk.
const TAG_LEN: u64 = 16;

/// Retrieve a stored object.
///
/// If a `Range: bytes=N-M` header is present, returns 206 Partial Content with
/// a `Content-Range` header: only the covering ciphertext chunks are read and
/// decrypted. A malformed or out-of-bounds range returns 416. Without a
/// `Range` header, returns 200 OK with the full body. Requires a valid Bearer
/// token.
#[utoipa::path(
    get,
    operation_id = "get_object",
    path = "/{bucket}/{key}",
    params(
        ("bucket" = String, Path, description = "Bucket name (alphanumeric, `-`, `_`)"),
        ("key" = String, Path, description = "Object key; may contain `/` to represent nested paths"),
        ("Range" = Option<String>, Header, description = "Byte range to retrieve, e.g. `bytes=0-1023`. Returns 206, or 416 if out of bounds."),
    ),
    responses(
        (status = 200, description = "Full object body", content_type = "application/octet-stream"),
        (status = 206, description = "Partial content (Range request)", content_type = "application/octet-stream"),
        (status = 400, description = "Invalid bucket or key", body = ErrorBody, content_type = "application/json"),
        (status = 401, description = "Authentication required", body = ErrorBody, content_type = "application/json"),
        (status = 404, description = "Object not found", body = ErrorBody, content_type = "application/json"),
        (status = 409, description = "Object is locked (write in progress)", body = ErrorBody, content_type = "application/json"),
        (status = 416, description = "Requested range not satisfiable (inverted or out of bounds)", body = ErrorBody, content_type = "application/json"),
        (status = 500, description = "Internal error", body = ErrorBody, content_type = "application/json"),
    ),
    security(("bearer" = [])),
    tag = "objects",
)]
pub async fn handle(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    storage: web::Data<Arc<AnyStorage>>,
    cluster: Option<web::Data<ClusterRuntime>>,
    auth: Authenticated,
) -> Result<HttpResponse, AppError> {
    let (bucket, key) = path.into_inner();
    authorize_bucket(&auth, &storage, &bucket, BucketPermission::Read).await?;
    let range_header = req
        .headers()
        .get(header::RANGE)
        .and_then(|h| h.to_str().ok())
        .and_then(parse_byte_range);

    // Clustered: an apportioned read either serves this node's local committed
    // copy (fall through) or fetches the committed envelope from the chain TAIL,
    // which is then decrypted here with the user keystore.
    if let Some(rt) = cluster.as_ref() {
        match cluster::plan_read(rt, &bucket, &key).await? {
            y2q_cluster::ReadPlan::Remote { envelope, size } => {
                metrics::counter!(observability::CLUSTER_READS, "kind" => "remote").increment(1);
                return serve_remote_envelope(envelope, size, range_header, &auth, &bucket, &key);
            }
            y2q_cluster::ReadPlan::Local => {
                metrics::counter!(observability::CLUSTER_READS, "kind" => "local").increment(1);
                // Fall through to the local serving path below.
            }
        }
    }

    // No Range header: return the full object, decrypted in place.
    let Some((start, end)) = range_header else {
        let object = storage.get(&bucket, &key).await.map_err(AppError::from)?;
        let stored = object.into_inner();
        // Consume the storage allocation so the AEAD open happens in place;
        // fall back to a copy if the buffer is shared.
        let buf = stored
            .try_into_mut()
            .unwrap_or_else(|b| BytesMut::from(b.as_ref()));
        let plaintext = cipher::decrypt_after_get(&auth.keystore, &bucket, &key, buf)?;
        // v2 envelopes are zero-padded to a Padmé boundary to hide the exact
        // object size, so the decrypted plaintext may carry trailing pad
        // bytes. Trim to the true size recorded in the (encrypted) metadata.
        let size = storage
            .describe(&bucket, &key)
            .await
            .map_err(AppError::from)?
            .size as usize;
        let plaintext = if plaintext.len() > size {
            plaintext.slice(0..size)
        } else {
            plaintext
        };
        return Ok(HttpResponse::Ok()
            .content_type("application/octet-stream")
            .body(plaintext));
    };

    // Range request: consult metadata (index lookup, no whole-file read) to learn
    // the plaintext size and envelope version before deciding how to serve it.
    let md = storage
        .describe(&bucket, &key)
        .await
        .map_err(AppError::from)?;
    let size = md.size;

    // A range must be well-formed and lie entirely within the object.
    if start > end || start >= size || end >= size {
        return Ok(range_not_satisfiable(size));
    }

    match md.envelope_version {
        // v2 chunked (the only supported format): read only the covering
        // ciphertext chunks and decrypt them.
        Some(2) => {
            let preamble_len = envelope::v2_preamble_len() as u64;
            let preamble = storage
                .get_range(&bucket, &key, (0..=preamble_len - 1).into())
                .await
                .map_err(AppError::from)?;
            let (chunk_size_u32, _) = envelope::parse_v2_geometry(&preamble).map_err(|_| {
                AppError(y2q_core::Error::EnvelopeMalformed {
                    bucket: bucket.clone(),
                    key: key.clone(),
                    reason: "bad v2 header".to_owned(),
                })
            })?;
            let chunk_size = chunk_size_u32 as u64;
            let stride = chunk_size + TAG_LEN;
            let first = start / chunk_size;
            let last = end / chunk_size;
            let cipher_start = preamble_len + first * stride;
            let cipher_end_calc = preamble_len + (last + 1) * stride - 1;
            // Clamp to the on-disk envelope size; the final chunk is shorter.
            let cipher_end = match md.cipher_size {
                Some(cs) => cipher_end_calc.min(cs - 1),
                None => cipher_end_calc,
            };
            let window = storage
                .get_range(&bucket, &key, (cipher_start..=cipher_end).into())
                .await
                .map_err(AppError::from)?;

            let chunks_pt = cipher::decrypt_v2_chunks(
                &auth.keystore,
                &bucket,
                &key,
                &preamble,
                &window,
                first,
            )?;

            let trim_front = (start - first * chunk_size) as usize;
            let take = (end - start + 1) as usize;
            let body = Bytes::from(chunks_pt).slice(trim_front..trim_front + take);
            Ok(partial_content(start, end, size, body))
        }
        // Any other (unknown, or pre-v2/legacy) envelope version is rejected —
        // there is no unauthenticated plaintext passthrough to fall back to.
        other => Err(AppError(y2q_core::Error::UnsupportedEnvelopeVersion {
            version: other.unwrap_or(0),
        })),
    }
}

/// Serve a committed ciphertext `envelope` fetched from a peer (the chain TAIL)
/// for an apportioned read: decrypt it with the user keystore, trim Padmé
/// padding to the true plaintext `size`, then answer the full body or the
/// requested byte range. Range requests decrypt the whole envelope and slice the
/// plaintext (the chunk-addressable fast path is local-only).
fn serve_remote_envelope(
    envelope: Bytes,
    size: u64,
    range: Option<(u64, u64)>,
    auth: &Authenticated,
    bucket: &str,
    key: &str,
) -> Result<HttpResponse, AppError> {
    let buf = BytesMut::from(envelope.as_ref());
    let plaintext = cipher::decrypt_after_get(&auth.keystore, bucket, key, buf)?;
    let plaintext: Bytes = if plaintext.len() as u64 > size {
        plaintext.slice(0..size as usize)
    } else {
        plaintext
    };

    let Some((start, end)) = range else {
        return Ok(HttpResponse::Ok()
            .content_type("application/octet-stream")
            .body(plaintext));
    };

    let total = plaintext.len() as u64;
    if start > end || start >= total || end >= total {
        return Ok(range_not_satisfiable(total));
    }
    let body = plaintext.slice(start as usize..end as usize + 1);
    Ok(partial_content(start, end, total, body))
}

/// Build a 206 Partial Content response for `[start, end]` of a `total`-byte object.
fn partial_content(start: u64, end: u64, total: u64, body: Bytes) -> HttpResponse {
    HttpResponse::PartialContent()
        .insert_header((header::CONTENT_TYPE, "application/octet-stream"))
        .insert_header((
            header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{total}"),
        ))
        .body(body)
}

/// Build a 416 Range Not Satisfiable response with `Content-Range: bytes */total`.
fn range_not_satisfiable(total: u64) -> HttpResponse {
    HttpResponse::RangeNotSatisfiable()
        .insert_header((header::CONTENT_RANGE, format!("bytes */{total}")))
        .finish()
}

/// Parse a `bytes=N-M` range string into `(start, end)`.
///
/// Returns `None` for open-ended forms (`bytes=N-`, `bytes=-M`) and unparseable
/// input. Inverted ranges (`start > end`) ARE returned so the handler can reject
/// them with 416 rather than silently falling through to a full response.
fn parse_byte_range(s: &str) -> Option<(u64, u64)> {
    let s = s.trim().strip_prefix("bytes=")?;
    let (start_s, end_s) = s.split_once('-')?;
    let start = start_s.trim().parse::<u64>().ok()?;
    let end = end_s.trim().parse::<u64>().ok()?;
    Some((start, end))
}

#[cfg(test)]
mod tests {
    use super::parse_byte_range;

    #[test]
    fn parses_valid_ranges() {
        assert_eq!(parse_byte_range("bytes=0-99"), Some((0, 99)));
        assert_eq!(parse_byte_range("  bytes=10-10 "), Some((10, 10)));
    }

    #[test]
    fn rejects_bad_ranges() {
        assert_eq!(parse_byte_range("0-99"), None); // no bytes= prefix
        assert_eq!(parse_byte_range("bytes=abc-1"), None);
        assert_eq!(parse_byte_range("bytes=5"), None); // no dash
    }

    #[test]
    fn surfaces_inverted_range() {
        // Inverted ranges are returned so the handler can reject them with 416.
        assert_eq!(parse_byte_range("bytes=99-0"), Some((99, 0)));
    }
}
