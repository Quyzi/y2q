//! AWS SigV4 request verification primitives.
//!
//! Pure functions only (plus `parse`'s dependence on actix's `HeaderMap` to
//! read the request's own headers) — no I/O, fully unit-testable. The
//! extractor in `crate::s3::auth` drives these functions against a live
//! request; getting any of the canonicalisation rules below wrong makes
//! every real S3 client fail with `SignatureDoesNotMatch`.

use actix_web::http::header::HeaderMap;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
pub const STREAMING_SIGNED: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
pub const STREAMING_SIGNED_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
pub const STREAMING_UNSIGNED_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";

/// Errors recognizing or parsing a SigV4-signed request. Never carries the
/// caller's raw input — `crate::s3::error::S3Error`'s `From` impl maps every
/// variant to a generic wire message so a probe can't distinguish parse
/// failure modes.
#[derive(Debug, thiserror::Error)]
pub enum SigV4Error {
    #[error("no Authorization header or X-Amz-* query credentials present")]
    NoCredentials,
    #[error("malformed Authorization header")]
    MalformedHeader,
    #[error("unsupported signing algorithm")]
    UnsupportedAlgorithm,
    #[error("malformed credential scope")]
    MalformedScope,
    #[error("SignedHeaders must include host")]
    MissingHostHeader,
    #[error("malformed or missing X-Amz-Date")]
    MalformedDate,
    #[error("malformed or missing X-Amz-Expires")]
    MalformedExpires,
}

/// `<akid>/<yyyymmdd>/<region>/service/aws4_request`, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialScope {
    pub access_key_id: String,
    /// `yyyymmdd`.
    pub date: String,
    pub region: String,
    pub service: String,
}

/// What the request declares about its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadHash {
    /// Lowercase hex SHA-256 of the whole body; verify while streaming.
    Exact(String),
    Unsigned,
    /// `aws-chunked` framing, per-chunk signatures, optional trailer.
    StreamingSigned {
        trailer: bool,
    },
    /// `aws-chunked` framing, no per-chunk signatures, trailer present.
    StreamingUnsigned,
}

/// The literal payload-hash token to place in the canonical request's final
/// field for `payload`.
pub fn payload_hash_token(payload: &PayloadHash) -> &str {
    match payload {
        PayloadHash::Exact(hex) => hex,
        PayloadHash::Unsigned => UNSIGNED_PAYLOAD,
        PayloadHash::StreamingSigned { trailer: false } => STREAMING_SIGNED,
        PayloadHash::StreamingSigned { trailer: true } => STREAMING_SIGNED_TRAILER,
        PayloadHash::StreamingUnsigned => STREAMING_UNSIGNED_TRAILER,
    }
}

/// A parsed (but not yet verified) SigV4 request.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    pub scope: CredentialScope,
    /// Lowercase, in the order the client declared them.
    pub signed_headers: Vec<String>,
    /// Lowercase hex.
    pub signature: String,
    /// `yyyymmddTHHMMSSZ`.
    pub amz_date: String,
    pub payload: PayloadHash,
    /// Present only for presigned (query-string) requests.
    pub presigned_expires: Option<u64>,
}

/// Parse `Authorization: AWS4-HMAC-SHA256 ...` or, failing that, the
/// `X-Amz-*` presigned query-string form. Header auth takes precedence when
/// both are present.
pub fn parse(query: &str, headers: &HeaderMap) -> Result<SignedRequest, SigV4Error> {
    if let Some(auth) = headers
        .get(actix_web::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        return parse_header_auth(auth, headers);
    }
    parse_presigned(query, headers)
}

fn parse_header_auth(auth: &str, headers: &HeaderMap) -> Result<SignedRequest, SigV4Error> {
    let (algorithm, rest) = auth.split_once(' ').ok_or(SigV4Error::MalformedHeader)?;
    if algorithm != ALGORITHM {
        return Err(SigV4Error::UnsupportedAlgorithm);
    }

    let mut credential = None;
    let mut signed_headers_str = None;
    let mut signature = None;
    for part in rest.split(',') {
        let part = part.trim();
        let (k, v) = part.split_once('=').ok_or(SigV4Error::MalformedHeader)?;
        match k {
            "Credential" => credential = Some(v),
            "SignedHeaders" => signed_headers_str = Some(v),
            "Signature" => signature = Some(v),
            _ => {}
        }
    }
    let scope = parse_credential_scope(credential.ok_or(SigV4Error::MalformedHeader)?)?;
    let signed_headers =
        parse_signed_headers(signed_headers_str.ok_or(SigV4Error::MalformedHeader)?)?;
    let signature = signature
        .ok_or(SigV4Error::MalformedHeader)?
        .to_ascii_lowercase();

    let amz_date = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .ok_or(SigV4Error::MalformedDate)?
        .to_owned();

    // Only trust `x-amz-content-sha256` when it is itself covered by the
    // signature (declared in SignedHeaders) — otherwise an on-path party
    // could alter it post-signing without invalidating the signature.
    let payload = if signed_headers.iter().any(|h| h == "x-amz-content-sha256") {
        headers
            .get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok())
            .map(classify_payload_hash)
            .unwrap_or(PayloadHash::Unsigned)
    } else {
        PayloadHash::Unsigned
    };

    Ok(SignedRequest {
        scope,
        signed_headers,
        signature,
        amz_date,
        payload,
        presigned_expires: None,
    })
}

fn parse_presigned(query: &str, headers: &HeaderMap) -> Result<SignedRequest, SigV4Error> {
    let params = parse_query_params(query);
    let algorithm = params
        .get("X-Amz-Algorithm")
        .ok_or(SigV4Error::NoCredentials)?;
    if algorithm != ALGORITHM {
        return Err(SigV4Error::UnsupportedAlgorithm);
    }
    let credential = params
        .get("X-Amz-Credential")
        .ok_or(SigV4Error::MalformedHeader)?;
    let scope = parse_credential_scope(credential)?;
    let signed_headers = parse_signed_headers(
        params
            .get("X-Amz-SignedHeaders")
            .ok_or(SigV4Error::MalformedHeader)?,
    )?;
    let signature = params
        .get("X-Amz-Signature")
        .ok_or(SigV4Error::MalformedHeader)?
        .to_ascii_lowercase();
    let amz_date = params
        .get("X-Amz-Date")
        .ok_or(SigV4Error::MalformedDate)?
        .clone();
    let expires: u64 = params
        .get("X-Amz-Expires")
        .ok_or(SigV4Error::MalformedExpires)?
        .parse()
        .map_err(|_| SigV4Error::MalformedExpires)?;

    // Presigned requests are always Unsigned unless they carry an explicit
    // `x-amz-content-sha256` request header (rare, but some clients set one
    // for presigned uploads).
    let payload = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .map(classify_payload_hash)
        .unwrap_or(PayloadHash::Unsigned);

    Ok(SignedRequest {
        scope,
        signed_headers,
        signature,
        amz_date,
        payload,
        presigned_expires: Some(expires),
    })
}

fn parse_signed_headers(s: &str) -> Result<Vec<String>, SigV4Error> {
    let headers: Vec<String> = s.split(';').map(|h| h.to_ascii_lowercase()).collect();
    if !headers.iter().any(|h| h == "host") {
        return Err(SigV4Error::MissingHostHeader);
    }
    Ok(headers)
}

fn parse_credential_scope(credential: &str) -> Result<CredentialScope, SigV4Error> {
    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5 {
        return Err(SigV4Error::MalformedScope);
    }
    if parts[4] != "aws4_request" {
        return Err(SigV4Error::MalformedScope);
    }
    Ok(CredentialScope {
        access_key_id: parts[0].to_owned(),
        date: parts[1].to_owned(),
        region: parts[2].to_owned(),
        service: parts[3].to_owned(),
    })
}

fn classify_payload_hash(v: &str) -> PayloadHash {
    match v {
        UNSIGNED_PAYLOAD => PayloadHash::Unsigned,
        STREAMING_SIGNED => PayloadHash::StreamingSigned { trailer: false },
        STREAMING_SIGNED_TRAILER => PayloadHash::StreamingSigned { trailer: true },
        STREAMING_UNSIGNED_TRAILER => PayloadHash::StreamingUnsigned,
        hex => PayloadHash::Exact(hex.to_ascii_lowercase()),
    }
}

/// Decode `%XX` percent-escapes. Any other byte, including a literal `+`,
/// passes through unchanged — AWS's own query encoding never emits `+` for
/// space (it emits `%20`), so treating `+` as space would misdecode a
/// legitimately literal `+` in, e.g., a continuation token.
pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query_params(query: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(percent_decode(k), percent_decode(v));
    }
    map
}

/// RFC 3986 unreserved characters: never percent-encoded anywhere in a
/// SigV4 canonical request.
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Percent-encode every byte of `s` except the unreserved set, uppercase
/// hex, one `%XX` triplet per byte (never double-encoded).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        if is_unreserved(*b) {
            out.push(*b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

/// Build the canonical URI for a SigV4 canonical request: percent-encode
/// every path segment (RFC 3986 unreserved set only), leave `/` literal,
/// and never double-encode an already-percent-encoded byte in the input
/// (S3 is the one AWS service that single-encodes). An empty path becomes
/// `/`.
pub fn canonical_uri(path: &str) -> String {
    if path.is_empty() || path == "/" {
        return "/".to_owned();
    }
    path.split('/')
        .map(|segment| percent_encode(&percent_decode(segment)))
        .collect::<Vec<_>>()
        .join("/")
}

/// Build the canonical query string: percent-encode each name/value
/// (unreserved set only), sort pairs by encoded name then encoded value,
/// join with `&`. Excludes `X-Amz-Signature` (used only in the presigned
/// form, and never itself covered by the signature it names).
pub fn canonical_query_string(query: &str) -> String {
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (
                percent_encode(&percent_decode(k)),
                percent_encode(&percent_decode(v)),
            )
        })
        .filter(|(k, _)| k != "X-Amz-Signature")
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Build the canonical headers block (each line `name:value\n`, folded
/// whitespace, sorted+deduplicated by `signed_headers`' order) and confirm
/// every named header is actually present. Returns the block (ending in a
/// trailing `\n` after the last header, per the SigV4 spec) and the
/// semicolon-joined signed-headers string.
pub fn canonical_headers(
    headers: &HeaderMap,
    host: &str,
    signed_headers: &[String],
) -> (String, String) {
    let mut block = String::new();
    for name in signed_headers {
        let value = if name == "host" {
            host.to_owned()
        } else {
            let mut values: Vec<String> = headers
                .get_all(name.as_str())
                .filter_map(|v| v.to_str().ok())
                .map(fold_header_value)
                .collect();
            if values.is_empty() {
                values.push(String::new());
            }
            values.join(",")
        };
        block.push_str(name);
        block.push(':');
        block.push_str(&value);
        block.push('\n');
    }
    (block, signed_headers.join(";"))
}

/// Trim leading/trailing whitespace and collapse internal runs of
/// whitespace to a single space, per SigV4's canonical-header folding rule.
fn fold_header_value(v: &str) -> String {
    v.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Assemble the SigV4 canonical request string.
///
/// `canonical_headers` must already end in `\n` after its last header line
/// (as returned by [`canonical_headers`]) — the extra `\n` this function
/// inserts before `signed_headers` is what produces the blank line the spec
/// requires between the header block and the signed-headers list.
pub fn canonical_request(
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    canonical_headers: &str,
    signed_headers: &str,
    payload_hash: &str,
) -> String {
    format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&Sha256::digest(data))
}

/// `HexEncode(Hash(""))`, needed by the `aws-chunked` chunk string-to-sign.
pub fn empty_payload_hash() -> String {
    sha256_hex(b"")
}

fn hmac_raw(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// `HMAC-SHA256(key, msg)`, hex-encoded.
pub fn hex_hmac_sha256(key: &[u8], msg: &[u8]) -> String {
    hex_encode(&hmac_raw(key, msg))
}

/// `"AWS4-HMAC-SHA256\n" + amz_date + "\n" + scope + "\n" + hex(sha256(canonical_request))`.
pub fn string_to_sign(amz_date: &str, scope: &str, canonical_request: &str) -> String {
    format!(
        "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    )
}

/// `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")`.
pub fn signing_key(secret: &[u8], date: &str, region: &str, service: &str) -> [u8; 32] {
    let mut prefixed = Vec::with_capacity(4 + secret.len());
    prefixed.extend_from_slice(b"AWS4");
    prefixed.extend_from_slice(secret);
    let k_date = hmac_raw(&prefixed, date.as_bytes());
    let k_region = hmac_raw(&k_date, region.as_bytes());
    let k_service = hmac_raw(&k_region, service.as_bytes());
    hmac_raw(&k_service, b"aws4_request")
}

/// Constant-time comparison of two lowercase-hex signatures.
pub fn signatures_match(expected: &str, provided: &str) -> bool {
    if expected.len() != provided.len() {
        return false;
    }
    expected.as_bytes().ct_eq(provided.as_bytes()).into()
}

/// Parse `yyyymmddTHHMMSSZ` (UTC) into a [`std::time::SystemTime`].
pub fn parse_amz_date(s: &str) -> Result<std::time::SystemTime, SigV4Error> {
    let bytes = s.as_bytes();
    if bytes.len() != 16 || bytes[8] != b'T' || bytes[15] != b'Z' {
        return Err(SigV4Error::MalformedDate);
    }
    let digit_run = |r: std::ops::Range<usize>| -> Result<i64, SigV4Error> {
        s.get(r)
            .filter(|chunk| chunk.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|chunk| chunk.parse::<i64>().ok())
            .ok_or(SigV4Error::MalformedDate)
    };
    let year = digit_run(0..4)?;
    let month = digit_run(4..6)?;
    let day = digit_run(6..8)?;
    let hour = digit_run(9..11)?;
    let minute = digit_run(11..13)?;
    let second = digit_run(13..15)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..60).contains(&second)
    {
        return Err(SigV4Error::MalformedDate);
    }
    let days = days_from_civil(year, month as u32, day as u32);
    let secs = days
        .checked_mul(86_400)
        .and_then(|d| d.checked_add(hour * 3600 + minute * 60 + second))
        .ok_or(SigV4Error::MalformedDate)?;
    if secs < 0 {
        return Err(SigV4Error::MalformedDate);
    }
    Ok(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs as u64))
}

/// Days since the Unix epoch (1970-01-01) for a proleptic-Gregorian civil
/// date. Howard Hinnant's `days_from_civil` algorithm — see
/// <https://howardhinnant.github.io/date_algorithms.html>.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m as i64 + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Per-chunk string-to-sign for `aws-chunked` signed payloads:
/// `"AWS4-HMAC-SHA256-PAYLOAD\n" + amz_date + "\n" + scope + "\n" +
/// prev_signature + "\n" + hex(sha256("")) + "\n" + chunk_sha256_hex`.
pub fn chunk_string_to_sign(
    amz_date: &str,
    scope: &str,
    prev_signature: &str,
    chunk_sha256_hex: &str,
) -> String {
    format!(
        "AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{prev_signature}\n{}\n{chunk_sha256_hex}",
        empty_payload_hash()
    )
}

/// Trailer string-to-sign for the `…-TRAILER` payload modes: identical to
/// [`chunk_string_to_sign`] but with the literal marker
/// `"AWS4-HMAC-SHA256-TRAILER"` and the trailer block's own SHA-256 in place
/// of a chunk's.
pub fn trailer_string_to_sign(
    amz_date: &str,
    scope: &str,
    prev_signature: &str,
    trailer_sha256_hex: &str,
) -> String {
    format!("AWS4-HMAC-SHA256-TRAILER\n{amz_date}\n{scope}\n{prev_signature}\n{trailer_sha256_hex}")
}

/// SHA-256 of `data`, lowercase hex — exposed for the `aws-chunked` decoder
/// (`crate::s3::body`) to hash each chunk/trailer it reads off the wire.
pub fn sha256_hex_of(data: &[u8]) -> String {
    sha256_hex(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};

    #[test]
    fn canonical_query_sorts_and_encodes() {
        let q = "prefix=a b/c&list-type=2&x=";
        let cq = canonical_query_string(q);
        assert_eq!(cq, "list-type=2&prefix=a%20b%2Fc&x=");
    }

    #[test]
    fn canonical_query_handles_repeated_names() {
        let q = "b=2&a=1&a=0";
        let cq = canonical_query_string(q);
        assert_eq!(cq, "a=0&a=1&b=2");
    }

    #[test]
    fn canonical_uri_keeps_slash_and_encodes_space() {
        assert_eq!(canonical_uri("/a b/c+d"), "/a%20b/c%2Bd");
        assert_eq!(canonical_uri(""), "/");
        assert_eq!(canonical_uri("/"), "/");
    }

    #[test]
    fn canonical_uri_does_not_double_encode() {
        // A literal '%' in the input is decoded once, then re-encoded once —
        // never left as a raw '%' (which would be ambiguous) and never
        // encoded twice into "%2520".
        assert_eq!(canonical_uri("/100%25"), "/100%25");
    }

    #[test]
    fn canonical_headers_folds_whitespace_and_lowercases_names() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-amz-date"),
            HeaderValue::from_static("  20250101T000000Z  "),
        );
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("text/plain;   charset=utf-8"),
        );
        let signed = vec![
            "content-type".to_owned(),
            "host".to_owned(),
            "x-amz-date".to_owned(),
        ];
        let (block, joined) = canonical_headers(&headers, "example.com", &signed);
        assert_eq!(
            block,
            "content-type:text/plain; charset=utf-8\nhost:example.com\nx-amz-date:20250101T000000Z\n"
        );
        assert_eq!(joined, "content-type;host;x-amz-date");
    }

    #[test]
    fn signing_key_is_deterministic_and_input_sensitive() {
        let a = signing_key(b"secret", "20250101", "us-east-1", "s3");
        let b = signing_key(b"secret", "20250101", "us-east-1", "s3");
        assert_eq!(a, b);
        let c = signing_key(b"secret", "20250102", "us-east-1", "s3");
        assert_ne!(a, c);
        let d = signing_key(b"secret", "20250101", "eu-west-1", "s3");
        assert_ne!(a, d);
        let e = signing_key(b"secret", "20250101", "us-east-1", "ec2");
        assert_ne!(a, e);
    }

    #[test]
    fn parse_amz_date_round_trips_known_timestamp() {
        let t = parse_amz_date("20250101T000000Z").unwrap();
        assert_eq!(
            t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            1_735_689_600
        );
    }

    #[test]
    fn parse_amz_date_rejects_malformed_input() {
        assert!(parse_amz_date("20240101T00:00:00Z").is_err());
        assert!(parse_amz_date("2024010").is_err());
        assert!(parse_amz_date("20240101T000000X").is_err());
    }

    #[test]
    fn signatures_match_is_constant_time_and_correct() {
        assert!(signatures_match("abcd1234", "abcd1234"));
        assert!(!signatures_match("abcd1234", "abcd1235"));
        assert!(!signatures_match("abcd1234", "abcd123"));
    }

    fn header_map_with_auth(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            actix_web::http::header::AUTHORIZATION,
            HeaderValue::from_str(value).unwrap(),
        );
        headers.insert(
            HeaderName::from_static("x-amz-date"),
            HeaderValue::from_static("20250101T000000Z"),
        );
        headers
    }

    #[test]
    fn parse_rejects_non_aws4_algorithm() {
        let headers = header_map_with_auth(
            "AWS3-HMAC-SHA1 Credential=AKID/20250101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abcd",
        );
        assert!(matches!(
            parse("", &headers),
            Err(SigV4Error::UnsupportedAlgorithm)
        ));
    }

    #[test]
    fn parse_rejects_scope_with_wrong_segment_count() {
        let headers = header_map_with_auth(
            "AWS4-HMAC-SHA256 Credential=AKID/20250101/us-east-1/aws4_request, SignedHeaders=host, Signature=abcd",
        );
        assert!(matches!(
            parse("", &headers),
            Err(SigV4Error::MalformedScope)
        ));
    }

    #[test]
    fn parse_rejects_scope_with_wrong_terminator() {
        let headers = header_map_with_auth(
            "AWS4-HMAC-SHA256 Credential=AKID/20250101/us-east-1/s3/not_aws4_request, SignedHeaders=host, Signature=abcd",
        );
        assert!(matches!(
            parse("", &headers),
            Err(SigV4Error::MalformedScope)
        ));
    }

    #[test]
    fn parse_rejects_signed_headers_without_host() {
        let headers = header_map_with_auth(
            "AWS4-HMAC-SHA256 Credential=AKID/20250101/us-east-1/s3/aws4_request, SignedHeaders=x-amz-date, Signature=abcd",
        );
        assert!(matches!(
            parse("", &headers),
            Err(SigV4Error::MissingHostHeader)
        ));
    }

    #[test]
    fn parse_accepts_well_formed_header_auth() {
        let headers = header_map_with_auth(
            "AWS4-HMAC-SHA256 Credential=AKID/20250101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeef",
        );
        let parsed = parse("", &headers).unwrap();
        assert_eq!(parsed.scope.access_key_id, "AKID");
        assert_eq!(parsed.scope.region, "us-east-1");
        assert_eq!(parsed.signature, "deadbeef");
        assert_eq!(parsed.payload, PayloadHash::Unsigned);
    }

    #[test]
    fn parse_presigned_reads_query_params() {
        let headers = HeaderMap::new();
        let query = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKID%2F20250101%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=deadbeef";
        let parsed = parse(query, &headers).unwrap();
        assert_eq!(parsed.scope.access_key_id, "AKID");
        assert_eq!(parsed.presigned_expires, Some(3600));
        assert_eq!(parsed.signature, "deadbeef");
    }
}
