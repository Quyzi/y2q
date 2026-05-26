//! Parse `X-Y2Q-<label>` request headers into a label map.
//!
//! Reserved names emitted by the server on HEAD (`created`, `modified`,
//! `checksum-gxhash`) cannot be supplied by clients on PUT.

use std::collections::BTreeSet;

use actix_web::HttpRequest;
use y2q_core::Error as CoreError;

use crate::config::LabelLimits;
use crate::error::AppError;

const HEADER_PREFIX: &str = "x-y2q-";
/// Server-emitted metadata header names that clients may not supply on PUT.
/// Used by HEAD to surface object state; sending these on a PUT yields 400.
const RESERVED: &[&str] = &["created", "modified", "checksum-gxhash"];
/// Header names in the `X-Y2Q-` namespace that are consumed by dedicated
/// handler logic and must not be persisted as user labels. The extractor
/// silently skips them — the relevant handler parses them separately.
const CONSUMED_BY_HANDLER: &[&str] = &["sync"];

/// Extract custom labels from `X-Y2Q-<name>` request headers.
///
/// - Header names are lowercased; the `x-y2q-` prefix is stripped.
/// - Names matching any reserved system header (case-insensitive) cause a
///   400 [`Error::ReservedLabel`].
/// - Non-UTF-8 values cause 400 [`Error::InvalidLabelValue`].
/// - Names and values exceeding the configured limits cause 400 errors.
/// - The same name may be sent multiple times with different values; every
///   distinct `(name, value)` pair is kept. Exact duplicates collapse.
///
/// [`Error::ReservedLabel`]: y2q_core::Error::ReservedLabel
/// [`Error::InvalidLabelValue`]: y2q_core::Error::InvalidLabelValue
pub fn extract_labels(
    req: &HttpRequest,
    limits: &LabelLimits,
) -> Result<BTreeSet<(String, String)>, AppError> {
    let mut out: BTreeSet<(String, String)> = BTreeSet::new();
    for (name, value) in req.headers().iter() {
        let lower = name.as_str().to_ascii_lowercase();
        let Some(label) = lower.strip_prefix(HEADER_PREFIX) else {
            continue;
        };
        if label.is_empty() {
            continue;
        }
        if CONSUMED_BY_HANDLER.contains(&label) {
            // Skip silently — the put handler parses these separately. A
            // value-level error (e.g. malformed `X-Y2Q-Sync`) is surfaced
            // there, not here.
            continue;
        }
        if RESERVED.contains(&label) {
            return Err(AppError(CoreError::ReservedLabel {
                name: label.to_owned(),
            }));
        }
        if label.len() > limits.max_label_name_bytes {
            return Err(AppError(CoreError::LabelNameTooLong {
                name: label.to_owned(),
            }));
        }
        let value_str = value.to_str().map_err(|_| {
            AppError(CoreError::InvalidLabelValue {
                name: label.to_owned(),
            })
        })?;
        if value_str.len() > limits.max_label_value_bytes {
            return Err(AppError(CoreError::LabelValueTooLong {
                name: label.to_owned(),
            }));
        }
        out.insert((label.to_owned(), value_str.to_owned()));
    }
    if out.len() > limits.max_labels {
        return Err(AppError(CoreError::TooManyLabels { count: out.len() }));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    fn limits() -> LabelLimits {
        LabelLimits {
            max_labels: 4,
            max_label_name_bytes: 16,
            max_label_value_bytes: 32,
        }
    }

    #[test]
    fn extracts_lowercased_labels() {
        let req = TestRequest::default()
            .insert_header(("X-Y2Q-Env", "prod"))
            .insert_header(("X-Y2Q-Owner", "alice"))
            .to_http_request();
        let labels = extract_labels(&req, &limits()).unwrap();
        assert!(labels.contains(&("env".to_owned(), "prod".to_owned())));
        assert!(labels.contains(&("owner".to_owned(), "alice".to_owned())));
    }

    #[test]
    fn keeps_repeated_name_with_different_values() {
        let req = TestRequest::default()
            .append_header(("X-Y2Q-Env", "prod"))
            .append_header(("X-Y2Q-Env", "stage"))
            .to_http_request();
        let labels = extract_labels(&req, &limits()).unwrap();
        assert!(labels.contains(&("env".to_owned(), "prod".to_owned())));
        assert!(labels.contains(&("env".to_owned(), "stage".to_owned())));
        assert_eq!(labels.len(), 2);
    }

    #[test]
    fn ignores_unrelated_headers() {
        let req = TestRequest::default()
            .insert_header(("Content-Type", "application/octet-stream"))
            .to_http_request();
        let labels = extract_labels(&req, &limits()).unwrap();
        assert!(labels.is_empty());
    }

    #[test]
    fn skips_handler_consumed_sync_header() {
        // X-Y2Q-Sync is consumed by the put handler, not stored as a label.
        // The extractor must silently drop it (not error, not persist).
        let req = TestRequest::default()
            .insert_header(("X-Y2Q-Sync", "best-effort"))
            .insert_header(("X-Y2Q-env", "prod"))
            .to_http_request();
        let labels = extract_labels(&req, &limits()).unwrap();
        assert!(!labels.iter().any(|(n, _)| n == "sync"));
        assert!(labels.contains(&("env".to_owned(), "prod".to_owned())));
    }

    #[test]
    fn rejects_each_reserved_name_case_insensitively() {
        for header in ["X-Y2Q-Created", "X-Y2Q-Modified", "X-Y2Q-checksum-gxhash"] {
            let req = TestRequest::default()
                .insert_header((header, "1"))
                .to_http_request();
            let err = extract_labels(&req, &limits()).unwrap_err();
            assert!(
                matches!(err.0, CoreError::ReservedLabel { .. }),
                "expected ReservedLabel for {header}, got {:?}",
                err.0
            );
        }
    }

    #[test]
    fn rejects_too_many_labels() {
        let req = TestRequest::default()
            .insert_header(("X-Y2Q-a", "1"))
            .insert_header(("X-Y2Q-b", "2"))
            .insert_header(("X-Y2Q-c", "3"))
            .insert_header(("X-Y2Q-d", "4"))
            .insert_header(("X-Y2Q-e", "5"))
            .to_http_request();
        let err = extract_labels(&req, &limits()).unwrap_err();
        assert!(matches!(err.0, CoreError::TooManyLabels { .. }));
    }

    #[test]
    fn rejects_oversize_name() {
        let req = TestRequest::default()
            .insert_header(("X-Y2Q-aaaaaaaaaaaaaaaaa", "v"))
            .to_http_request();
        let err = extract_labels(&req, &limits()).unwrap_err();
        assert!(matches!(err.0, CoreError::LabelNameTooLong { .. }));
    }

    #[test]
    fn rejects_oversize_value() {
        let big = "x".repeat(33);
        let req = TestRequest::default()
            .insert_header(("X-Y2Q-env", big.as_str()))
            .to_http_request();
        let err = extract_labels(&req, &limits()).unwrap_err();
        assert!(matches!(err.0, CoreError::LabelValueTooLong { .. }));
    }
}
