//! Route table and virtual-hosted-addressing middleware for the S3
//! gateway's second listener.
//!
//! Sub-resource dispatch (`?tagging`, `?uploadId=`, `?list-type=`, ...)
//! happens inside each handler on the query string, because actix cannot
//! route on query parameters — see [`SubResource`].

use std::collections::HashMap;

use actix_web::body::{EitherBody, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header;
use actix_web::middleware::Next;
use actix_web::{HttpMessage, ResponseError, web};

use crate::request_id::RequestIdExt;
use crate::s3::auth::OriginalUri;
use crate::s3::object;
use crate::s3::sigv4::percent_decode;
use crate::s3::state::S3State;

/// Presence-and-value view of the S3 sub-resource query parameters
/// (`?location`, `?uploadId=...`, `?list-type=2`, ...). Values are
/// percent-decoded; keys are not (sub-resource names are always plain
/// ASCII identifiers).
pub struct SubResource {
    params: HashMap<String, String>,
}

impl SubResource {
    pub fn parse(raw: &str) -> Self {
        let mut params = HashMap::new();
        for pair in raw.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            params.insert(k.to_owned(), percent_decode(v));
        }
        Self { params }
    }

    pub fn has(&self, name: &str) -> bool {
        self.params.contains_key(name)
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }
}

/// Register the S3 gateway's routes on `cfg`.
///
/// Routes are added incrementally as their handlers are implemented; a verb
/// reaching a registered resource with no matching route yields actix's
/// default 405, which is the correct S3 answer for an unsupported method on
/// a valid resource.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/api/v1/s3/credentials")
            .wrap(actix_governor::Governor::new(
                &crate::rate_limit::S3_CREDENTIAL_GOVERNOR_CONFIG,
            ))
            .route(web::post().to(crate::s3::credentials::mint))
            .route(web::get().to(crate::s3::credentials::list)),
    );
    cfg.service(
        web::resource("/api/v1/s3/credentials/{access_key_id}")
            .route(web::delete().to(crate::s3::credentials::revoke)),
    );
    cfg.service(web::resource("/").route(web::get().to(crate::s3::service::list_buckets)));
    cfg.service(
        web::resource("/{bucket}")
            .route(web::get().to(crate::s3::bucket::get))
            .route(web::head().to(crate::s3::bucket::head))
            .route(web::put().to(crate::s3::bucket::put))
            .route(web::post().to(crate::s3::bucket::post))
            .route(web::delete().to(crate::s3::bucket::delete)),
    );
    cfg.service(
        web::resource("/{bucket}/")
            .route(web::get().to(crate::s3::bucket::get))
            .route(web::head().to(crate::s3::bucket::head))
            .route(web::put().to(crate::s3::bucket::put))
            .route(web::post().to(crate::s3::bucket::post))
            .route(web::delete().to(crate::s3::bucket::delete)),
    );
    cfg.service(
        web::resource("/{bucket}/{key}*")
            .route(web::get().to(object::get))
            .route(web::head().to(object::head))
            .route(web::put().to(object::put))
            .route(web::post().to(object::post))
            .route(web::delete().to(object::delete)),
    );
}

/// When `[s3] virtual_host_domain` is set and `Host` is
/// `<bucket>.<domain>[:port]`, rewrite the request path to
/// `/<bucket><original-path>` so the path-style routes above match.
///
/// Stores the pre-rewrite path in request extensions as [`OriginalUri`]
/// unconditionally (even when no rewrite happens), so the SigV4 extractor
/// has one code path — the client always signs the URI it actually sent.
pub async fn vhost_middleware<B: MessageBody>(
    mut req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, actix_web::Error> {
    let original_path = req.path().to_owned();

    let domain = req
        .app_data::<web::Data<S3State>>()
        .map(|s| s.config.virtual_host_domain.clone())
        .unwrap_or_default();

    if !domain.is_empty()
        && let Some(host) = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    {
        let host_only = host.split(':').next().unwrap_or(&host);
        let suffix = format!(".{domain}");
        if let Some(bucket) = host_only.strip_suffix(suffix.as_str())
            && !bucket.is_empty()
            && bucket
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            let new_path_and_query = match req.uri().query() {
                Some(q) => format!("/{bucket}{original_path}?{q}"),
                None => format!("/{bucket}{original_path}"),
            };
            if let Ok(pq) = new_path_and_query.parse::<actix_web::http::uri::PathAndQuery>() {
                let mut parts = req.uri().clone().into_parts();
                parts.path_and_query = Some(pq);
                if let Ok(new_uri) = actix_web::http::Uri::from_parts(parts) {
                    req.head_mut().uri = new_uri;
                }
            }
        }
    }

    req.extensions_mut().insert(OriginalUri(original_path));
    next.call(req).await
}

/// Funnel every S3-gateway error response through one place that fills in
/// the daemon's own request id (matching the `X-Request-ID` header every
/// other middleware already stamps) and the resource path the error
/// concerns — so almost-every S3 error no longer ships a random,
/// unlogged `x-amz-request-id` and an empty `<Resource>`.
///
/// `request_id` middleware is wrapped outside this one so the root span
/// can see [`RequestIdExt`] when it is built. That middleware stamps
/// `X-Request-ID` only after `next.call` returns, which is after this
/// middleware has already rendered the error body, so the id comes from
/// the request extension. The response header is a fallback for callers
/// that still wrap `request_id` inside this middleware.
pub async fn error_detail_middleware<B: MessageBody + 'static>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<B>>, actix_web::Error> {
    let resource = req.path().to_owned();
    let res = next.call(req).await?;

    let Some(s3_err) = res
        .response()
        .error()
        .and_then(|e| e.as_error::<crate::s3::error::S3Error>())
    else {
        return Ok(res.map_into_left_body());
    };
    let from_ext = res
        .request()
        .extensions()
        .get::<RequestIdExt>()
        .map(|id| id.0.clone())
        .filter(|id| !id.is_empty());
    let from_header = res
        .response()
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|id| !id.is_empty())
        .map(str::to_owned);
    let request_id = from_ext.or(from_header).unwrap_or_default();
    let filled = s3_err
        .clone()
        .with_request_id(request_id.clone())
        .with_resource(resource);
    let mut error_resp = filled.error_response();
    // `into_response` replaces the whole response. Re-stamp `X-Request-ID`
    // here: `request_id` middleware is outside this one and has not set
    // the header yet, and the replacement would drop it anyway.
    if let Ok(val) = actix_web::http::header::HeaderValue::from_str(&request_id) {
        error_resp.headers_mut().insert(
            actix_web::http::header::HeaderName::from_static("x-request-id"),
            val,
        );
    }
    Ok(res.into_response(error_resp.map_into_right_body()))
}
