use actix_web::{
    Error, HttpMessage,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    http::header::{HeaderName, HeaderValue},
    middleware::Next,
};

/// Request-scoped extension holding the assigned request ID.
#[derive(Clone)]
pub struct RequestIdExt(pub String);

/// Middleware that assigns a `request_id` to every request.
///
/// Reads `X-Request-ID` from the incoming headers and reuses it if present;
/// otherwise generates a UUID v4. The ID is stored as a request extension so
/// downstream middleware and handlers can retrieve it, and echoed back on the
/// response via the `X-Request-ID` header.
pub async fn request_id_middleware<B: MessageBody>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error> {
    let id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    req.extensions_mut().insert(RequestIdExt(id.clone()));

    let mut res = next.call(req).await?;

    if let Ok(val) = HeaderValue::from_str(&id) {
        res.headers_mut()
            .insert(HeaderName::from_static("x-request-id"), val);
    }

    Ok(res)
}
