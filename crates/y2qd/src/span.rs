use actix_web::{
    Error, HttpMessage,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
};
use tracing::Span;
use tracing_actix_web::{RootSpanBuilder, root_span};

use crate::request_id::RequestIdExt;

/// Custom [`RootSpanBuilder`] that adds `request_id` and `remote.addr` to
/// every request span, and emits structured INFO/ERROR log events at request
/// start and completion.
///
/// Unlike the default builder, this implementation never writes bucket names,
/// object keys, or other user-supplied path segments to structured logs.
pub struct Y2qRootSpanBuilder;

impl RootSpanBuilder for Y2qRootSpanBuilder {
    fn on_request_start(request: &ServiceRequest) -> Span {
        let request_id = request
            .extensions()
            .get::<RequestIdExt>()
            .map(|r| r.0.clone())
            .unwrap_or_default();

        let remote_addr = request
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();

        let span = root_span!(
            request,
            request_id = %request_id,
            remote.addr = %remote_addr,
        );

        // Overwrite the literal request URI set by root_span! so that bucket
        // names and object keys never appear as span context in log output.
        span.record("http.target", "[redacted]");

        tracing::info!(
            parent: &span,
            method = %request.method(),
            remote.addr = %remote_addr,
            request_id = %request_id,
            "request received"
        );

        span
    }

    fn on_request_end<B: MessageBody>(span: Span, outcome: &Result<ServiceResponse<B>, Error>) {
        let status = outcome
            .as_ref()
            .map(|r| r.status().as_u16())
            .unwrap_or(500u16);

        if let Ok(response) = outcome {
            let s = response.status();
            span.record(
                "otel.status_code",
                if s.is_server_error() { "ERROR" } else { "OK" },
            );
            span.record("http.status_code", status);
            if response.response().error().is_some() {
                // Record only the error class — not Display/Debug of the error
                // type, which may embed bucket names or object keys.
                span.record("exception.message", error_kind_label(status));
            }
        } else {
            span.record("otel.status_code", "ERROR");
        }

        if status >= 500 {
            tracing::error!(parent: &span, status, "request failed");
        } else {
            tracing::info!(parent: &span, status, "request complete");
        }
        // Intentionally do NOT call DefaultRootSpanBuilder::on_request_end:
        // it logs exception.message (Display) and exception.details (Debug)
        // which contain bucket names and object keys from CoreError variants.
    }
}

fn error_kind_label(status: u16) -> &'static str {
    match status {
        400 => "bad request",
        401 => "unauthorized",
        403 => "forbidden",
        404 => "not found",
        409 => "conflict",
        413 => "payload too large",
        500 => "internal server error",
        501 => "not implemented",
        503 => "service unavailable",
        _ => "request failed",
    }
}
