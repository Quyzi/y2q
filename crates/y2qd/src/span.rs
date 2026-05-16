use actix_web::{
    Error, HttpMessage,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
};
use tracing::Span;
use tracing_actix_web::{DefaultRootSpanBuilder, RootSpanBuilder, root_span};

use crate::request_id::RequestIdExt;

/// Custom [`RootSpanBuilder`] that adds `request_id` and `remote.addr` to
/// every request span, and emits structured INFO/ERROR log events at request
/// start and completion.
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

        tracing::info!(
            parent: &span,
            method = %request.method(),
            path = %request.path(),
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

        if status >= 500 {
            tracing::error!(parent: &span, status, "request failed");
        } else {
            tracing::info!(parent: &span, status, "request complete");
        }

        DefaultRootSpanBuilder::on_request_end(span, outcome);
    }
}
