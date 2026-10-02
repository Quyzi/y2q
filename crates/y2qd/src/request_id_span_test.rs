//! The root span reads `RequestIdExt` when `TracingLogger` builds it.
//! Actix runs the last `.wrap()` first, so `request_id` has to be
//! registered after the logger. These apps use that order for both
//! listeners (see `main`).

use std::sync::{Arc, Mutex};

use actix_web::body::MessageBody;
use actix_web::dev::{Service, ServiceResponse};
use actix_web::middleware::from_fn;
use actix_web::test::{self, TestRequest};
use actix_web::{App, web};
use tracing::Subscriber;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing_actix_web::TracingLogger;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;

use crate::observability;
use crate::request_id;
use crate::s3;
use crate::span::Y2qRootSpanBuilder;
use crate::trace;

const NATIVE_REQUEST_ID: &str = "0123456789abcdef0123456789abcdef";
const S3_REQUEST_ID: &str = "fedcba9876543210fedcba9876543210";

struct RequestIdSpanLayer {
    ids: Arc<Mutex<Vec<String>>>,
}

struct RequestIdVisitor<'a> {
    ids: &'a mut Vec<String>,
}

impl Visit for RequestIdVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "request_id" {
            self.ids.push(format!("{value:?}"));
        }
    }
}

impl<S> Layer<S> for RequestIdSpanLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(
        &self,
        attrs: &Attributes<'_>,
        _id: &Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut ids = self.ids.lock().expect("request id span lock");
        attrs.record(&mut RequestIdVisitor { ids: &mut ids });
    }

    fn on_record(
        &self,
        _id: &Id,
        values: &Record<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut ids = self.ids.lock().expect("request id span lock");
        values.record(&mut RequestIdVisitor { ids: &mut ids });
    }
}

async fn assert_echo_and_span<S, R, B>(app: &S, req: R, known: &str, seen: &Mutex<Vec<String>>)
where
    S: Service<R, Response = ServiceResponse<B>, Error = actix_web::Error>,
    B: MessageBody,
{
    seen.lock().expect("request id span lock").clear();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "health probe failed");
    let echoed = resp
        .headers()
        .get("x-request-id")
        .expect("response echoes X-Request-ID")
        .to_str()
        .expect("X-Request-ID is valid header text");
    assert_eq!(echoed, known);
    let recorded = seen.lock().expect("request id span lock");
    assert!(
        recorded.iter().any(|id| id == known),
        "root span request_id fields were {recorded:?}, want {known}"
    );
    assert!(
        recorded.iter().all(|id| !id.is_empty()),
        "root span recorded an empty request_id: {recorded:?}"
    );
}

fn probe(known: &str) -> TestRequest {
    TestRequest::get()
        .uri("/health")
        .insert_header(("x-request-id", known))
}

/// Native listener order, outer to inner: trace, metrics, request_id, logger.
#[test]
fn root_span_records_inbound_request_id() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(RequestIdSpanLayer {
        ids: Arc::clone(&seen),
    });

    tracing::subscriber::with_default(subscriber, || {
        actix_web::rt::System::new().block_on(async {
            let native = test::init_service(
                App::new()
                    .wrap(TracingLogger::<Y2qRootSpanBuilder>::new())
                    .wrap(from_fn(request_id::request_id_middleware))
                    .wrap(from_fn(observability::metrics_middleware))
                    .wrap(from_fn(trace::trace_middleware))
                    .route("/health", web::get().to(|| async { "ok" })),
            )
            .await;
            assert_echo_and_span(
                &native,
                probe(NATIVE_REQUEST_ID).to_request(),
                NATIVE_REQUEST_ID,
                &seen,
            )
            .await;

            // S3 listener order, outer to inner: vhost, trace, metrics,
            // request_id, logger, error_detail.
            let s3_app = test::init_service(
                App::new()
                    .wrap(from_fn(s3::routes::error_detail_middleware))
                    .wrap(TracingLogger::<Y2qRootSpanBuilder>::new())
                    .wrap(from_fn(request_id::request_id_middleware))
                    .wrap(from_fn(observability::metrics_middleware))
                    .wrap(from_fn(trace::trace_middleware))
                    .wrap(from_fn(s3::routes::vhost_middleware))
                    .route("/health", web::get().to(|| async { "ok" })),
            )
            .await;
            assert_echo_and_span(
                &s3_app,
                probe(S3_REQUEST_ID).to_request(),
                S3_REQUEST_ID,
                &seen,
            )
            .await;
        });
    });
}
