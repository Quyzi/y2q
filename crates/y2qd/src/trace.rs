use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use actix_web::{
    Error, HttpMessage, HttpResponse,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    middleware::Next,
    web,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::auth::AdminReadAuthenticated;
use crate::request_id::RequestIdExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    pub request_id: String,
    pub timestamp_ns: u64,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub latency_ms: f64,
    pub req_bytes: Option<u64>,
    pub resp_bytes: Option<u64>,
    pub remote_addr: Option<String>,
}

pub struct TraceHub {
    tx: broadcast::Sender<TraceEvent>,
}

impl TraceHub {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1024);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<TraceEvent> {
        self.tx.subscribe()
    }

    pub fn publish(&self, event: TraceEvent) {
        let _ = self.tx.send(event);
    }

    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

/// Middleware that publishes a `TraceEvent` to the `TraceHub` after each request.
/// Zero overhead when no client is connected (`receiver_count() == 0`).
pub async fn trace_middleware<B: MessageBody>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error> {
    let hub = req.app_data::<web::Data<Arc<TraceHub>>>().cloned();
    let req_bytes = content_length(req.headers());
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    let remote_addr = req.peer_addr().map(|a| a.to_string());
    let request_id = req
        .extensions()
        .get::<RequestIdExt>()
        .map(|r| r.0.clone())
        .unwrap_or_default();
    let started = Instant::now();

    let res = next.call(req).await?;

    if let Some(hub) = hub
        && hub.receiver_count() > 0
    {
        let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
        let status = res.status().as_u16();
        let resp_bytes = content_length(res.headers());
        let timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        hub.publish(TraceEvent {
            request_id,
            timestamp_ns,
            method,
            path,
            status,
            latency_ms: elapsed_ms,
            req_bytes,
            resp_bytes,
            remote_addr,
        });
    }
    Ok(res)
}

/// `GET /api/v1/trace` — streams live trace events as Server-Sent Events.
pub async fn stream(hub: web::Data<Arc<TraceHub>>, _auth: AdminReadAuthenticated) -> HttpResponse {
    let rx = hub.subscribe();
    let event_stream = futures::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let json = serde_json::to_string(&event).unwrap_or_default();
                    let bytes = Bytes::from(format!("data: {json}\n\n"));
                    return Some((Ok::<_, actix_web::Error>(bytes), rx));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    HttpResponse::Ok()
        .content_type("text/event-stream")
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("X-Accel-Buffering", "no"))
        .streaming(event_stream)
}

fn content_length(headers: &header::HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()
}
