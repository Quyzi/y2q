//! IP-keyed rate limiting for the unauthenticated login endpoint.
//!
//! [`auth::state::LoginAttempts`](crate::auth::state::LoginAttempts) locks out
//! a *username* after repeated failures, but every request still pays a full
//! Argon2id hash before that check can even apply — and an attacker who
//! varies the username on each request never triggers any single username's
//! lockout. This middleware adds a source-IP-keyed cap in front of the
//! handler so a flood of distinct-username login attempts from one client is
//! throttled regardless of what username each request claims.

use std::sync::LazyLock;

use actix_governor::governor::middleware::NoOpMiddleware;
use actix_governor::{
    GovernorConfig, GovernorConfigBuilder, KeyExtractor, SimpleKeyExtractionError,
};
use actix_web::dev::ServiceRequest;

/// Keys the rate limiter by the caller's real IP address (proxy-aware via
/// `Forwarded`/`X-Forwarded-For`, see [`actix_web::dev::ConnectionInfo`]),
/// not by username — the per-username lockout already exists separately and
/// is exactly what a varying-username flood bypasses.
#[derive(Clone)]
pub struct RealIpKeyExtractor;

impl KeyExtractor for RealIpKeyExtractor {
    type Key = String;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        Ok(req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("unknown")
            .to_owned())
    }
}

/// Rate-limit config for `/api/v1/auth/login`: bursts of up to 5 requests per
/// source IP, replenishing one every 4 seconds thereafter. A process-wide
/// static so every worker shares one rate-limiter state instead of each
/// worker getting its own independent quota (which would multiply the
/// effective limit by the worker count).
pub static LOGIN_GOVERNOR_CONFIG: LazyLock<GovernorConfig<RealIpKeyExtractor, NoOpMiddleware>> =
    LazyLock::new(|| {
        let mut builder = GovernorConfigBuilder::default();
        let mut builder = builder.key_extractor(RealIpKeyExtractor);
        builder.burst_size(5).seconds_per_request(4);
        builder.finish().expect("valid governor config")
    });

#[cfg(test)]
mod tests {
    use super::*;
    use actix_governor::Governor;
    use actix_web::{App, HttpResponse, test, web};
    use std::net::SocketAddr;

    async fn ok() -> HttpResponse {
        HttpResponse::Ok().finish()
    }

    #[actix_web::test]
    async fn limits_by_source_ip_regardless_of_request_body() {
        // A tight local config (burst 2) so the test doesn't need to send
        // dozens of requests; the extractor and wiring under test are
        // identical to the production `LOGIN_GOVERNOR_CONFIG`.
        let mut builder = GovernorConfigBuilder::default();
        let mut builder = builder.key_extractor(RealIpKeyExtractor);
        builder.burst_size(2).seconds_per_request(60);
        let config = builder.finish().expect("valid governor config");

        let app = test::init_service(
            App::new()
                .wrap(Governor::new(&config))
                .route("/login", web::post().to(ok)),
        )
        .await;

        let attacker: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        for _ in 0..2 {
            let req = test::TestRequest::post()
                .uri("/login")
                .peer_addr(attacker)
                .to_request();
            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);
        }

        // Burst exhausted for this source IP — simulating a fresh username on
        // every request (which the per-username lockout can't see) does not
        // help, because the limiter is keyed by IP, not by request content.
        let req = test::TestRequest::post()
            .uri("/login")
            .peer_addr(attacker)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 429);

        // A different source IP is unaffected by the first IP's burst.
        let other: SocketAddr = "10.0.0.2:12345".parse().unwrap();
        let req = test::TestRequest::post()
            .uri("/login")
            .peer_addr(other)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
    }
}
