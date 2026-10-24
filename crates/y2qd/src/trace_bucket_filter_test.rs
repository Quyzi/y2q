//! `GET /api/v1/trace` must not stream bucket/object events for buckets the
//! tracer's persona cannot already read (same sealed-grant rule as `GET /`).
//!
//! `y2qd` is binary-only, so this is an in-process module declared from
//! `main.rs`. Sessions are minted the way login does: persona is the user's
//! `primary_slot`, and the session holds that slot's real identity secret.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use actix_web::body::{BoxBody, MessageBody};
use actix_web::middleware::from_fn;
use actix_web::test::{self, TestRequest};
use actix_web::{App, HttpResponse, web};
use futures_util::future::poll_fn;
use y2q_core::crypto::{Argon2Params, Role, SlotPayload, UserRecord, UserStore, kdf};
use y2q_core::secmem::SecretVec;
use y2q_core::{AnyStorage, FilesystemStorage, SyncLevel};

use crate::auth::AuthState;
use crate::auth::session::NewSession;
use crate::config::{Argon2Config, AuthConfig, EncryptionParams, LabelLimits};
use crate::handlers;
use crate::trace::{self, TraceEvent, TraceHub};

const OBJECT_BYTES: &[u8] = b"trace-filter-plaintext";

struct Account {
    username: String,
    role: Role,
    persona: u8,
    identity_sk: SecretVec,
}

struct Harness {
    _storage_dir: tempfile::TempDir,
    _user_dir: tempfile::TempDir,
    storage: web::Data<Arc<AnyStorage>>,
    auth_state: web::Data<AuthState>,
    hub: web::Data<Arc<TraceHub>>,
}

impl Harness {
    fn new(enforce_authorization: bool) -> Self {
        let storage_dir = tempfile::TempDir::new().unwrap();
        let fs = FilesystemStorage::new(
            storage_dir.path().join("data"),
            storage_dir.path().join("index.redb"),
        )
        .unwrap();
        let node_key = [9u8; 32];
        fs.install_node_key(&node_key);
        let storage: Arc<AnyStorage> = Arc::new(AnyStorage::Filesystem(fs));

        let user_dir = tempfile::TempDir::new().unwrap();
        let user_store = UserStore::open(&user_dir.path().join("users.redb"), &node_key).unwrap();
        let auth_config = AuthConfig {
            default_ttl_seconds: 3600,
            max_ttl_seconds: 86_400,
            session_sweep_interval_seconds: 300,
            min_login_response_ms: 0,
            max_failed_logins: 10,
            lockout_seconds: 900,
            enforce_authorization,
            max_refreshes: 0,
        };
        let argon2 = Argon2Config {
            m_cost_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        };
        let auth_state = AuthState::new(user_store, auth_config, argon2).unwrap();

        Self {
            _storage_dir: storage_dir,
            _user_dir: user_dir,
            storage: web::Data::new(storage),
            auth_state: web::Data::new(auth_state),
            hub: web::Data::new(Arc::new(TraceHub::new())),
        }
    }

    fn add_account(&self, username: &str, role: Role) -> Account {
        let params = Argon2Params::with_random_salt(8 * 1024, 1, 1);
        let password = b"test-password";
        let (slots, primary) =
            kdf::new_slots_random(username, password, &params, role, false).unwrap();
        let kek = params.derive_kek(password).unwrap();
        let aad = kdf::slot_wrap_aad(username, primary);
        let opened = kdf::unwrap_slot(&slots[primary].wrapped, &kek, &aad).unwrap();
        let payload = SlotPayload::from_bytes(&opened).unwrap();
        let record = UserRecord {
            username: username.to_owned(),
            created_at: 1,
            last_login: None,
            kdf: params,
            slots,
            primary_slot: primary as u8,
            role,
        };
        self.auth_state.user_store.upsert(&record).unwrap();
        Account {
            username: username.to_owned(),
            role,
            persona: primary as u8,
            identity_sk: payload.identity_sk,
        }
    }

    fn bearer(&self, account: &Account) -> String {
        let token = self
            .auth_state
            .sessions
            .insert(NewSession {
                username: account.username.clone(),
                role: account.role,
                created_at: SystemTime::now(),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
                persona: account.persona,
                revoke_other_sessions: false,
                identity_sk: SecretVec::from_slice(&account.identity_sk).unwrap(),
            })
            .unwrap();
        format!("Bearer {}", token.0.expose())
    }
}

macro_rules! build_app {
    ($harness:expr) => {
        test::init_service(
            App::new()
                .wrap(from_fn(trace::trace_middleware))
                .app_data($harness.hub.clone())
                .app_data($harness.storage.clone())
                .app_data($harness.auth_state.clone())
                .app_data(web::Data::new(LabelLimits {
                    max_labels: 32,
                    max_label_name_bytes: 64,
                    max_label_value_bytes: 1024,
                }))
                .app_data(web::Data::new(SyncLevel::Durable))
                .app_data(web::Data::new(EncryptionParams {
                    chunk_size_bytes: 4 * 1024 * 1024,
                    max_body_bytes: 8 * 1024 * 1024,
                }))
                .configure(handlers::configure),
        )
        .await
    };
}

macro_rules! call {
    ($app:expr, $req:expr) => {{
        let resp = test::call_service(&$app, $req).await;
        let status = resp.status().as_u16();
        let body = test::read_body(resp).await;
        (status, body)
    }};
}

macro_rules! put_object {
    ($app:expr, $bearer:expr, $bucket:expr, $key:expr, $body:expr) => {{
        let req = TestRequest::put()
            .uri(&format!("/{}/{}", $bucket, $key))
            .insert_header(("authorization", $bearer.as_str()))
            .insert_header(("content-type", "application/octet-stream"))
            .set_payload($body.to_vec())
            .to_request();
        call!($app, req)
    }};
}

macro_rules! get_object {
    ($app:expr, $bearer:expr, $bucket:expr, $key:expr) => {{
        let req = TestRequest::get()
            .uri(&format!("/{}/{}", $bucket, $key))
            .insert_header(("authorization", $bearer.as_str()))
            .to_request();
        call!($app, req)
    }};
}

macro_rules! put_acl {
    ($app:expr, $bearer:expr, $bucket:expr, $json:expr) => {{
        let req = TestRequest::put()
            .uri(&format!("/api/v1/buckets/{}/acl", $bucket))
            .insert_header(("authorization", $bearer.as_str()))
            .insert_header(("content-type", "application/json"))
            .set_payload($json.to_owned())
            .to_request();
        call!($app, req)
    }};
}

macro_rules! open_trace {
    ($app:expr, $bearer:expr) => {{
        let req = TestRequest::get()
            .uri("/api/v1/trace")
            .insert_header(("authorization", $bearer))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        assert_eq!(resp.status().as_u16(), 200, "trace subscribe failed");
        resp.into_body()
    }};
}

async fn collect_sse_events(body: BoxBody, wait: Duration) -> Vec<serde_json::Value> {
    let deadline = tokio::time::Instant::now() + wait;
    let mut buf: Vec<u8> = Vec::new();
    let mut events = Vec::new();
    let mut pinned = std::pin::pin!(body);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let polled = tokio::time::timeout(remaining, async {
            poll_fn(|cx| pinned.as_mut().poll_next(cx)).await
        })
        .await;
        match polled {
            Ok(Some(Ok(chunk))) => {
                buf.extend_from_slice(&chunk);
                while let Some(end) = find_sse_frame_end(&buf) {
                    let frame = String::from_utf8_lossy(&buf[..end]).into_owned();
                    buf.drain(..end);
                    if let Some(json) = frame.strip_prefix("data: ") {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(json.trim()) {
                            events.push(v);
                        }
                    }
                }
            }
            Ok(Some(Err(_))) | Ok(None) | Err(_) => break,
        }
    }
    events
}

fn find_sse_frame_end(buf: &[u8]) -> Option<usize> {
    buf.windows(2)
        .position(|w| w == b"\n\n")
        .map(|i| i + 2)
}

fn paths_containing(events: &[serde_json::Value], needle: &str) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| e.get("path").and_then(|p| p.as_str()).map(str::to_owned))
        .filter(|p| p.contains(needle))
        .collect()
}

#[actix_web::test]
async fn admin_without_grant_does_not_see_secret_bucket_events() {
    let harness = Harness::new(true);
    let owner = harness.add_account("owner", Role::User);
    let admin = harness.add_account("admin", Role::Admin);
    let owner_token = harness.bearer(&owner);
    let admin_token = harness.bearer(&admin);
    let app = build_app!(harness);

    let (status, _) = put_object!(app, &owner_token, "secret", "obj", OBJECT_BYTES);
    assert_eq!(status, 201);

    let body = open_trace!(app, admin_token.as_str());

    let (status, _) = get_object!(app, &owner_token, "secret", "obj");
    assert_eq!(status, 200);

    let locks = TestRequest::get()
        .uri("/api/v1/locks?older_than=1h")
        .insert_header(("authorization", admin_token.as_str()))
        .to_request();
    let (status, _) = call!(app, locks);
    assert_eq!(status, 200);

    let events = collect_sse_events(body, Duration::from_millis(400)).await;
    assert!(
        paths_containing(&events, "/secret").is_empty(),
        "ungranted admin must not see secret paths: {events:?}"
    );
    assert!(
        events.iter().any(|e| e["path"] == "/api/v1/locks"),
        "non-bucket admin path must still be delivered: {events:?}"
    );
    for e in &events {
        assert!(
            e.get("bucket").is_none(),
            "bucket must stay off the wire JSON: {e}"
        );
    }
}

#[actix_web::test]
async fn admin_with_grant_sees_secret_bucket_events() {
    let harness = Harness::new(true);
    let owner = harness.add_account("owner", Role::User);
    let admin = harness.add_account("admin", Role::Admin);
    let owner_token = harness.bearer(&owner);
    let admin_token = harness.bearer(&admin);
    let app = build_app!(harness);

    let (status, _) = put_object!(app, &owner_token, "secret", "obj", OBJECT_BYTES);
    assert_eq!(status, 201);
    let (status, _) = put_acl!(
        app,
        &owner_token,
        "secret",
        r#"{"grants":{"admin":"read"}}"#
    );
    assert_eq!(status, 200);

    let body = open_trace!(app, admin_token.as_str());

    let (status, _) = get_object!(app, &owner_token, "secret", "obj");
    assert_eq!(status, 200);

    let events = collect_sse_events(body, Duration::from_millis(400)).await;
    let secret_paths = paths_containing(&events, "/secret/");
    assert!(
        !secret_paths.is_empty(),
        "granted admin must see concrete secret paths: {events:?}"
    );
    assert!(
        secret_paths.iter().any(|p| p.contains("obj")),
        "expected object key in path: {secret_paths:?}"
    );
}

#[actix_web::test]
async fn authz_disabled_delivers_all_bucket_events() {
    let harness = Harness::new(false);
    let owner = harness.add_account("owner", Role::User);
    let admin = harness.add_account("admin", Role::Admin);
    let owner_token = harness.bearer(&owner);
    let admin_token = harness.bearer(&admin);
    let app = build_app!(harness);

    let (status, _) = put_object!(app, &owner_token, "secret", "obj", OBJECT_BYTES);
    assert_eq!(status, 201);

    let body = open_trace!(app, admin_token.as_str());

    let (status, _) = get_object!(app, &owner_token, "secret", "obj");
    assert_eq!(status, 200);

    let events = collect_sse_events(body, Duration::from_millis(400)).await;
    assert!(
        !paths_containing(&events, "/secret/").is_empty(),
        "enforce_authorization=false must deliver secret events: {events:?}"
    );
}

#[actix_web::test]
async fn middleware_captures_bucket_from_match_info() {
    let hub = Arc::new(TraceHub::new());
    let mut rx = hub.subscribe();
    let app = test::init_service(
        App::new()
            .wrap(from_fn(trace::trace_middleware))
            .app_data(web::Data::new(Arc::clone(&hub)))
            // Specific routes before the catch-all, same order as handlers::configure.
            .route(
                "/api/v1/locks",
                web::get().to(|| async { HttpResponse::Ok().finish() }),
            )
            .route(
                "/api/v1/buckets/{bucket}/acl",
                web::get().to(|| async { HttpResponse::Ok().finish() }),
            )
            .route(
                "/{bucket}/{tail:.*}",
                web::get().to(|| async { HttpResponse::Ok().finish() }),
            ),
    )
    .await;

    let resp = test::call_service(
        &app,
        TestRequest::get().uri("/secret/obj").to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    let event = rx.recv().await.expect("object route event");
    assert_eq!(event.bucket.as_deref(), Some("secret"));
    assert_eq!(event.path, "/secret/obj");

    let resp = test::call_service(
        &app,
        TestRequest::get()
            .uri("/api/v1/buckets/secret/acl")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    let event = rx.recv().await.expect("acl route event");
    assert_eq!(event.bucket.as_deref(), Some("secret"));

    let resp = test::call_service(
        &app,
        TestRequest::get().uri("/api/v1/locks").to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    let event = rx.recv().await.expect("locks route event");
    assert_eq!(event.bucket, None);
    assert_eq!(event.path, "/api/v1/locks");
}

#[test]
fn trace_event_wire_json_omits_bucket() {
    let event = TraceEvent {
        request_id: "rid".into(),
        timestamp_ns: 1,
        method: "GET".into(),
        path: "/secret/obj".into(),
        status: 200,
        latency_ms: 1.0,
        req_bytes: None,
        resp_bytes: Some(4),
        remote_addr: None,
        bucket: Some("secret".into()),
    };
    let json = serde_json::to_value(&event).unwrap();
    assert!(json.get("bucket").is_none());
    assert_eq!(json["path"], "/secret/obj");
}
