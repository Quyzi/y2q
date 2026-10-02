//! In-process proofs for bucket-quota enforcement on the native PUT path.
//!
//! `y2qd` is a binary-only crate, so this lives as a `#[cfg(test)]` module
//! declared from `main.rs` (same shape as `s3_gateway_test`) rather than an
//! external integration binary.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use actix_web::dev::ServiceResponse;
use actix_web::test::{self, TestRequest};
use actix_web::web::{self, Bytes};
use actix_web::{App, Error};
use y2q_core::crypto::{Role, SlotPayload, UserRecord, kdf};
use y2q_core::secmem::SecretVec;
use y2q_core::{AnyStorage, FilesystemStorage, Listing};

use crate::auth::AuthState;
use crate::auth::session::NewSession;
use crate::config::{Argon2Config, AuthConfig, EncryptionParams, LabelLimits};

/// Fast Argon2id costs. The production defaults are intentionally slow;
/// these tests only need a real primary-slot identity, not brute-force friction.
fn fast_argon2() -> Argon2Config {
    Argon2Config {
        m_cost_kib: 8 * 1024,
        t_cost: 1,
        p_cost: 1,
    }
}

struct Harness {
    _storage_dir: tempfile::TempDir,
    _user_dir: tempfile::TempDir,
    storage: web::Data<Arc<AnyStorage>>,
    auth_state: web::Data<AuthState>,
    bearer: String,
}

impl Harness {
    fn new() -> Self {
        let storage_dir = tempfile::TempDir::new().unwrap();
        let fs = FilesystemStorage::new(
            storage_dir.path().join("data"),
            storage_dir.path().join("index.redb"),
        )
        .unwrap();
        fs.install_node_key([3u8; 32]);
        let storage: Arc<AnyStorage> = Arc::new(AnyStorage::Filesystem(fs));

        let user_dir = tempfile::TempDir::new().unwrap();
        let user_store =
            y2q_core::crypto::UserStore::open(&user_dir.path().join("users.redb"), &[0u8; 32])
                .unwrap();

        let params = y2q_core::crypto::Argon2Params::with_random_salt(8 * 1024, 1, 1);
        const PASSWORD: &[u8] = b"quota-test-password";
        let (slots, primary) =
            kdf::new_slots_random("alice", PASSWORD, &params, Role::User, false).unwrap();
        let primary_slot = u8::try_from(primary).unwrap();
        let kek = params.derive_kek(PASSWORD).unwrap();
        let aad = kdf::slot_wrap_aad("alice", primary);
        let recovered = kdf::unwrap_slot(&slots[primary].wrapped, &kek, &aad).unwrap();
        let payload = SlotPayload::from_bytes(&recovered).unwrap();
        let identity_sk: SecretVec = payload.identity_sk;

        user_store
            .upsert(&UserRecord {
                username: "alice".to_owned(),
                created_at: 0,
                last_login: None,
                kdf: params,
                slots,
                primary_slot,
                role: Role::User,
            })
            .unwrap();

        let auth_config = AuthConfig {
            default_ttl_seconds: 3600,
            max_ttl_seconds: 86_400,
            session_sweep_interval_seconds: 300,
            min_login_response_ms: 0,
            max_failed_logins: 10,
            lockout_seconds: 900,
            // Quota does not consult the ACL. Skipping enforcement avoids
            // needing a sealed grant for the config endpoint; the first
            // write still claims the bucket with this session's real identity.
            enforce_authorization: false,
            max_refreshes: 0,
        };
        let auth_state = AuthState::new(user_store, auth_config, fast_argon2()).unwrap();
        let token = auth_state
            .sessions
            .insert(NewSession {
                username: "alice".to_owned(),
                role: Role::User,
                created_at: SystemTime::now(),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
                persona: primary_slot,
                revoke_other_sessions: false,
                identity_sk,
            })
            .unwrap();
        let bearer = token.0.expose().to_owned();

        Self {
            _storage_dir: storage_dir,
            _user_dir: user_dir,
            storage: web::Data::new(storage),
            auth_state: web::Data::new(auth_state),
            bearer,
        }
    }
}

fn app(
    harness: &Harness,
) -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = ServiceResponse,
        Error = Error,
        InitError = (),
    > + use<>,
> {
    App::new()
        .app_data(harness.storage.clone())
        .app_data(web::Data::new(LabelLimits {
            max_labels: 32,
            max_label_name_bytes: 64,
            max_label_value_bytes: 1024,
        }))
        .app_data(web::Data::new(y2q_core::SyncLevel::BestEffort))
        .app_data(web::Data::new(EncryptionParams {
            chunk_size_bytes: 64 * 1024,
            max_body_bytes: 8 * 1024 * 1024,
        }))
        .app_data(harness.auth_state.clone())
        .app_data(web::PayloadConfig::new(8 * 1024 * 1024))
        .configure(crate::handlers::configure)
}

macro_rules! exchange {
    ($app:expr, $req:expr) => {{
        let resp = test::call_service(&$app, $req.to_request()).await;
        let code = resp.status().as_u16();
        let body = test::read_body(resp).await;
        (code, body)
    }};
}

fn expect_status(what: &str, want: u16, got: u16, body: &Bytes) {
    assert_eq!(
        got,
        want,
        "{what}: status {got}, body {}",
        String::from_utf8_lossy(body)
    );
}

fn authed(harness: &Harness, req: TestRequest) -> TestRequest {
    req.insert_header(("authorization", format!("Bearer {}", harness.bearer)))
}

fn put_object(harness: &Harness, bucket: &str, key: &str, body: Vec<u8>) -> TestRequest {
    let len = body.len().to_string();
    authed(
        harness,
        TestRequest::put()
            .uri(&format!("/{bucket}/{key}"))
            .insert_header(("content-type", "application/octet-stream"))
            .insert_header(("content-length", len))
            .set_payload(body),
    )
}

/// quota 100. Objects of 60 and 40 both fit. Rewriting the 60-byte object
/// to 50 must succeed (result is 90). Rewriting it to 80 must 413, and a
/// brand-new key past the remaining headroom must 413 as well.
#[actix_web::test]
async fn quota_overwrite_credits_replaced_object() {
    let harness = Harness::new();
    let app = test::init_service(app(&harness)).await;

    let (code, body) = exchange!(app, authed(&harness, TestRequest::put().uri("/shrink/")));
    expect_status("create bucket", 200, code, &body);
    let (code, body) = exchange!(
        app,
        authed(
            &harness,
            TestRequest::put()
                .uri("/api/v1/buckets/shrink/config")
                .insert_header(("content-type", "application/json"))
                .set_payload(r#"{"quota_bytes":100}"#),
        )
    );
    expect_status("set quota", 200, code, &body);

    let (code, body) = exchange!(app, put_object(&harness, "shrink", "a", vec![b'a'; 60]));
    expect_status("put a 60", 201, code, &body);
    let (code, body) = exchange!(app, put_object(&harness, "shrink", "b", vec![b'b'; 40]));
    expect_status("put b 40", 201, code, &body);

    let replacement = vec![b'A'; 50];
    let (code, body) = exchange!(
        app,
        put_object(&harness, "shrink", "a", replacement.clone())
    );
    expect_status("rewrite a to 50", 200, code, &body);

    let (code, body) = exchange!(app, authed(&harness, TestRequest::get().uri("/shrink/a")));
    expect_status("get a", 200, code, &body);
    assert_eq!(body.as_ref(), replacement.as_slice());

    let (code, body) = exchange!(app, put_object(&harness, "shrink", "a", vec![b'Z'; 80]));
    expect_status("rewrite a to 80", 413, code, &body);

    let (code, body) = exchange!(app, put_object(&harness, "shrink", "c", vec![b'c'; 11]));
    expect_status("new key past remaining budget", 413, code, &body);

    assert_eq!(harness.storage.bucket_usage("shrink").await.unwrap(), 90);
}

/// Two concurrent 60-byte puts of distinct keys into an empty 100-byte
/// bucket must not both succeed. Eight fresh buckets, so a single lucky
/// schedule cannot hide the race and leftovers cannot leak into the next round.
#[actix_web::test]
async fn quota_concurrent_puts_cannot_both_pass() {
    let harness = Harness::new();
    let app = test::init_service(app(&harness)).await;

    for round in 0..8 {
        let bucket = format!("q{round}");
        let (code, body) = exchange!(
            app,
            authed(&harness, TestRequest::put().uri(&format!("/{bucket}/")))
        );
        expect_status("create bucket", 200, code, &body);
        let (code, body) = exchange!(
            app,
            authed(
                &harness,
                TestRequest::put()
                    .uri(&format!("/api/v1/buckets/{bucket}/config"))
                    .insert_header(("content-type", "application/json"))
                    .set_payload(r#"{"quota_bytes":100}"#),
            )
        );
        expect_status("set quota", 200, code, &body);

        let req_a = put_object(&harness, &bucket, "a", vec![b'a'; 60]).to_request();
        let req_b = put_object(&harness, &bucket, "b", vec![b'b'; 60]).to_request();
        let (resp_a, resp_b) = tokio::join!(
            test::call_service(&app, req_a),
            test::call_service(&app, req_b),
        );
        let sa = resp_a.status().as_u16();
        let sb = resp_b.status().as_u16();
        let body_a = test::read_body(resp_a).await;
        let body_b = test::read_body(resp_b).await;
        assert!(
            !(sa == 201 && sb == 201),
            "round {round}: both puts returned 201\n{}\n{}",
            String::from_utf8_lossy(&body_a),
            String::from_utf8_lossy(&body_b),
        );
        assert!(
            matches!(sa, 201 | 413) && matches!(sb, 201 | 413),
            "round {round}: unexpected statuses {sa} {sb}\n{}\n{}",
            String::from_utf8_lossy(&body_a),
            String::from_utf8_lossy(&body_b),
        );
        assert!(
            sa == 201 || sb == 201,
            "round {round}: expected one success, got {sa} and {sb}"
        );
        let used = harness.storage.bucket_usage(&bucket).await.unwrap();
        assert!(
            used <= 100,
            "round {round}: stored {used} bytes (statuses {sa}, {sb})"
        );
    }
}
