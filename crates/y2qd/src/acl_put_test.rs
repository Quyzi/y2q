//! `PUT /api/v1/buckets/{bucket}/acl` must reject malformed bodies instead of
//! silently clearing every grant.
//!
//! `y2qd` is binary-only, so this is an in-process module declared from
//! `main.rs`. Sessions are minted the way login does: persona is the user's
//! `primary_slot`, and the session holds that slot's real identity secret.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use actix_web::test::{self, TestRequest};
use actix_web::{App, web};
use y2q_core::crypto::{Argon2Params, Role, SlotPayload, UserRecord, UserStore, kdf};
use y2q_core::secmem::SecretVec;
use y2q_core::{AnyStorage, FilesystemStorage, SyncLevel};

use crate::auth::AuthState;
use crate::auth::session::NewSession;
use crate::config::{Argon2Config, AuthConfig, EncryptionParams, LabelLimits};
use crate::handlers;

const OBJECT_BYTES: &[u8] = b"acl-put-plaintext";

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
}

impl Harness {
    fn new() -> Self {
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
            enforce_authorization: true,
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

    /// Fresh session for `account`'s real primary slot. Called again after a
    /// grant is removed because that revokes the grantee's live tokens.
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

macro_rules! get_acl {
    ($app:expr, $bearer:expr, $bucket:expr) => {{
        let req = TestRequest::get()
            .uri(&format!("/api/v1/buckets/{}/acl", $bucket))
            .insert_header(("authorization", $bearer.as_str()))
            .to_request();
        call!($app, req)
    }};
}

/// Alice owns `bkt` and has granted bob `read`.
struct Scenario {
    harness: Harness,
    alice: Account,
    bob: Account,
}

fn scenario() -> Scenario {
    let harness = Harness::new();
    let alice = harness.add_account("alice", Role::User);
    let bob = harness.add_account("bob", Role::User);
    Scenario {
        harness,
        alice,
        bob,
    }
}

#[actix_web::test]
async fn acl_put_rejects_malformed_bodies_and_keeps_grants() {
    let Scenario {
        harness,
        alice,
        bob,
    } = scenario();
    let alice_token = harness.bearer(&alice);
    let bob_token = harness.bearer(&bob);
    let app = build_app!(harness);

    let (status, _) = put_object!(app, &alice_token, "bkt", "obj", OBJECT_BYTES);
    assert_eq!(status, 201);
    let (status, _) = put_acl!(app, &alice_token, "bkt", r#"{"grants":{"bob":"read"}}"#);
    assert_eq!(status, 200);

    let bodies: &[&str] = &[
        "[]",
        "{}",
        r#"{"a":1}"#,
        r#"{"grant":{"bob":"read"}}"#,
        r#"{"owner":"bob"}"#,
        "null",
        "\"x\"",
        r#"{"grants":null}"#,
        r#"{"grants":[]}"#,
        r#"{"grants":{"bob":"read"},"extra":true}"#,
        r#"{"grants":{"bob":"nope"}}"#,
    ];
    for raw in bodies {
        let (status, body) = put_acl!(app, &alice_token, "bkt", raw);
        assert_eq!(status, 400, "body {raw}");
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            body["error"].as_str().unwrap().starts_with("invalid acl:"),
            "body {raw}: {body}"
        );

        let (status, body) = get_acl!(app, &alice_token, "bkt");
        assert_eq!(status, 200);
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["grants"],
            serde_json::json!({"bob": "read"}),
            "body {raw}"
        );

        let (status, _) = get_object!(app, &bob_token, "bkt", "obj");
        assert_eq!(status, 200, "body {raw}");
    }
}

#[actix_web::test]
async fn acl_put_empty_grants_object_clears_all_grants() {
    let Scenario {
        harness,
        alice,
        bob,
    } = scenario();
    let alice_token = harness.bearer(&alice);
    let app = build_app!(harness);

    let (status, _) = put_object!(app, &alice_token, "bkt", "obj", OBJECT_BYTES);
    assert_eq!(status, 201);
    let (status, _) = put_acl!(app, &alice_token, "bkt", r#"{"grants":{"bob":"read"}}"#);
    assert_eq!(status, 200);

    // PUT must echo the generation from GET (CAS); empty grants clear all.
    let (status, got) = get_acl!(app, &alice_token, "bkt");
    assert_eq!(status, 200);
    let mut clear: serde_json::Value = serde_json::from_slice(&got).unwrap();
    clear["grants"] = serde_json::json!({});
    let (status, body) = put_acl!(app, &alice_token, "bkt", clear.to_string());
    assert_eq!(status, 200);
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["grants"], serde_json::json!({}));

    let (status, body) = get_acl!(app, &alice_token, "bkt");
    assert_eq!(status, 200);
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["grants"], serde_json::json!({}));

    // Bob's old token was revoked; a fresh session has no grant left.
    let bob_again = harness.bearer(&bob);
    let (status, _) = get_object!(app, &bob_again, "bkt", "obj");
    assert_eq!(status, 404);
}

#[actix_web::test]
async fn acl_get_body_round_trips_through_put() {
    let Scenario { harness, alice, .. } = scenario();
    let alice_token = harness.bearer(&alice);
    let app = build_app!(harness);

    let (status, _) = put_object!(app, &alice_token, "bkt", "obj", OBJECT_BYTES);
    assert_eq!(status, 201);
    let (status, _) = put_acl!(app, &alice_token, "bkt", r#"{"grants":{"bob":"read"}}"#);
    assert_eq!(status, 200);

    let (status, got) = get_acl!(app, &alice_token, "bkt");
    assert_eq!(status, 200);
    let before: serde_json::Value = serde_json::from_slice(&got).unwrap();
    assert!(before["key_epochs"].is_array());

    let (status, _) = put_acl!(app, &alice_token, "bkt", got);
    assert_eq!(status, 200);

    let (status, after) = get_acl!(app, &alice_token, "bkt");
    assert_eq!(status, 200);
    let after: serde_json::Value = serde_json::from_slice(&after).unwrap();
    assert_eq!(after["grants"], before["grants"]);
}

#[actix_web::test]
async fn acl_put_owner_omitted_keeps_owner() {
    let Scenario { harness, alice, .. } = scenario();
    let alice_token = harness.bearer(&alice);
    let app = build_app!(harness);

    let (status, _) = put_object!(app, &alice_token, "bkt", "obj", OBJECT_BYTES);
    assert_eq!(status, 201);

    let (status, body) = put_acl!(app, &alice_token, "bkt", r#"{"grants":{"bob":"write"}}"#);
    assert_eq!(status, 200);
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["owner"], "alice");
}

#[actix_web::test]
async fn acl_put_wrong_content_type_is_not_acl_envelope() {
    let Scenario { harness, alice, .. } = scenario();
    let alice_token = harness.bearer(&alice);
    let app = build_app!(harness);

    let (status, _) = put_object!(app, &alice_token, "bkt", "obj", OBJECT_BYTES);
    assert_eq!(status, 201);

    let req = TestRequest::put()
        .uri("/api/v1/buckets/bkt/acl")
        .insert_header(("authorization", alice_token.as_str()))
        .insert_header(("content-type", "text/plain"))
        .set_payload(r#"{"grants":{}}"#)
        .to_request();
    let (status, body) = call!(app, req);
    assert_eq!(status, 400);
    assert!(serde_json::from_slice::<serde_json::Value>(&body).is_err());
}
