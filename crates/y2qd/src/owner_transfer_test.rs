//! Owner transfer must move the bucket wrap key, not just `cfg.owner`.
//!
//! `y2qd` is binary-only, so this is an in-process module declared from
//! `main.rs`. Sessions are minted the way login does: persona is the user's
//! `primary_slot`, and the session holds that slot's real identity secret.
//! A `persona: 0` session cannot read a seal made to a random primary slot.

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

const OBJECT_BYTES: &[u8] = b"owner-transfer-plaintext";

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
        fs.install_node_key(node_key);
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
    /// transfer because decoying the previous owner revokes their live tokens.
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

#[actix_web::test]
async fn bucket_owner_transfer_moves_read_access() {
    let harness = Harness::new();
    let alice = harness.add_account("alice", Role::User);
    let bob = harness.add_account("bob", Role::User);
    let alice_token = harness.bearer(&alice);
    let bob_token = harness.bearer(&bob);
    let app = build_app!(harness);

    let (status, body) = put_object!(app, &alice_token, "bkt", "obj", OBJECT_BYTES);
    assert_eq!(
        status,
        201,
        "creating the object must claim the bucket: {}",
        String::from_utf8_lossy(&body)
    );
    let (status, body) = put_acl!(app, &alice_token, "bkt", r#"{"owner":"bob","grants":{}}"#);
    assert_eq!(
        status,
        200,
        "owner transfer: {}",
        String::from_utf8_lossy(&body)
    );

    // Alice's token was revoked with the decoy reseal. A new login must 404,
    // not keep reading from the session's bucket-key cache.
    let alice_again = harness.bearer(&alice);
    let (status, body) = get_object!(app, &bob_token, "bkt", "obj");
    assert_eq!(
        status,
        200,
        "new owner GET: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(&body[..], OBJECT_BYTES);
    let (status, body) = get_object!(app, &alice_again, "bkt", "obj");
    assert_eq!(
        status,
        404,
        "previous owner GET: {}",
        String::from_utf8_lossy(&body)
    );
}

#[actix_web::test]
async fn bucket_owner_transfer_retains_previous_owner_with_read_grant() {
    let harness = Harness::new();
    let alice = harness.add_account("alice", Role::User);
    let bob = harness.add_account("bob", Role::User);
    let alice_token = harness.bearer(&alice);
    let app = build_app!(harness);

    let (status, body) = put_object!(app, &alice_token, "bkt", "obj", OBJECT_BYTES);
    assert_eq!(
        status,
        201,
        "creating the object must claim the bucket: {}",
        String::from_utf8_lossy(&body)
    );
    let (status, body) = put_acl!(
        app,
        &alice_token,
        "bkt",
        r#"{"owner":"bob","grants":{"alice":"read"}}"#
    );
    assert_eq!(
        status,
        200,
        "owner transfer with read grant: {}",
        String::from_utf8_lossy(&body)
    );

    // Neither user is revoked: bob was not the previous owner, and alice still
    // holds a read-implying grant. Fresh sessions avoid a stale cache hit.
    let alice_again = harness.bearer(&alice);
    let bob_again = harness.bearer(&bob);
    let (status, body) = get_object!(app, &bob_again, "bkt", "obj");
    assert_eq!(
        status,
        200,
        "new owner GET: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(&body[..], OBJECT_BYTES);
    let (status, body) = get_object!(app, &alice_again, "bkt", "obj");
    assert_eq!(
        status,
        200,
        "previous owner with read grant GET: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(&body[..], OBJECT_BYTES);
}

#[actix_web::test]
async fn bucket_owner_transfer_rejects_grantless_admin() {
    let harness = Harness::new();
    let alice = harness.add_account("alice", Role::User);
    let _bob = harness.add_account("bob", Role::User);
    let admin = harness.add_account("root", Role::Admin);
    let alice_token = harness.bearer(&alice);
    let admin_token = harness.bearer(&admin);
    let app = build_app!(harness);

    let (status, body) = put_object!(app, &alice_token, "bkt", "obj", OBJECT_BYTES);
    assert_eq!(
        status,
        201,
        "creating the object must claim the bucket: {}",
        String::from_utf8_lossy(&body)
    );
    let (status, body) = put_acl!(app, &admin_token, "bkt", r#"{"owner":"bob","grants":{}}"#);
    assert_eq!(
        status,
        404,
        "grantless admin must not learn the bucket exists: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body) = get_object!(app, &alice_token, "bkt", "obj");
    assert_eq!(
        status,
        200,
        "owner must still read after a rejected transfer: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(&body[..], OBJECT_BYTES);
}
