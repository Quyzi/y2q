//! A 200 GET must carry the same metadata headers as HEAD.
//!
//! `y2qd` is a binary-only crate, so this lives as an in-process test
//! module (`#[cfg(test)] mod get_metadata_headers_test;` in `main.rs`).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use actix_web::http::Method;
use actix_web::http::header::HeaderMap;
use actix_web::test::{self, TestRequest};
use actix_web::{App, web};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use y2q_core::crypto::{self, Argon2Params, CredentialSlot, Role, UserRecord, UserStore, kem};
use y2q_core::secmem::SecretVec;
use y2q_core::{AnyStorage, FilesystemStorage, SyncLevel};

use crate::auth::AuthState;
use crate::auth::session::NewSession;
use crate::config::{Argon2Config, AuthConfig, EncryptionParams, LabelLimits};
use crate::handlers;

/// Metadata headers a 200 GET is documented to share with HEAD.
fn metadata_headers(headers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in headers {
        let key = name.as_str().to_ascii_lowercase();
        if key == "content-type" || key == "content-length" || key.starts_with("x-y2q-") {
            out.entry(key)
                .or_default()
                .push(value.to_str().expect("metadata header is utf-8").to_owned());
        }
    }
    out
}

fn bearer_for(auth_state: &AuthState, identity_sk: SecretVec) -> String {
    let token = auth_state
        .sessions
        .insert(NewSession {
            username: "alice".to_owned(),
            role: Role::User,
            created_at: SystemTime::now(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            persona: 0,
            revoke_other_sessions: false,
            identity_sk,
        })
        .unwrap();
    token.0.expose().to_owned()
}

/// Live native-route harness: temp filesystem storage, a node key, and an
/// `AuthState` whose session identity matches the user record that will
/// own the bucket created by the first PUT.
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
        let user_store = UserStore::open(&user_dir.path().join("users.redb"), &[0u8; 32]).unwrap();
        // Cheap KDF: this test never unwraps a password slot. The dummy
        // login record built inside `AuthState::new` still runs Argon2.
        let argon2_config = Argon2Config {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let auth_config = AuthConfig {
            default_ttl_seconds: 3600,
            max_ttl_seconds: 86_400,
            session_sweep_interval_seconds: 300,
            min_login_response_ms: 0,
            max_failed_logins: 10,
            lockout_seconds: 900,
            enforce_authorization: false,
            max_refreshes: 1,
        };
        let auth_state = AuthState::new(user_store, auth_config, argon2_config).unwrap();

        let (pk, sk) = kem::keypair();
        let mut slots = Vec::with_capacity(crypto::CREDENTIAL_SLOTS);
        slots.push(CredentialSlot {
            identity_pk_b64: STANDARD.encode(pk.to_bytes()),
            wrapped: crypto::WrappedSk::default(),
        });
        for _ in 1..crypto::CREDENTIAL_SLOTS {
            let (other_pk, _) = kem::keypair();
            slots.push(CredentialSlot {
                identity_pk_b64: STANDARD.encode(other_pk.to_bytes()),
                wrapped: crypto::WrappedSk::default(),
            });
        }
        auth_state
            .user_store
            .upsert(&UserRecord {
                username: "alice".to_owned(),
                created_at: 1,
                last_login: None,
                kdf: Argon2Params::with_random_salt(8, 1, 1),
                slots,
                primary_slot: 0,
                role: Role::User,
            })
            .unwrap();

        let identity_sk = SecretVec::from_slice(sk.to_bytes().as_ref()).unwrap();
        let bearer = bearer_for(&auth_state, identity_sk);

        Self {
            _storage_dir: storage_dir,
            _user_dir: user_dir,
            storage: web::Data::new(storage),
            auth_state: web::Data::new(auth_state),
            bearer,
        }
    }
}

#[actix_web::test]
async fn get_200_matches_head_metadata_headers() {
    let harness = Harness::new();
    let app = test::init_service(
        App::new()
            .app_data(harness.storage.clone())
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
            .app_data(harness.auth_state.clone())
            .app_data(web::PayloadConfig::new(8 * 1024 * 1024))
            .configure(handlers::configure),
    )
    .await;

    // Non-empty object with a mixed-case label, then an empty object.
    for (key, body, label_name, label_value) in [
        ("hello", &b"hello world"[..], "Owner", "alice"),
        ("empty", &b""[..], "Kind", "empty"),
    ] {
        let uri = format!("/pics/{key}");
        let label_header = format!("X-Y2Q-{label_name}");
        let put = TestRequest::put()
            .uri(&uri)
            .insert_header(("authorization", format!("Bearer {}", harness.bearer)))
            .insert_header((label_header, label_value))
            .set_payload(body.to_vec())
            .to_request();
        let put_resp = test::call_service(&app, put).await;
        let put_status = put_resp.status();
        let put_body = test::read_body(put_resp).await;
        assert_eq!(
            put_status,
            201,
            "PUT {uri} failed: {}",
            String::from_utf8_lossy(&put_body)
        );

        let head = TestRequest::default()
            .method(Method::HEAD)
            .uri(&uri)
            .insert_header(("authorization", format!("Bearer {}", harness.bearer)))
            .to_request();
        let head_resp = test::call_service(&app, head).await;
        assert_eq!(head_resp.status(), 200, "HEAD {uri}");
        let head_meta = metadata_headers(head_resp.headers());

        let get = TestRequest::get()
            .uri(&uri)
            .insert_header(("authorization", format!("Bearer {}", harness.bearer)))
            .to_request();
        let get_resp = test::call_service(&app, get).await;
        assert_eq!(get_resp.status(), 200, "GET {uri}");
        let get_meta = metadata_headers(get_resp.headers());
        let get_body = test::read_body(get_resp).await;

        assert_eq!(
            get_meta, head_meta,
            "GET metadata headers differ from HEAD for {uri}"
        );
        assert_eq!(
            get_meta.get("content-type").map(Vec::as_slice),
            Some(["application/octet-stream".to_owned()].as_slice())
        );
        assert_eq!(
            get_meta.get("x-y2q-size").map(Vec::as_slice),
            Some([body.len().to_string()].as_slice())
        );
        assert_eq!(
            get_meta.get("content-length").map(Vec::as_slice),
            Some([body.len().to_string()].as_slice())
        );
        let created = get_meta.get("x-y2q-created").expect("X-Y2Q-Created");
        let modified = get_meta.get("x-y2q-modified").expect("X-Y2Q-Modified");
        assert_eq!(created.len(), 1);
        assert_eq!(modified.len(), 1);
        assert!(created[0].parse::<u64>().is_ok());
        assert!(modified[0].parse::<u64>().is_ok());
        let checksum = &get_meta
            .get("x-y2q-checksum-gxhash")
            .expect("X-Y2Q-Checksum-GxHash")[0];
        assert_eq!(checksum.len(), 12, "gxhash base64 length");
        let echoed = format!("x-y2q-{}", label_name.to_ascii_lowercase());
        assert_eq!(
            get_meta.get(&echoed).map(Vec::as_slice),
            Some([label_value.to_owned()].as_slice()),
            "custom label missing on GET"
        );
        assert_eq!(&get_body[..], body);
    }
}
