//! HTTP-level regression proofs for the S3 gateway thermo-nuclear review
//! fix changeset that don't fit as in-module unit tests (they need a live
//! signed request routed through the real actix service, not just a
//! function call).
//!
//! `y2qd` is a binary-only crate, so this lives as an in-process test
//! module (`#[cfg(test)] mod s3_gateway_test;` in `main.rs`) rather than a
//! `tests/` integration binary — an external integration test cannot see
//! the crate's `pub(crate)` items this harness needs (`sigv4::*`,
//! `s3::routes::configure`, `s3::state::*`). There is no `aws` CLI on this
//! machine, so every request here is signed by hand against the same
//! `sigv4` primitives the gateway itself uses to verify.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};
use actix_web::middleware::from_fn;
use actix_web::test::{self, TestRequest};
use actix_web::{App, web};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use y2q_core::crypto::{
    self, Argon2Params, CredentialSlot, Role, UserRecord, UserStore, kem,
};
use y2q_core::secmem::SecretVec;
use y2q_core::{AnyStorage, FilesystemStorage, Listing};

use crate::auth::AuthState;
use crate::auth::session::NewSession;
use crate::config::{Argon2Config, AuthConfig, EncryptionParams, LabelLimits, S3Config};
use crate::request_id;
use crate::s3::state::{MultipartRegistry, S3CredentialStore, S3State};
use crate::s3::{routes, sigv4};

/// Live harness: a real actix service wired like `main.rs`'s S3 listener
/// (same middleware order including `vhost_middleware`, same app_data,
/// same route table), a UserStore with alice's identity key material
/// (needed when a first write claims bucket ownership), one live session,
/// and one minted S3 credential. `virtual_host_domain` is always
/// `s3.local` so path-style tests also cover the "domain set but Host is
/// not a vhost" no-op rewrite.
struct Harness {
    _storage_dir: tempfile::TempDir,
    _user_dir: tempfile::TempDir,
    storage: web::Data<Arc<AnyStorage>>,
    auth_state: web::Data<AuthState>,
    s3_state: web::Data<S3State>,
    akid: String,
    secret: String,
    region: String,
}

impl Harness {
    fn new(enforce_authorization: bool) -> Self {
        let storage_dir = tempfile::TempDir::new().unwrap();
        let fs = FilesystemStorage::new(
            storage_dir.path().join("data"),
            storage_dir.path().join("index.redb"),
        )
        .unwrap();
        fs.install_node_key(&[3u8; 32]);
        let storage: Arc<AnyStorage> = Arc::new(AnyStorage::Filesystem(fs));

        let user_dir = tempfile::TempDir::new().unwrap();
        let user_store = UserStore::open(&user_dir.path().join("users.redb"), &[0u8; 32]).unwrap();
        // Cheap KDF: these tests never unwrap a password slot. The dummy
        // login record inside `AuthState::new` still runs Argon2.
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
            enforce_authorization,
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
        let token_hash = token.hash();

        let region = "y2q".to_owned();
        let s3_config = S3Config {
            region: region.clone(),
            max_clock_skew_secs: 900,
            virtual_host_domain: "s3.local".to_owned(),
            ..Default::default()
        };
        let credentials = S3CredentialStore::new(auth_state.sessions.keyring(), 4);
        let (akid, secret) = credentials
            .mint(
                token_hash,
                "alice",
                SystemTime::now() + Duration::from_secs(3600),
                SystemTime::now() + Duration::from_secs(3600),
            )
            .unwrap();
        let s3_state = S3State {
            credentials,
            uploads: MultipartRegistry::new(16),
            config: s3_config,
        };

        Self {
            _storage_dir: storage_dir,
            _user_dir: user_dir,
            storage: web::Data::new(storage),
            auth_state: web::Data::new(auth_state),
            s3_state: web::Data::new(s3_state),
            akid,
            secret: secret.expose().to_owned(),
            region,
        }
    }
}

/// Sign `method path?query` with the harness's minted credential,
/// returning the `Authorization` header value and the `X-Amz-Date` used.
/// Always an unsigned-payload, header-auth request — every test here
/// exercises routing/guard logic ahead of any body read.
fn sign(harness: &Harness, method: &str, path: &str, query: &str, host: &str) -> (String, String) {
    let now = SystemTime::now();
    let amz_date = amz_date_from(now);
    let date_stamp = &amz_date[0..8];

    let signed_headers = vec![
        "host".to_owned(),
        "x-amz-content-sha256".to_owned(),
        "x-amz-date".to_owned(),
    ];
    let mut headers = HeaderMap::new();
    headers.insert(
        actix_web::http::header::HOST,
        HeaderValue::from_str(host).unwrap(),
    );
    headers.insert(
        HeaderName::from_static("x-amz-content-sha256"),
        HeaderValue::from_static(sigv4::UNSIGNED_PAYLOAD),
    );
    headers.insert(
        HeaderName::from_static("x-amz-date"),
        HeaderValue::from_str(&amz_date).unwrap(),
    );

    let canonical_uri = sigv4::canonical_uri(path);
    let canonical_query = sigv4::canonical_query_string(query);
    let (headers_block, signed_headers_joined) =
        sigv4::canonical_headers(&headers, host, &signed_headers);
    let canonical_request = sigv4::canonical_request(
        method,
        &canonical_uri,
        &canonical_query,
        &headers_block,
        &signed_headers_joined,
        sigv4::UNSIGNED_PAYLOAD,
    );
    let scope = format!("{date_stamp}/{}/s3/aws4_request", harness.region);
    let sts = sigv4::string_to_sign(&amz_date, &scope, &canonical_request);
    let key = sigv4::signing_key(harness.secret.as_bytes(), date_stamp, &harness.region, "s3");
    let signature = sigv4::hex_hmac_sha256(&key, sts.as_bytes());
    let auth_header = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers_joined}, Signature={signature}",
        harness.akid
    );
    (auth_header, amz_date)
}

fn amz_date_from(t: SystemTime) -> String {
    let iso = crate::s3::httpdate::iso8601_from(t);
    format!(
        "{}T{}Z",
        iso[0..10].replace('-', ""),
        iso[11..19].replace(':', "")
    )
}

macro_rules! build_app {
    ($harness:expr) => {
        test::init_service(
            App::new()
                // Outer→inner among these wraps: vhost, request_id,
                // error_detail — same relative order as `main.rs` (which
                // also inserts TracingLogger / metrics / trace between
                // request_id and vhost). Last `.wrap` is outermost.
                .wrap(from_fn(routes::error_detail_middleware))
                .wrap(from_fn(request_id::request_id_middleware))
                .wrap(from_fn(routes::vhost_middleware))
                .app_data($harness.storage.clone())
                .app_data(web::Data::new(LabelLimits {
                    max_labels: 32,
                    max_label_name_bytes: 64,
                    max_label_value_bytes: 1024,
                }))
                .app_data(web::Data::new(y2q_core::SyncLevel::Durable))
                .app_data(web::Data::new(EncryptionParams {
                    chunk_size_bytes: 4 * 1024 * 1024,
                    max_body_bytes: 8 * 1024 * 1024,
                }))
                .app_data($harness.auth_state.clone())
                .app_data($harness.s3_state.clone())
                .app_data(web::PayloadConfig::new(8 * 1024 * 1024))
                .configure(routes::configure),
        )
        .await
    };
}

const HOST: &str = "example.com";
const VHOST_DOMAIN: &str = "s3.local";
const VHOST_BUCKET: &str = "alice-priv";

fn vhost_host(bucket: &str) -> String {
    format!("{bucket}.{VHOST_DOMAIN}")
}

/// Signed request helper that also stamps Host / SigV4 headers used by every
/// gateway test here.
fn signed_req(
    harness: &Harness,
    method: actix_web::http::Method,
    path: &str,
    query: &str,
    host: &str,
) -> TestRequest {
    let uri = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let (auth_header, amz_date) = sign(harness, method.as_str(), path, query, host);
    TestRequest::default()
        .method(method)
        .uri(&uri)
        .insert_header(("host", host))
        .insert_header(("x-amz-content-sha256", sigv4::UNSIGNED_PAYLOAD))
        .insert_header(("x-amz-date", amz_date))
        .insert_header(("authorization", auth_header))
}

/// Check: `DELETE /{bucket}?policy` returns 501 and never touches the
/// bucket (it still exists afterward); `PUT /{bucket}?acl` likewise 501s
/// instead of silently succeeding as if the ACL had been applied.
#[actix_web::test]
async fn bucket_unimplemented_subresource_guard_applies_to_put_and_delete() {
    let harness = Harness::new(true);
    harness.storage.create_bucket("bkt").await.unwrap();
    let app = build_app!(harness);

    let (auth_header, amz_date) = sign(&harness, "DELETE", "/bkt", "policy=", HOST);
    let req = TestRequest::delete()
        .uri("/bkt?policy=")
        .insert_header(("host", HOST))
        .insert_header(("x-amz-content-sha256", sigv4::UNSIGNED_PAYLOAD))
        .insert_header(("x-amz-date", amz_date.as_str()))
        .insert_header(("authorization", auth_header.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 501);
    assert!(
        harness.storage.bucket_exists("bkt").await.unwrap(),
        "DELETE with an unimplemented sub-resource must not delete the bucket"
    );

    let (auth_header, amz_date) = sign(&harness, "PUT", "/bkt", "acl=", HOST);
    let req = TestRequest::put()
        .uri("/bkt?acl=")
        .insert_header(("host", HOST))
        .insert_header(("x-amz-content-sha256", sigv4::UNSIGNED_PAYLOAD))
        .insert_header(("x-amz-date", amz_date.as_str()))
        .insert_header(("authorization", auth_header.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 501);
}

/// Check: `PUT /{b}/{k}?tagging` with an over-limit body returns 413
/// before ever reaching storage — no bucket exists in this test at all.
#[actix_web::test]
async fn object_tagging_body_is_capped() {
    let harness = Harness::new(true);
    let app = build_app!(harness);

    let (auth_header, amz_date) = sign(&harness, "PUT", "/bkt/key", "tagging=", HOST);
    let body = vec![b'x'; crate::s3::xml::MAX_XML_BYTES + 1];
    let req = TestRequest::put()
        .uri("/bkt/key?tagging=")
        .insert_header(("host", HOST))
        .insert_header(("x-amz-content-sha256", sigv4::UNSIGNED_PAYLOAD))
        .insert_header(("x-amz-date", amz_date.as_str()))
        .insert_header(("authorization", auth_header.as_str()))
        .set_payload(body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 413);
}

/// Check: an invalid (non-decodable) `continuation-token` is rejected with
/// 400, not silently treated as "no token" (which looped page one
/// forever). `enforce_authorization = false` so `ListObjects`'s
/// `authorize_bucket(Read)` succeeds unconditionally and the request
/// reaches the cursor-decode step without any bucket needing to exist.
#[actix_web::test]
async fn malformed_continuation_token_is_rejected_not_silently_ignored() {
    let harness = Harness::new(false);
    let app = build_app!(harness);

    let query = "list-type=2&continuation-token=%21%21%21";
    let (auth_header, amz_date) = sign(&harness, "GET", "/bkt", query, HOST);
    let req = TestRequest::get()
        .uri(&format!("/bkt?{query}"))
        .insert_header(("host", HOST))
        .insert_header(("x-amz-content-sha256", sigv4::UNSIGNED_PAYLOAD))
        .insert_header(("x-amz-date", amz_date.as_str()))
        .insert_header(("authorization", auth_header.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
    let body = test::read_body(resp).await;
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("InvalidArgument"), "body: {text}");
}

/// Check: every S3 error response carries `x-amz-request-id` equal to its
/// own `X-Request-ID` header and a non-empty `<Resource>` matching the
/// request path — the `error_detail_middleware` funnel this session added.
#[actix_web::test]
async fn error_response_carries_matching_request_id_and_populated_resource() {
    let harness = Harness::new(true);
    let app = build_app!(harness);

    let (auth_header, amz_date) = sign(&harness, "DELETE", "/bkt", "policy=", HOST);
    let req = TestRequest::delete()
        .uri("/bkt?policy=")
        .insert_header(("host", HOST))
        .insert_header(("x-amz-content-sha256", sigv4::UNSIGNED_PAYLOAD))
        .insert_header(("x-amz-date", amz_date.as_str()))
        .insert_header(("authorization", auth_header.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 501);

    let request_id_header = resp
        .headers()
        .get("x-request-id")
        .expect("request_id_middleware always sets X-Request-ID")
        .to_str()
        .unwrap()
        .to_owned();
    let amz_request_id = resp
        .headers()
        .get("x-amz-request-id")
        .expect("error_detail_middleware must set x-amz-request-id")
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(amz_request_id, request_id_header);

    let body = test::read_body(resp).await;
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        text.contains("<Resource>/bkt</Resource>"),
        "body must carry the request path as Resource: {text}"
    );
    assert!(
        text.contains(&format!("<RequestId>{amz_request_id}</RequestId>")),
        "body: {text}"
    );
}

/// Virtual-hosted PUT then GET must bind `web::Path` from the rewritten
/// `/<bucket>/<key>` path (not the client `/<key>`), while SigV4 still
/// verifies against the client-sent URI via `OriginalUri`.
#[actix_web::test]
async fn virtual_hosted_object_put_get_round_trip() {
    let harness = Harness::new(false);
    let app = build_app!(harness);
    let host = vhost_host(VHOST_BUCKET);

    for (key, payload) in [("keep.txt", &b"keep-me"[..]), ("noperiod", &b"plain"[..])] {
        let path = format!("/{key}");
        let put = signed_req(
            &harness,
            actix_web::http::Method::PUT,
            &path,
            "",
            &host,
        )
        .set_payload(payload.to_vec())
        .to_request();
        let put_resp = test::call_service(&app, put).await;
        let put_status = put_resp.status();
        let put_body = test::read_body(put_resp).await;
        assert_eq!(
            put_status,
            200,
            "vhost PUT {path} Host={host}: {}",
            String::from_utf8_lossy(&put_body)
        );

        let get = signed_req(
            &harness,
            actix_web::http::Method::GET,
            &path,
            "",
            &host,
        )
        .to_request();
        let get_resp = test::call_service(&app, get).await;
        let get_status = get_resp.status();
        let get_body = test::read_body(get_resp).await;
        assert_eq!(
            get_status,
            200,
            "vhost GET {path} Host={host}: {}",
            String::from_utf8_lossy(&get_body)
        );
        assert_eq!(&get_body[..], payload, "GET body mismatch for {key}");
    }
}

/// `GET /` with a virtual-hosted Host must list that bucket's objects
/// (`ListBucketResult`), not the service-level `ListAllMyBuckets`.
#[actix_web::test]
async fn virtual_hosted_bucket_root_lists_objects() {
    let harness = Harness::new(false);
    let app = build_app!(harness);
    let host = vhost_host(VHOST_BUCKET);

    let put = signed_req(
        &harness,
        actix_web::http::Method::PUT,
        "/listed.txt",
        "",
        &host,
    )
    .set_payload(b"listed".to_vec())
    .to_request();
    let put_resp = test::call_service(&app, put).await;
    assert_eq!(put_resp.status(), 200, "seed PUT must succeed");

    let list = signed_req(&harness, actix_web::http::Method::GET, "/", "", &host).to_request();
    let list_resp = test::call_service(&app, list).await;
    let list_status = list_resp.status();
    let list_body = test::read_body(list_resp).await;
    let text = String::from_utf8(list_body.to_vec()).unwrap();
    assert_eq!(list_status, 200, "vhost GET /: {text}");
    assert!(
        text.contains("ListBucketResult"),
        "expected ListObjects XML, got: {text}"
    );
    assert!(
        !text.contains("ListAllMyBucketsResult"),
        "vhost GET / must not hit ListAllMyBuckets: {text}"
    );
    assert!(
        text.contains("<Name>alice-priv</Name>") || text.contains("<Key>listed.txt</Key>"),
        "listing must be scoped to the Host bucket: {text}"
    );
}

/// Path-style addressing must keep working with `virtual_host_domain` set
/// and `vhost_middleware` wrapped — Host `example.com` is not a vhost, so
/// the rewrite is a no-op.
#[actix_web::test]
async fn path_style_still_works_with_vhost_domain_configured() {
    let harness = Harness::new(false);
    let app = build_app!(harness);

    let put = signed_req(
        &harness,
        actix_web::http::Method::PUT,
        "/pathbkt/obj.txt",
        "",
        HOST,
    )
    .set_payload(b"path-style".to_vec())
    .to_request();
    let put_resp = test::call_service(&app, put).await;
    let put_status = put_resp.status();
    let put_body = test::read_body(put_resp).await;
    assert_eq!(
        put_status,
        200,
        "path-style PUT: {}",
        String::from_utf8_lossy(&put_body)
    );

    let get = signed_req(
        &harness,
        actix_web::http::Method::GET,
        "/pathbkt/obj.txt",
        "",
        HOST,
    )
    .to_request();
    let get_resp = test::call_service(&app, get).await;
    let get_status = get_resp.status();
    let get_body = test::read_body(get_resp).await;
    assert_eq!(
        get_status,
        200,
        "path-style GET: {}",
        String::from_utf8_lossy(&get_body)
    );
    assert_eq!(&get_body[..], b"path-style");
}
