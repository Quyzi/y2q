//! `S3Authenticated` extractor and `SessionLeash` — the S3 gateway's
//! security core.
//!
//! Construction of an `S3Authenticated` proves: the SigV4 signature is
//! valid, the minted credential is live, and the owning session is live
//! *right now*. Every S3 request re-resolves its credential's session
//! through [`SessionStore::get_active`] — the same call the REST listener's
//! `Authenticated` extractor makes — so logout, expiry, revocation, and
//! duress persona switches take effect on the S3 surface immediately.
//! [`SessionLeash`] extends that guarantee across a streaming transfer that
//! outlives the initial signature check.

use std::future::{Ready, ready};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use actix_web::{FromRequest, HttpMessage, HttpRequest, dev::Payload, web};
use zeroize::Zeroizing;

use crate::auth::session::{SessionInfo, SessionStore};
use crate::auth::{AuthState, Authenticated};
use crate::s3::error::S3Error;
use crate::s3::sigv4::{self, PayloadHash};
use crate::s3::state::S3State;

/// Set by `crate::s3::routes::vhost_middleware` to the pre-rewrite request
/// path when virtual-hosted addressing rewrote the path for routing — the
/// client's SigV4 signature covers the URI it actually sent, not the
/// path-style rewrite. Absent on a path-style request (or before the
/// middleware is wired), callers fall back to `req.path()`.
#[derive(Clone)]
pub struct OriginalUri(pub String);

/// Signing material needed to verify the per-chunk signature chain of an
/// `aws-chunked` signed-payload upload (see `crate::s3::body`).
#[derive(Clone)]
pub struct ChunkSigning {
    pub signing_key: Zeroizing<[u8; 32]>,
    pub scope: String,
    pub amz_date: String,
    /// The request's own top-level signature — the seed the first chunk's
    /// signature chains from.
    pub seed_signature: String,
}

/// A verified S3 request.
pub struct S3Authenticated {
    /// Exactly the value the REST handlers use, so every downstream
    /// authorization and key-resolution call (`authorize_bucket`,
    /// `bucket_keys::resolve_read_key`/`resolve_write_key`) is shared code.
    pub auth: Authenticated,
    /// Re-validates the session during long transfers.
    pub leash: SessionLeash,
    /// Present only for `STREAMING-AWS4-HMAC-SHA256-PAYLOAD[-TRAILER]`.
    pub chunk_signing: Option<ChunkSigning>,
    pub payload: PayloadHash,
}

impl FromRequest for S3Authenticated {
    type Error = S3Error;
    type Future = Ready<Result<Self, S3Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let request_id = S3Error::request_id_from(req);
        ready(verify(req).map_err(|e| e.with_request_id(request_id)))
    }
}

fn verify(req: &HttpRequest) -> Result<S3Authenticated, S3Error> {
    let s3 = req
        .app_data::<web::Data<S3State>>()
        .ok_or_else(S3Error::internal_error)?;
    let auth_state = req
        .app_data::<web::Data<AuthState>>()
        .ok_or_else(S3Error::internal_error)?;

    // 1. Parse the Authorization header or presigned query parameters.
    let query = req.query_string();
    let parsed = sigv4::parse(query, req.headers())?;

    // 2. Scope checks.
    if parsed.scope.service != "s3" {
        return Err(S3Error::authorization_header_malformed(
            "credential scope service must be \"s3\"",
        ));
    }
    if parsed.scope.region != s3.config.region {
        return Err(S3Error::authorization_header_malformed(format!(
            "credential scope region \"{}\" does not match this endpoint's region \"{}\"",
            parsed.scope.region, s3.config.region
        )));
    }
    let date_prefix = parsed.amz_date.get(0..8).unwrap_or("");
    if parsed.scope.date != date_prefix {
        return Err(S3Error::authorization_header_malformed(
            "credential scope date does not match X-Amz-Date",
        ));
    }

    // 3. Clock skew. Presigned URLs are bounded by their own
    // `X-Amz-Expires` window (step 8), not this check — real S3 does not
    // apply `max_clock_skew_secs` to a presigned request either, since its
    // whole point is to remain valid well after the moment it was signed.
    let now = SystemTime::now();
    let request_time = sigv4::parse_amz_date(&parsed.amz_date)
        .map_err(|_| S3Error::authorization_header_malformed("malformed X-Amz-Date"))?;
    if parsed.presigned_expires.is_none() {
        let skew = now
            .duration_since(request_time)
            .or_else(|_| request_time.duration_since(now))
            .unwrap_or(Duration::MAX);
        if skew.as_secs() > s3.config.max_clock_skew_secs {
            return Err(S3Error::request_time_too_skewed());
        }
    }

    // 4. Access key id must be a live credential.
    let akid = parsed.scope.access_key_id.clone();
    let cred = s3
        .credentials
        .get(&akid)
        .ok_or_else(S3Error::invalid_access_key_id)?;

    // 5. Credential itself must not be expired.
    if cred.is_expired(now) {
        s3.credentials.remove(&akid);
        return Err(S3Error::expired_token("credential has expired"));
    }

    // 6-7. The owning session must still be live and (when enforced) not
    // disabled. Delegates to `crate::auth::authenticate_token_hash` — the
    // exact tail `crate::auth::extract_authenticated` runs for the REST
    // listener, so any gate added there applies here too, rather than a
    // hand-duplicated copy silently missing it. Two S3-specific behaviours
    // the shared helper doesn't know about stay here: purge the
    // now-orphaned credential when the session itself is gone (not merely
    // disabled — that session is still live), and map the resulting
    // `AuthError` through the existing `From<AuthError> for S3Error`.
    let auth = crate::auth::authenticate_token_hash(auth_state, cred.token_hash).map_err(|e| {
        if !matches!(e, crate::auth::AuthError::AccountDisabled) {
            s3.credentials.remove(&akid);
        }
        S3Error::from(e)
    })?;
    let session = Arc::clone(&auth.session);

    // 8. Presigned URLs: expiry is the minimum of the URL's own stated
    // window, the credential's expiry, and the session's expiry — a
    // presigned link can never outlive the session that (transitively)
    // authorized it.
    if let Some(expires_secs) = parsed.presigned_expires {
        if !(1..=604_800).contains(&expires_secs) {
            return Err(S3Error::authorization_header_malformed(
                "X-Amz-Expires must be between 1 and 604800 seconds",
            ));
        }
        let url_expiry = request_time + Duration::from_secs(expires_secs);
        let effective = url_expiry.min(cred.expires_at).min(session.expires_at);
        if now >= effective {
            return Err(S3Error::access_denied("Request has expired"));
        }
    }

    // 9. Recompute the signature over the canonical request.
    let host = req
        .headers()
        .get(actix_web::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let path = req
        .extensions()
        .get::<OriginalUri>()
        .map(|o| o.0.clone())
        .unwrap_or_else(|| req.path().to_owned());
    let canonical_uri = sigv4::canonical_uri(&path);
    let canonical_query = sigv4::canonical_query_string(query);
    let (headers_block, signed_headers_joined) =
        sigv4::canonical_headers(req.headers(), &host, &parsed.signed_headers);
    let payload_token = sigv4::payload_hash_token(&parsed.payload);
    let canonical_request = sigv4::canonical_request(
        req.method().as_str(),
        &canonical_uri,
        &canonical_query,
        &headers_block,
        &signed_headers_joined,
        payload_token,
    );
    let scope_str = parsed.scope.scope_string();
    let string_to_sign = sigv4::string_to_sign(&parsed.amz_date, &scope_str, &canonical_request);

    let signing_key = Zeroizing::new(
        cred.with_secret(s3.credentials.keyring(), |secret| {
            sigv4::signing_key(
                secret,
                &parsed.scope.date,
                &parsed.scope.region,
                &parsed.scope.service,
            )
        })
        .map_err(S3Error::from)?,
    );
    let expected_signature =
        sigv4::hex_hmac_sha256(signing_key.as_slice(), string_to_sign.as_bytes());
    if !sigv4::signatures_match(&expected_signature, &parsed.signature) {
        return Err(S3Error::signature_does_not_match());
    }

    // 11. Build the leash and, for signed-streaming uploads, the chunk
    // signing material.
    let leash = SessionLeash {
        sessions: auth_state.sessions.clone(),
        token_hash: cred.token_hash,
        session,
        bytes_since_check: 0,
        last_check: Instant::now(),
        recheck_bytes: s3.config.session_recheck_bytes,
        recheck_interval: Duration::from_secs(s3.config.session_recheck_interval_secs),
    };

    let chunk_signing = match &parsed.payload {
        PayloadHash::StreamingSigned { .. } => Some(ChunkSigning {
            signing_key,
            scope: scope_str,
            amz_date: parsed.amz_date.clone(),
            seed_signature: parsed.signature.clone(),
        }),
        _ => None,
    };

    Ok(S3Authenticated {
        auth,
        leash,
        chunk_signing,
        payload: parsed.payload,
    })
}

/// Re-validates that the session behind an in-flight S3 transfer is still
/// the same live session it was when the request was authenticated. Held by
/// the streaming body adapters (`crate::s3::body`); not `Clone` — a leash
/// tracks exactly one in-flight transfer's byte count and last-check clock.
pub struct SessionLeash {
    sessions: SessionStore,
    token_hash: [u8; 32],
    /// The exact session row this request authenticated against.
    session: Arc<SessionInfo>,
    bytes_since_check: u64,
    last_check: Instant,
    recheck_bytes: u64,
    recheck_interval: Duration,
}

impl SessionLeash {
    /// Account for `n` transferred bytes, re-checking session liveness once
    /// either threshold (bytes or wall-clock interval) is crossed.
    pub fn note(&mut self, n: u64) -> Result<(), S3Error> {
        self.bytes_since_check += n;
        if self.bytes_since_check >= self.recheck_bytes
            || self.last_check.elapsed() >= self.recheck_interval
        {
            self.force()?;
            self.bytes_since_check = 0;
        }
        Ok(())
    }

    /// Re-check unconditionally: the session must still be active, and must
    /// be the *exact* row (`Arc::ptr_eq`) this leash was built from.
    ///
    /// `switch_user_to_persona` (duress) replaces the `Arc<SessionInfo>`
    /// under the same token hash rather than mutating it in place, so a
    /// duress switch mid-transfer makes the pointers diverge and this fails
    /// — the in-flight transfer, which is still holding the previous
    /// persona's bucket key, aborts instead of continuing under authority
    /// that has since been revoked. Nothing else in the daemon replaces a
    /// session row in place, so this cannot produce a false abort.
    fn force(&mut self) -> Result<(), S3Error> {
        let current = self
            .sessions
            .get_active(&self.token_hash)
            .map_err(|_| S3Error::expired_token("session expired during transfer"))?;
        if !Arc::ptr_eq(&current, &self.session) {
            return Err(S3Error::expired_token("session changed during transfer"));
        }
        self.last_check = Instant::now();
        Ok(())
    }

    /// Re-check before a multi-object or multi-part operation's next unit
    /// of work (between parts in `CompleteMultipartUpload`, between objects
    /// in `DeleteObjects`). See [`SessionLeash::force`] for what "re-check"
    /// means.
    pub fn checkpoint(&mut self) -> Result<(), S3Error> {
        self.force()
    }
}

#[cfg(test)]
mod tests {
    use actix_web::test::TestRequest;

    use super::*;
    use crate::auth::session::NewSession;
    use y2q_core::crypto::Role;
    use y2q_core::secmem::SecretVec;

    fn new_session(store: &SessionStore, username: &str) -> ([u8; 32], Arc<SessionInfo>) {
        let token = store
            .insert(NewSession {
                username: username.to_owned(),
                role: Role::User,
                created_at: SystemTime::now(),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
                persona: 0,
                revoke_other_sessions: false,
                identity_sk: SecretVec::zeroed(32).unwrap(),
            })
            .unwrap();
        let hash = token.hash();
        let session = store.get_active(&hash).unwrap();
        (hash, session)
    }

    fn leash_for(
        store: &SessionStore,
        token_hash: [u8; 32],
        session: Arc<SessionInfo>,
    ) -> SessionLeash {
        SessionLeash {
            sessions: store.clone(),
            token_hash,
            session,
            bytes_since_check: 0,
            last_check: Instant::now(),
            recheck_bytes: 1024,
            recheck_interval: Duration::from_secs(3600),
        }
    }

    #[test]
    fn force_fails_after_session_revoked() {
        let store = SessionStore::new().unwrap();
        let (hash, session) = new_session(&store, "alice");
        let mut leash = leash_for(&store, hash, session);
        assert!(leash.force().is_ok());
        store.revoke(&hash);
        assert!(leash.force().is_err());
    }

    #[test]
    fn force_fails_after_duress_persona_switch_replaces_the_row() {
        let store = SessionStore::new().unwrap();
        let (hash, session) = new_session(&store, "alice");
        let mut leash = leash_for(&store, hash, session);
        assert!(leash.force().is_ok());

        let duress_sk = SecretVec::zeroed(32).unwrap();
        store.switch_user_to_persona("alice", 1, Role::User, false, &duress_sk);

        let err = leash.force().unwrap_err();
        assert_eq!(err.code, "ExpiredToken");
    }

    #[test]
    fn note_below_threshold_does_not_recheck() {
        let store = SessionStore::new().unwrap();
        let (hash, session) = new_session(&store, "alice");
        let mut leash = leash_for(&store, hash, session);

        // Revoke the session, then a sub-threshold `note` must NOT trip a
        // recheck (no lookup happens, so the revocation isn't observed yet).
        store.revoke(&hash);
        assert!(leash.note(10).is_ok());

        // Crossing the byte threshold forces a recheck, which now observes
        // the revocation.
        assert!(leash.note(2000).is_err());
    }

    fn test_auth_state() -> (AuthState, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let user_store =
            y2q_core::crypto::UserStore::open(&dir.path().join("users.redb"), &[0u8; 32]).unwrap();
        let auth_config = crate::config::AuthConfig {
            default_ttl_seconds: 3600,
            max_ttl_seconds: 86_400,
            session_sweep_interval_seconds: 300,
            min_login_response_ms: 0,
            max_failed_logins: 10,
            lockout_seconds: 900,
            enforce_authorization: false,
            max_refreshes: 0,
        };
        let auth_state = AuthState::new(
            user_store,
            auth_config,
            crate::config::Argon2Config::default(),
        )
        .unwrap();
        (auth_state, dir)
    }

    fn amz_date_from(t: SystemTime) -> String {
        // "YYYY-MM-DDTHH:MM:SS.mmmZ" -> "YYYYMMDDTHHMMSSZ".
        let iso = crate::s3::httpdate::iso8601_from(t);
        format!(
            "{}T{}Z",
            iso[0..10].replace('-', ""),
            iso[11..19].replace(':', "")
        )
    }

    /// Regression proof: a presigned URL is bounded only by its own
    /// `X-Amz-Expires` window, never by `max_clock_skew_secs` — before the
    /// fix, the same skew check applied to header-signed requests also
    /// rejected an otherwise-valid, otherwise-unexpired presigned URL
    /// whose `X-Amz-Date` simply predates `max_clock_skew_secs` (900s),
    /// which is routine for a presigned link handed out minutes or hours
    /// before it's used.
    #[test]
    fn presigned_request_bypasses_clock_skew_but_header_signed_does_not() {
        let (auth_state, _dir) = test_auth_state();
        let token = auth_state
            .sessions
            .insert(NewSession {
                username: "alice".to_owned(),
                role: Role::User,
                created_at: SystemTime::now(),
                expires_at: SystemTime::now() + Duration::from_secs(3600),
                persona: 0,
                revoke_other_sessions: false,
                identity_sk: SecretVec::zeroed(32).unwrap(),
            })
            .unwrap();
        let token_hash = token.hash();

        let s3_config = crate::config::S3Config {
            region: "y2q".to_owned(),
            max_clock_skew_secs: 900,
            ..Default::default()
        };
        let creds = crate::s3::state::S3CredentialStore::new(auth_state.sessions.keyring(), 4);
        let (akid, secret) = creds
            .mint(
                token_hash,
                "alice",
                SystemTime::now() + Duration::from_secs(3600),
                SystemTime::now() + Duration::from_secs(3600),
            )
            .unwrap();
        let s3_state = S3State {
            credentials: creds,
            uploads: crate::s3::state::MultipartRegistry::new(16),
            config: s3_config,
        };

        let auth_state_data = web::Data::new(auth_state);
        let s3_state_data = web::Data::new(s3_state);

        // 20 minutes in the past: stale for the header-signed skew check
        // (max_clock_skew_secs = 900s = 15 min) but well inside a
        // presigned URL's 3600-second X-Amz-Expires window.
        let stale = SystemTime::now() - Duration::from_secs(20 * 60);
        let amz_date = amz_date_from(stale);
        let date_stamp = &amz_date[0..8];
        let region = "y2q";

        let path = "/bucket/key";
        let host = "example.com";
        let signed_headers = vec!["host".to_owned()];
        let mut headers = actix_web::http::header::HeaderMap::new();
        headers.insert(
            actix_web::http::header::HOST,
            actix_web::http::header::HeaderValue::from_static(host),
        );

        // --- Presigned form ---
        let query_no_sig = format!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={akid}%2F{date_stamp}%2F{region}%2Fs3%2Faws4_request&X-Amz-Date={amz_date}&X-Amz-Expires=3600&X-Amz-SignedHeaders=host"
        );
        let canonical_uri = sigv4::canonical_uri(path);
        let canonical_query = sigv4::canonical_query_string(&query_no_sig);
        let (headers_block, signed_headers_joined) =
            sigv4::canonical_headers(&headers, host, &signed_headers);
        let canonical_request = sigv4::canonical_request(
            "GET",
            &canonical_uri,
            &canonical_query,
            &headers_block,
            &signed_headers_joined,
            sigv4::UNSIGNED_PAYLOAD,
        );
        let scope = format!("{date_stamp}/{region}/s3/aws4_request");
        let sts = sigv4::string_to_sign(&amz_date, &scope, &canonical_request);
        let signing_key = sigv4::signing_key(secret.expose().as_bytes(), date_stamp, region, "s3");
        let signature = sigv4::hex_hmac_sha256(&signing_key, sts.as_bytes());

        let presigned_req = TestRequest::with_uri(&format!(
            "{path}?{query_no_sig}&X-Amz-Signature={signature}"
        ))
        .insert_header((actix_web::http::header::HOST, host))
        .app_data(auth_state_data.clone())
        .app_data(s3_state_data.clone())
        .to_http_request();
        let result = verify(&presigned_req);
        assert!(
            result.is_ok(),
            "presigned request with a 20-minute-old X-Amz-Date must succeed: {:?}",
            result.err().map(|e| e.code)
        );

        // --- Header-signed form, identical stale date, no presigned
        // expiry window to rely on ---
        let header_canonical_query = sigv4::canonical_query_string("");
        let header_canonical_request = sigv4::canonical_request(
            "GET",
            &canonical_uri,
            &header_canonical_query,
            &headers_block,
            &signed_headers_joined,
            sigv4::payload_hash_token(&sigv4::PayloadHash::Unsigned),
        );
        let header_sts = sigv4::string_to_sign(&amz_date, &scope, &header_canonical_request);
        let header_signature = sigv4::hex_hmac_sha256(&signing_key, header_sts.as_bytes());
        let auth_header = format!(
            "AWS4-HMAC-SHA256 Credential={akid}/{scope}, SignedHeaders=host, Signature={header_signature}"
        );
        let header_req = TestRequest::with_uri(path)
            .insert_header((actix_web::http::header::HOST, host))
            .insert_header((actix_web::http::header::AUTHORIZATION, auth_header))
            .insert_header(("x-amz-date", amz_date.as_str()))
            .app_data(auth_state_data)
            .app_data(s3_state_data)
            .to_http_request();
        let header_result = verify(&header_req);
        assert!(
            matches!(&header_result, Err(e) if e.code == "RequestTimeTooSkewed"),
            "a header-signed request with the same stale date must still be rejected for skew: {:?}",
            header_result.map(|_| ())
        );
    }
}
