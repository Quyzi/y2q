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
    pub signing_key: [u8; 32],
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

    // 3. Clock skew.
    let now = SystemTime::now();
    let request_time = sigv4::parse_amz_date(&parsed.amz_date)
        .map_err(|_| S3Error::authorization_header_malformed("malformed X-Amz-Date"))?;
    let skew = now
        .duration_since(request_time)
        .or_else(|_| request_time.duration_since(now))
        .unwrap_or(Duration::MAX);
    if skew.as_secs() > s3.config.max_clock_skew_secs {
        return Err(S3Error::request_time_too_skewed());
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

    // 6. The owning session must still be live. This single call is what
    // makes logout, natural expiry, and role/lockout changes on the REST
    // listener take effect on the S3 surface immediately.
    let session: Arc<SessionInfo> = match auth_state.sessions.get_active(&cred.token_hash) {
        Ok(s) => s,
        Err(_) => {
            s3.credentials.remove(&akid);
            return Err(S3Error::expired_token(
                "the session backing this credential has expired or been revoked",
            ));
        }
    };

    // 7. A disabled account authenticates but may not act.
    if auth_state.config.enforce_authorization && session.role == y2q_core::crypto::Role::Disabled {
        return Err(S3Error::access_denied("Access Denied"));
    }

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
    let payload_token = sigv4::payload_hash_token(&parsed.payload).to_owned();
    let canonical_request = sigv4::canonical_request(
        req.method().as_str(),
        &canonical_uri,
        &canonical_query,
        &headers_block,
        &signed_headers_joined,
        &payload_token,
    );
    let scope_str = format!(
        "{}/{}/{}/aws4_request",
        parsed.scope.date, parsed.scope.region, parsed.scope.service
    );
    let string_to_sign = sigv4::string_to_sign(&parsed.amz_date, &scope_str, &canonical_request);

    let scope_date = parsed.scope.date.clone();
    let scope_region = parsed.scope.region.clone();
    let scope_service = parsed.scope.service.clone();
    let signing_key = cred
        .with_secret(s3.credentials.keyring(), |secret| {
            sigv4::signing_key(secret, &scope_date, &scope_region, &scope_service)
        })
        .map_err(S3Error::from)?;
    let expected_signature = sigv4::hex_hmac_sha256(&signing_key, string_to_sign.as_bytes());
    if !sigv4::signatures_match(&expected_signature, &parsed.signature) {
        return Err(S3Error::signature_does_not_match());
    }

    // 10. Build the shared `Authenticated` value.
    let auth = Authenticated {
        username: session.username.clone(),
        role: session.role,
        token_hash: cred.token_hash,
        session: Arc::clone(&session),
        authz_enforced: auth_state.config.enforce_authorization,
    };

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
    pub fn force(&mut self) -> Result<(), S3Error> {
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
    /// in `DeleteObjects`).
    pub fn checkpoint(&mut self) -> Result<(), S3Error> {
        self.force()
    }
}

#[cfg(test)]
mod tests {
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
}
