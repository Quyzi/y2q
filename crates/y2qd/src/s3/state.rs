//! In-memory S3 credential store and multipart-upload registry.
//!
//! Both are session-bound: a credential's authority is re-derived from
//! [`SessionStore::get_active`] on every request (see `crate::s3::auth`), and
//! a multipart upload is owned by the session that created it. Neither
//! structure persists across a restart, matching [`SessionStore`] itself.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use dashmap::DashMap;
use rand::Rng;
use y2q_core::LabelSet;
use y2q_core::secmem::{SealedSecret, SecretString, SecretVec};

use crate::auth::AuthError;
use crate::auth::keyring::SessionKeyring;
use crate::auth::session::SessionStore;
use crate::config::S3Config;
use crate::s3::error::S3Error;

/// Access key ids are `"Y2Q"` followed by 17 characters from this alphabet
/// (indexed by `byte % 32`, exactly uniform since 256 / 32 = 8).
const AKID_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const AKID_SUFFIX_LEN: usize = 17;
/// Secret access keys are the standard-base64 encoding of this many CSPRNG
/// bytes. 30 is a multiple of 3, so the encoding is exactly 40 characters
/// with no padding.
const SECRET_RAW_LEN: usize = 30;
/// Upload ids are URL-safe-base64-no-pad of this many CSPRNG bytes.
const UPLOAD_ID_RAW_LEN: usize = 16;

/// One S3 temporary credential, bound to the session that minted it.
pub struct S3Credential {
    pub access_key_id: String,
    /// SHA-256 of the bearer token of the owning session. The only link to
    /// authority: every request re-resolves it through [`SessionStore`].
    pub token_hash: [u8; 32],
    pub username: String,
    /// Secret access key, sealed under the session keyring.
    secret: SealedSecret,
    pub created_at: SystemTime,
    /// Never later than the owning session's `expires_at`.
    pub expires_at: SystemTime,
}

impl S3Credential {
    pub fn is_expired(&self, now: SystemTime) -> bool {
        now >= self.expires_at
    }

    /// Open the secret into guarded memory for the duration of `f`. The
    /// opened buffer is dropped as soon as `f` returns.
    pub fn with_secret<R>(
        &self,
        keyring: &SessionKeyring,
        f: impl FnOnce(&[u8]) -> R,
    ) -> Result<R, AuthError> {
        let opened = keyring.open_s3_secret(&self.token_hash, &self.access_key_id, &self.secret)?;
        Ok(f(&opened))
    }
}

/// In-memory map of access key id -> credential. Cheap to clone (`Arc` inside).
#[derive(Clone)]
pub struct S3CredentialStore {
    inner: Arc<DashMap<String, Arc<S3Credential>>>,
    keyring: Arc<SessionKeyring>,
    max_per_session: usize,
}

impl S3CredentialStore {
    pub fn new(keyring: Arc<SessionKeyring>, max_per_session: usize) -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            keyring,
            max_per_session,
        }
    }

    /// Mint a credential for `token_hash`, expiring at
    /// `min(requested_expires_at, session_expires_at)` — never later than
    /// the owning session's own expiry. Evicts this session's oldest
    /// credential(s) if the mint pushes it past `max_per_session`. Returns
    /// `(access_key_id, secret_access_key)`; the secret is returned exactly
    /// once and is never recoverable afterwards.
    pub fn mint(
        &self,
        token_hash: [u8; 32],
        username: &str,
        requested_expires_at: SystemTime,
        session_expires_at: SystemTime,
    ) -> Result<(String, SecretString), AuthError> {
        let expires_at = requested_expires_at.min(session_expires_at);

        let access_key_id = generate_access_key_id();
        let secret_bytes = generate_secret_bytes()?;
        let secret_b64 = {
            let mut out = vec![0u8; SECRET_RAW_LEN * 4 / 3];
            let n = BASE64_STANDARD
                .encode_slice(&secret_bytes, &mut out)
                .expect("40-byte destination exactly fits base64(30 bytes)");
            out.truncate(n);
            out
        };
        // Seal the base64-encoded string's bytes, not the pre-encoding raw
        // bytes: the client's actual signing secret (what `with_secret`
        // must later hand back to the SigV4 HMAC) is the string it received
        // from `mint`, not an intermediate representation never sent over
        // the wire.
        let sealed = self
            .keyring
            .seal_s3_secret(&token_hash, &access_key_id, &secret_b64)?;
        let secret_str = SecretString::from_str(
            std::str::from_utf8(&secret_b64).expect("base64 output is ASCII"),
        )
        .map_err(|e| AuthError::Backend(e.to_string()))?;

        let cred = Arc::new(S3Credential {
            access_key_id: access_key_id.clone(),
            token_hash,
            username: username.to_owned(),
            secret: sealed,
            created_at: SystemTime::now(),
            expires_at,
        });
        self.inner.insert(access_key_id.clone(), cred);

        // Trim after inserting, not before: a pre-insert check-then-act
        // (check `len() >= max`, evict oldest, then insert) lets two
        // concurrent mints both observe `len() == max`, both evict the
        // same oldest entry, and both insert — leaving `max + 1` live
        // credentials. Trimming post-insert is idempotent and
        // self-healing regardless of how concurrent mints interleave: it
        // always converges on at most `max_per_session` credentials.
        let mut remaining = self.list_for_session(&token_hash);
        remaining.sort_by_key(|c| c.created_at);
        while remaining.len() > self.max_per_session {
            let oldest = remaining.remove(0);
            self.inner.remove(&oldest.access_key_id);
        }
        Ok((access_key_id, secret_str))
    }

    pub fn get(&self, access_key_id: &str) -> Option<Arc<S3Credential>> {
        self.inner.get(access_key_id).map(|r| Arc::clone(r.value()))
    }

    pub fn remove(&self, access_key_id: &str) -> bool {
        self.inner.remove(access_key_id).is_some()
    }

    pub fn list_for_session(&self, token_hash: &[u8; 32]) -> Vec<Arc<S3Credential>> {
        self.inner
            .iter()
            .filter(|r| &r.value().token_hash == token_hash)
            .map(|r| Arc::clone(r.value()))
            .collect()
    }

    pub fn keyring(&self) -> &SessionKeyring {
        &self.keyring
    }

    /// Re-bind every credential of `old` to `new` after
    /// `SessionStore::reissue` rotated the session's token hash. The sealed
    /// secret's AAD includes the hash (`auth::keyring::s3_secret_aad`), so
    /// each secret is opened under the old binding and re-sealed under the
    /// new one. A credential whose secret cannot be re-sealed is dropped,
    /// never left unresolvable. Returns the number re-bound.
    pub fn rekey_session(&self, old: &[u8; 32], new: &[u8; 32]) -> usize {
        let mut rekeyed = 0;
        for cred in self.list_for_session(old) {
            let resealed = self
                .keyring
                .open_s3_secret(old, &cred.access_key_id, &cred.secret)
                .and_then(|opened| {
                    self.keyring
                        .seal_s3_secret(new, &cred.access_key_id, &opened)
                });
            match resealed {
                Ok(sealed) => {
                    let rebuilt = Arc::new(S3Credential {
                        access_key_id: cred.access_key_id.clone(),
                        token_hash: *new,
                        username: cred.username.clone(),
                        secret: sealed,
                        created_at: cred.created_at,
                        expires_at: cred.expires_at,
                    });
                    self.inner.insert(cred.access_key_id.clone(), rebuilt);
                    rekeyed += 1;
                }
                Err(error) => {
                    tracing::error!(
                        access_key_id = %cred.access_key_id,
                        %error,
                        "failed to re-key S3 credential after token refresh; dropping"
                    );
                    self.inner.remove(&cred.access_key_id);
                }
            }
        }
        rekeyed
    }

    /// Drop every credential that has expired or whose session is gone.
    /// Returns the number removed.
    pub fn sweep(&self, sessions: &SessionStore) -> usize {
        let now = SystemTime::now();
        let stale: Vec<String> = self
            .inner
            .iter()
            .filter(|r| {
                let cred = r.value();
                cred.is_expired(now) || sessions.get_active(&cred.token_hash).is_err()
            })
            .map(|r| r.key().clone())
            .collect();
        let removed = stale.len();
        for akid in stale {
            if let Some((_, cred)) = self.inner.remove(&akid) {
                tracing::debug!(
                    access_key_id = %akid,
                    username = %cred.username,
                    "swept expired S3 credential"
                );
            }
        }
        removed
    }
}

fn generate_access_key_id() -> String {
    let mut raw = [0u8; AKID_SUFFIX_LEN];
    rand::rng().fill_bytes(&mut raw);
    let mut id = String::with_capacity(3 + AKID_SUFFIX_LEN);
    id.push_str("Y2Q");
    for b in raw {
        id.push(AKID_ALPHABET[(b % 32) as usize] as char);
    }
    id
}

fn generate_secret_bytes() -> Result<SecretVec, AuthError> {
    let mut secret =
        SecretVec::zeroed(SECRET_RAW_LEN).map_err(|e| AuthError::Backend(e.to_string()))?;
    rand::rng().fill_bytes(secret.as_mut());
    Ok(secret)
}

/// One in-flight multipart upload. Bound to the session that created it:
/// when that session dies, the upload is aborted and its parts deleted by
/// the background sweeper (see `crate::s3::multipart::abort_upload`).
pub struct MultipartUpload {
    pub upload_id: String,
    pub bucket: String,
    pub key: String,
    pub token_hash: [u8; 32],
    pub username: String,
    pub created_at: SystemTime,
    /// Headers captured at `CreateMultipartUpload` and applied to the
    /// assembled object at `Complete`.
    pub labels: LabelSet,
    /// part number -> (plaintext size, etag) of stored part objects.
    /// `Arc`-shared so `MultipartRegistry::rekey_session` can rebuild the
    /// registry entry under a new token hash while an in-flight
    /// `upload_part` still holding the pre-refresh `Arc<MultipartUpload>`
    /// keeps writing into the same map — no recorded part is lost to a
    /// refresh racing a part upload.
    pub parts: Arc<Mutex<BTreeMap<u16, (u64, String)>>>,
}

/// In-memory registry of in-flight multipart uploads. Cheap to clone.
#[derive(Clone)]
pub struct MultipartRegistry {
    inner: Arc<DashMap<String, Arc<MultipartUpload>>>,
    max_per_session: usize,
}

/// Fields needed to register a new upload; [`MultipartRegistry::create`]
/// allocates `upload_id`, `created_at`, and the empty parts map itself —
/// the caller never constructs a [`MultipartUpload`] directly, so
/// `upload_id` is only ever written by the allocator.
pub struct NewUpload {
    pub bucket: String,
    pub key: String,
    pub token_hash: [u8; 32],
    pub username: String,
    pub labels: LabelSet,
}

impl MultipartRegistry {
    pub fn new(max_per_session: usize) -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            max_per_session,
        }
    }

    /// Allocate a fresh upload id (independent of any caller-chosen name so
    /// registry entries can't collide) and register the upload. Rejects
    /// with [`S3Error::slow_down`] when the owning session already holds
    /// `max_per_session` in-flight uploads — rejecting, not FIFO-evicting,
    /// since evicting an upload would delete a client's already-uploaded
    /// parts.
    pub fn create(&self, new: NewUpload) -> Result<Arc<MultipartUpload>, S3Error> {
        if self.list_for_session(&new.token_hash).len() >= self.max_per_session {
            return Err(S3Error::slow_down(
                "too many in-flight multipart uploads for this session; complete or abort an existing upload",
            ));
        }
        let upload = MultipartUpload {
            upload_id: generate_upload_id(),
            bucket: new.bucket,
            key: new.key,
            token_hash: new.token_hash,
            username: new.username,
            created_at: SystemTime::now(),
            labels: new.labels,
            parts: Arc::new(Mutex::new(BTreeMap::new())),
        };
        let arc = Arc::new(upload);
        self.inner.insert(arc.upload_id.clone(), Arc::clone(&arc));
        Ok(arc)
    }

    pub fn get(&self, upload_id: &str) -> Option<Arc<MultipartUpload>> {
        self.inner.get(upload_id).map(|r| Arc::clone(r.value()))
    }

    pub fn remove(&self, upload_id: &str) -> Option<Arc<MultipartUpload>> {
        self.inner.remove(upload_id).map(|(_, v)| v)
    }

    /// Every currently-registered upload, regardless of owning session or
    /// bucket. Used by the age-based half of the background sweeper.
    pub fn all(&self) -> Vec<Arc<MultipartUpload>> {
        self.inner.iter().map(|r| Arc::clone(r.value())).collect()
    }
    pub fn list_for_bucket(&self, bucket: &str) -> Vec<Arc<MultipartUpload>> {
        self.inner
            .iter()
            .filter(|r| r.value().bucket == bucket)
            .map(|r| Arc::clone(r.value()))
            .collect()
    }

    pub fn list_for_session(&self, token_hash: &[u8; 32]) -> Vec<Arc<MultipartUpload>> {
        self.inner
            .iter()
            .filter(|r| &r.value().token_hash == token_hash)
            .map(|r| Arc::clone(r.value()))
            .collect()
    }

    /// Upload ids whose owning session is no longer live.
    pub fn orphans(&self, sessions: &SessionStore) -> Vec<Arc<MultipartUpload>> {
        self.inner
            .iter()
            .filter(|r| sessions.get_active(&r.value().token_hash).is_err())
            .map(|r| Arc::clone(r.value()))
            .collect()
    }

    /// Re-bind every in-flight upload of `old` to `new` after
    /// `SessionStore::reissue` rotated the session's token hash. The
    /// rebuilt entry shares the same `parts` map (`Arc`-cloned), so a
    /// concurrent `upload_part` still holding the pre-refresh
    /// `Arc<MultipartUpload>` cannot lose its recorded part. Returns the
    /// number re-bound.
    pub fn rekey_session(&self, old: &[u8; 32], new: &[u8; 32]) -> usize {
        let matching: Vec<Arc<MultipartUpload>> = self
            .inner
            .iter()
            .filter(|r| r.value().token_hash == *old)
            .map(|r| Arc::clone(r.value()))
            .collect();
        let rekeyed = matching.len();
        for upload in matching {
            let rebuilt = Arc::new(MultipartUpload {
                upload_id: upload.upload_id.clone(),
                bucket: upload.bucket.clone(),
                key: upload.key.clone(),
                token_hash: *new,
                username: upload.username.clone(),
                created_at: upload.created_at,
                labels: upload.labels.clone(),
                parts: Arc::clone(&upload.parts),
            });
            self.inner.insert(rebuilt.upload_id.clone(), rebuilt);
        }
        rekeyed
    }
}

fn generate_upload_id() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut raw = [0u8; UPLOAD_ID_RAW_LEN];
    rand::rng().fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

/// Shared S3-gateway state registered as `web::Data` on both listeners.
pub struct S3State {
    pub credentials: S3CredentialStore,
    pub uploads: MultipartRegistry,
    pub config: S3Config,
}

impl S3State {
    /// Re-bind every credential and in-flight upload of `old` to `new`
    /// after `SessionStore::reissue` rotated the session's token hash.
    /// Called from `auth::handlers::refresh` — re-keying never fails the
    /// refresh itself.
    pub fn rekey_session(&self, old: &[u8; 32], new: &[u8; 32]) {
        let credentials = self.credentials.rekey_session(old, new);
        let uploads = self.uploads.rekey_session(old, new);
        tracing::debug!(
            credentials,
            uploads,
            "re-keyed S3 state after token refresh"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::session::{NewSession, SessionStore};
    use std::time::Duration;
    use y2q_core::crypto::Role;

    /// Regression proof for the token-refresh S3-state blocker: before the
    /// fix, `SessionStore::reissue` rotated the session's token hash with
    /// no corresponding update to `S3CredentialStore`/`MultipartRegistry`,
    /// so every live credential 403'd (`get_active` on the old hash fails)
    /// and the sweeper reclaimed in-flight multipart uploads out from
    /// under their still-live session.
    #[test]
    fn rekey_session_preserves_credentials_and_uploads_after_token_refresh() {
        let sessions = SessionStore::new().unwrap();
        let keyring = sessions.keyring();
        let old_token = sessions
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
        let old_hash = old_token.hash();

        let creds = S3CredentialStore::new(Arc::clone(&keyring), 4);
        let uploads = MultipartRegistry::new(16);

        let (akid, secret) = creds
            .mint(
                old_hash,
                "alice",
                SystemTime::now() + Duration::from_secs(600),
                SystemTime::now() + Duration::from_secs(3600),
            )
            .unwrap();

        let upload = uploads
            .create(NewUpload {
                bucket: "b".to_owned(),
                key: "k".to_owned(),
                token_hash: old_hash,
                username: "alice".to_owned(),
                labels: LabelSet::new(),
            })
            .unwrap();
        upload
            .parts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(1, (5 * 1024 * 1024, "\"etag\"".to_owned()));
        let upload_id = upload.upload_id.clone();

        // Refresh: reissue the session token, then re-key S3 state exactly
        // as `auth::handlers::refresh` does.
        let new_token = sessions
            .reissue(&old_hash, SystemTime::now() + Duration::from_secs(3600), 1)
            .unwrap();
        let new_hash = new_token.hash();
        assert_eq!(creds.rekey_session(&old_hash, &new_hash), 1);
        assert_eq!(uploads.rekey_session(&old_hash, &new_hash), 1);

        // The credential resolves under the new hash and its secret
        // round-trips byte-for-byte through the re-seal.
        let cred = creds
            .get(&akid)
            .expect("credential still present after rekey");
        assert_eq!(cred.token_hash, new_hash);
        let opened = cred.with_secret(&keyring, |s| s.to_vec()).unwrap();
        assert_eq!(std::str::from_utf8(&opened).unwrap(), secret.expose());

        // The upload still resolves under the new hash, and its recorded
        // part survived (same `Arc`-shared parts map).
        let upload = uploads
            .get(&upload_id)
            .expect("upload still present after rekey");
        assert_eq!(upload.token_hash, new_hash);
        assert_eq!(
            upload.parts.lock().unwrap_or_else(|e| e.into_inner()).len(),
            1
        );

        // Neither store considers anything orphaned or expired: the
        // session (under its new hash) is still live.
        assert!(uploads.orphans(&sessions).is_empty());
        assert_eq!(creds.sweep(&sessions), 0);
    }
}
