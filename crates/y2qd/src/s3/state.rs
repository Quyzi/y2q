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

    /// Mint a credential for `token_hash`, FIFO-evicting this session's
    /// oldest credential when it already holds `max_per_session`. Returns
    /// `(access_key_id, secret_access_key)`; the secret is returned exactly
    /// once and is never recoverable afterwards.
    pub fn mint(
        &self,
        token_hash: [u8; 32],
        username: &str,
        expires_at: SystemTime,
    ) -> Result<(String, SecretString), AuthError> {
        let existing = self.list_for_session(&token_hash);
        if existing.len() >= self.max_per_session
            && let Some(oldest) = existing.iter().min_by_key(|c| c.created_at)
        {
            self.inner.remove(&oldest.access_key_id);
        }

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
    pub parts: Mutex<BTreeMap<u16, (u64, String)>>,
}

/// In-memory registry of in-flight multipart uploads. Cheap to clone.
#[derive(Clone)]
pub struct MultipartRegistry {
    inner: Arc<DashMap<String, Arc<MultipartUpload>>>,
}

impl Default for MultipartRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MultipartRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    /// Allocate a fresh upload id (independent of any caller-chosen name so
    /// registry entries can't collide) and register `upload` under it.
    pub fn create(&self, mut upload: MultipartUpload) -> Arc<MultipartUpload> {
        upload.upload_id = generate_upload_id();
        let arc = Arc::new(upload);
        self.inner.insert(arc.upload_id.clone(), Arc::clone(&arc));
        arc
    }

    pub fn get(&self, upload_id: &str) -> Option<Arc<MultipartUpload>> {
        self.inner.get(upload_id).map(|r| Arc::clone(r.value()))
    }

    pub fn remove(&self, upload_id: &str) -> Option<Arc<MultipartUpload>> {
        self.inner.remove(upload_id).map(|(_, v)| v)
    }

    pub fn list_for_bucket(&self, bucket: &str) -> Vec<Arc<MultipartUpload>> {
        self.inner
            .iter()
            .filter(|r| r.value().bucket == bucket)
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
