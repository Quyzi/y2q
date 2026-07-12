//! Encryption behavior: object envelope, streaming encryptor, key derivation,
//! metadata cipher, and the in-memory key slot.
//!
//! The object scheme is ML-KEM-768 encapsulation -> HKDF-SHA256 -> AES-256-GCM.
//! Secret keys are wrapped with Argon2id -> AES-256-GCM. The metadata index is
//! sealed under an HMAC-derived metadata encryption key (MEK) and blinded with a
//! derived index key (IK).

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};

/// Envelope encryption for object payloads.
///
/// The v2 chunked format splits the payload into independently sealed,
/// per-chunk-nonced segments so large objects can be decrypted in ranges.
/// There is no unauthenticated passthrough: an envelope with an unrecognized
/// magic is rejected outright rather than treated as legacy plaintext. The
/// content key is bound to the object's `(bucket, key)` address (folded into
/// the HKDF derivation), so a ciphertext valid for one object fails to
/// decrypt if presented under a different address — copying one object's
/// on-disk envelope onto another object's storage location does not grant
/// access to it.
pub trait ObjectCipher {
    /// Per-envelope metadata recorded alongside the ciphertext: envelope version,
    /// KEM and AEAD algorithm identifiers, and ciphertext size.
    type EnvelopeInfo;
    /// Error returned when encapsulation, AEAD, or header parsing fails.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Encapsulate a shared secret to the recipient public key `pk_bytes`, derive
    /// the content key (bound to `bucket`/`key`), and seal `plaintext`. Returns
    /// the complete envelope bytes and the [`EnvelopeInfo`](Self::EnvelopeInfo)
    /// describing what was produced.
    fn encrypt(
        &self,
        pk_bytes: &[u8],
        plaintext: &[u8],
        bucket: &str,
        key: &str,
    ) -> Result<(Vec<u8>, Self::EnvelopeInfo), Self::Error>;

    /// Decapsulate with `sk_bytes` and open an envelope addressed to
    /// `bucket`/`key`, copying the recovered plaintext into a fresh buffer.
    /// Fails if `bucket`/`key` don't match the address the envelope was
    /// originally encrypted for.
    fn decrypt(
        &self,
        sk_bytes: &[u8],
        envelope: &[u8],
        bucket: &str,
        key: &str,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Open an envelope in place, decrypting into the owned input buffer and
    /// returning a view of the plaintext so no copy is made. Suited to large
    /// objects already held in memory. Same `bucket`/`key` binding as
    /// [`decrypt`](Self::decrypt).
    fn decrypt_owned(
        &self,
        sk_bytes: &[u8],
        envelope: BytesMut,
        bucket: &str,
        key: &str,
    ) -> Result<Bytes, Self::Error>;

    /// Open a contiguous run of chunks.
    ///
    /// `preamble` is the fixed header carrying the KEM ciphertext and geometry;
    /// `chunks_ct` is the concatenation of the chunk ciphertexts to open; and
    /// `first_chunk_idx` is the index of the first supplied chunk, which seeds the
    /// per-chunk nonce derivation. Lets a range read decrypt only the chunks it
    /// touches. Same `bucket`/`key` binding as [`decrypt`](Self::decrypt).
    fn decrypt_v2_chunks(
        &self,
        sk_bytes: &[u8],
        preamble: &[u8],
        chunks_ct: &[u8],
        first_chunk_idx: u64,
        bucket: &str,
        key: &str,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Parse a header, returning `(chunk_size, plaintext_len)`. Callers use the
    /// geometry to map a requested byte range onto the chunks that cover it.
    fn parse_v2_geometry(&self, header: &[u8]) -> Result<(u32, u64), Self::Error>;
}

/// Incremental v2 encryptor that seals chunks into a write sink as plaintext
/// arrives, so an object can be encrypted while it is being uploaded without
/// buffering it whole.
///
/// Construction (encapsulating to the recipient key and writing the header) is
/// the implementor's responsibility; this trait covers feeding data and
/// finalizing. [`finish`](Self::finish) consumes a boxed `self` to keep the
/// trait dyn-compatible.
#[async_trait]
pub trait StreamingEncryptor: Send {
    /// The write sink returned to the caller once the stream is finalized.
    type Sink;
    /// Per-envelope metadata produced when the stream is finalized.
    type EnvelopeInfo;
    /// Error returned when AEAD or sink I/O fails.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Encrypt `data` and write the resulting chunks to the sink. Bytes that do
    /// not fill a whole chunk are buffered until the next call or `finish`.
    async fn feed(&mut self, data: &[u8]) -> Result<(), Self::Error>;

    /// Seal any buffered tail as the final chunk, back-patch the plaintext length
    /// into the header, and return the sink together with the resulting
    /// [`EnvelopeInfo`](Self::EnvelopeInfo).
    async fn finish(self: Box<Self>) -> Result<(Self::Sink, Self::EnvelopeInfo), Self::Error>;
}

/// Password-based wrapping of a user's secret key.
///
/// A key-encryption key (KEK) is derived from the password with Argon2id and
/// then used to seal the secret key under AES-256-GCM, so the wrapped form can be
/// stored at rest and only opened with the password.
pub trait KeyDerivation {
    /// Argon2id cost parameters and per-key salt.
    type Params;
    /// The wrapped secret key: nonce plus AEAD ciphertext-with-tag.
    type WrappedKey;
    /// Error returned when the KDF or AEAD fails.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Derive a 32-byte key-encryption key from `password` under `params`.
    fn derive_kek(&self, params: &Self::Params, password: &[u8]) -> Result<[u8; 32], Self::Error>;

    /// Seal `sk_bytes` under a KEK derived from `password` and `params`, producing
    /// a [`WrappedKey`](Self::WrappedKey).
    fn wrap_sk(
        &self,
        sk_bytes: &[u8],
        password: &[u8],
        params: &Self::Params,
    ) -> Result<Self::WrappedKey, Self::Error>;

    /// Re-derive the KEK from `password` and `params` and open a
    /// [`WrappedKey`](Self::WrappedKey), recovering the raw secret-key bytes.
    fn unwrap_sk(
        &self,
        wrapped: &Self::WrappedKey,
        password: &[u8],
        params: &Self::Params,
    ) -> Result<Vec<u8>, Self::Error>;
}

/// Encryption for the metadata index: key derivation, the keyed PRF used to blind
/// lookups, and sealing and opening of metadata blobs.
pub trait MetadataCipher {
    /// Error returned when AEAD or decoding fails.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Derive the metadata encryption key from a user's secret-key bytes. The same
    /// secret key always yields the same MEK, so it can be reconstructed on login.
    fn derive_mek(&self, sk_bytes: &[u8]) -> [u8; 32];

    /// Derive the index key from the MEK. The index key blinds the keys and labels
    /// written to the index, separating them from the data-sealing MEK.
    fn derive_index_key(&self, mek: &[u8; 32]) -> [u8; 32];

    /// Keyed pseudo-random function (HMAC-SHA256). Used to blind object keys and
    /// label values into fixed-size, lookup-stable index entries.
    fn prf(&self, key: &[u8; 32], data: &[u8]) -> [u8; 32];

    /// Seal a metadata JSON blob under `mek` for storage in the index.
    fn encrypt_meta(&self, mek: &[u8; 32], json: &[u8]) -> Result<Vec<u8>, Self::Error>;

    /// Open a metadata blob under `mek`. A blob without the recognized version
    /// byte is rejected rather than treated as legacy plaintext.
    fn decrypt_meta(&self, mek: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

/// Shared, in-memory holder for the active metadata encryption key and its
/// derived index key.
///
/// The keys live only in memory for the duration of a login session.
/// Implementations are expected to zeroize key material on
/// [`clear`](Self::clear) and to support concurrent access from request handlers.
pub trait KeySlot: Send + Sync {
    /// Install `mek` as the active key, deriving and caching the index key from it.
    fn install(&self, mek: [u8; 32]);

    /// Zeroize and drop the stored keys. Returns whether a key was present.
    fn clear(&self) -> bool;

    /// The active metadata encryption key, or `None` if no key is installed.
    fn mek(&self) -> Option<[u8; 32]>;

    /// The active `(mek, index_key)` pair. Each element is `None` when no key is
    /// installed.
    fn mek_ik(&self) -> (Option<[u8; 32]>, Option<[u8; 32]>);

    /// Whether a key is currently installed.
    fn is_set(&self) -> bool;
}
