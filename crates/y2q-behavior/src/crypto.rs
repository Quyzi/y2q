//! Encryption behavior: object envelope, streaming encryptor, persona
//! password wrapping, node-key derivation, and the in-memory node-key slot.
//!
//! The object scheme is ML-KEM-768 encapsulation -> HKDF-SHA256 -> AES-256-GCM,
//! sealed to the *current epoch of a bucket's* keypair (not a single
//! deployment-wide key) — see [`ObjectCipher`]. A user's persona identity
//! secret key is wrapped with Argon2id -> AES-256-GCM per credential slot
//! (one slot per password the account accepts) — see [`KeyDerivation`]. The
//! metadata index, on-disk paths, object-metadata sidecars, and bucket-config
//! sidecars are each sealed under their own key, all derived directly (by
//! keyed HMAC-PRF) from a single operator-supplied node key installed once at
//! boot — see [`MetadataCipher`] and [`KeySlot`].

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};

/// Envelope encryption for object payloads.
///
/// The v3 chunked format splits the payload into independently sealed,
/// per-chunk-nonced segments so large objects can be decrypted in ranges.
/// There is no unauthenticated passthrough: an envelope with an unrecognized
/// magic (including the retired v1 whole-object and v2 chunked formats) is
/// rejected outright rather than treated as legacy plaintext. The content key
/// is bound to the object's `(bucket, key)` address (folded into the HKDF
/// derivation), so a ciphertext valid for one object fails to decrypt if
/// presented under a different address — copying one object's on-disk
/// envelope onto another object's storage location does not grant access to
/// it.
///
/// Every envelope also carries a `key_epoch`, recording which epoch of the
/// *bucket's* ML-KEM-768 keypair `pk_bytes`/`sk_bytes` belongs to (not a
/// single deployment-wide keypair). `key_epoch` is cleartext — a reader needs
/// it before it can select the matching secret key — but it is still
/// authenticated as part of every chunk's AAD, so tampering with it to point
/// at a different, still-valid epoch is caught by the AEAD tag rather than
/// silently succeeding. Resolving which epoch's secret key to pass as
/// `sk_bytes` (via the caller's persona and the bucket's grant list) is
/// outside this trait's scope; it only ever sees the bytes it's handed.
pub trait ObjectCipher {
    /// Per-envelope metadata recorded alongside the ciphertext: envelope
    /// version, KEM and AEAD algorithm identifiers, ciphertext size, and the
    /// bucket key epoch the envelope was sealed under.
    type EnvelopeInfo;
    /// Error returned when encapsulation, AEAD, or header parsing fails.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Encapsulate a shared secret to the recipient public key `pk_bytes`
    /// (the current epoch of a bucket's keypair), derive the content key
    /// (bound to `bucket`/`key`), and seal `plaintext` under `key_epoch`.
    /// Returns the complete envelope bytes and the
    /// [`EnvelopeInfo`](Self::EnvelopeInfo) describing what was produced.
    fn encrypt(
        &self,
        pk_bytes: &[u8],
        key_epoch: u32,
        plaintext: &[u8],
        bucket: &str,
        key: &str,
    ) -> Result<(Vec<u8>, Self::EnvelopeInfo), Self::Error>;

    /// Decapsulate with `sk_bytes` and open an envelope addressed to
    /// `bucket`/`key`, copying the recovered plaintext into a fresh buffer.
    /// `sk_bytes` must be the secret key for the epoch the envelope's header
    /// records (itself authenticated — see the trait docs); supplying the
    /// wrong epoch's key derives the wrong content key and every chunk fails
    /// to authenticate the same way a wrong `bucket`/`key` address does.
    fn decrypt(
        &self,
        sk_bytes: &[u8],
        envelope: &[u8],
        bucket: &str,
        key: &str,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Open an envelope in place, decrypting into the owned input buffer and
    /// returning a view of the plaintext so no copy is made. Suited to large
    /// objects already held in memory. Same `bucket`/`key`/epoch binding as
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
    /// `preamble` is the fixed header carrying the KEM ciphertext and
    /// geometry; `chunks_ct` is the concatenation of the chunk ciphertexts to
    /// open; and `first_chunk_idx` is the index of the first supplied chunk,
    /// which seeds the per-chunk nonce derivation. Lets a range read decrypt
    /// only the chunks it touches. Same `bucket`/`key`/epoch binding as
    /// [`decrypt`](Self::decrypt).
    fn decrypt_v3_chunks(
        &self,
        sk_bytes: &[u8],
        preamble: &[u8],
        chunks_ct: &[u8],
        first_chunk_idx: u64,
        bucket: &str,
        key: &str,
    ) -> Result<Vec<u8>, Self::Error>;

    /// Parse a header, returning `(key_epoch, chunk_size, plaintext_len)`.
    /// Callers use `key_epoch` to resolve the matching secret key before
    /// calling [`decrypt_v3_chunks`](Self::decrypt_v3_chunks), and the
    /// geometry to map a requested byte range onto the chunks that cover it.
    fn parse_v3_geometry(&self, header: &[u8]) -> Result<(u32, u32, u64), Self::Error>;
}

/// Incremental v3 encryptor that seals chunks into a write sink as plaintext
/// arrives, so an object can be encrypted while it is being uploaded without
/// buffering it whole.
///
/// Construction (encapsulating to the recipient key, recording `key_epoch`,
/// and writing the header) is the implementor's responsibility; this trait
/// covers feeding data and finalizing. [`finish`](Self::finish) consumes a
/// boxed `self` to keep the trait dyn-compatible.
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

/// Password-based wrapping of a persona's identity secret key.
///
/// Every user record carries a fixed number of credential slots (one slot
/// per password the account accepts, so a duress password can unwrap a
/// separate, restricted persona instead of the real one — unused slots hold
/// a real, byte-shape-identical keypair wrapped under a discarded random key,
/// so nothing on disk reveals how many passwords are actually in use). A
/// key-encryption key (KEK) is derived from the password with Argon2id and
/// then used to seal the slot's identity secret key under AES-256-GCM, so the
/// wrapped form can be stored at rest and only opened with the password.
pub trait KeyDerivation {
    /// Argon2id cost parameters and salt, shared by every slot on a record.
    type Params;
    /// The wrapped secret key: nonce plus AEAD ciphertext-with-tag.
    type WrappedKey;
    /// Error returned when the KDF or AEAD fails.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Derive a 32-byte key-encryption key from `password` under `params`.
    fn derive_kek(&self, params: &Self::Params, password: &[u8]) -> Result<[u8; 32], Self::Error>;

    /// Seal `sk_bytes` (a persona's identity secret key) under a KEK derived
    /// from `password` and `params`, producing a
    /// [`WrappedKey`](Self::WrappedKey).
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

/// Encryption for server-structural state: the metadata index, on-disk
/// paths, object-metadata sidecars, and bucket-config sidecars. Every key
/// here derives directly (flat keyed-HMAC, not a chained KEK) from a single
/// operator-supplied node key, installed once at boot — never from any
/// user's password. A compromised user account therefore never carries the
/// power to decrypt this layer; only the operator holding the node key can.
pub trait MetadataCipher {
    /// Error returned when AEAD or decoding fails.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Keyed pseudo-random function (HMAC-SHA256), the single primitive every
    /// derivation below is built from: `derive_x(nk) = prf(nk, LABEL_X)` for
    /// a fixed, distinct label per key. Also used directly to blind object
    /// keys and label values into fixed-size, lookup-stable index entries.
    fn prf(&self, key: &[u8; 32], data: &[u8]) -> [u8; 32];

    /// Derive the Index Key from the node key. Blinds the keys and labels
    /// written to the metadata index and whole-file-encrypts the index file.
    fn derive_index_key(&self, node_key: &[u8; 32]) -> [u8; 32];

    /// Derive the Path Key from the node key. Keyed-hashes on-disk bucket and
    /// object directory names so the filesystem layout does not reveal
    /// plaintext bucket/key names to anyone without the node key.
    fn derive_path_key(&self, node_key: &[u8; 32]) -> [u8; 32];

    /// Derive the Object Metadata Key (OMK) from the node key. Seals each
    /// object's metadata sidecar (size, checksum, labels, key epoch, ...).
    fn derive_object_metadata_key(&self, node_key: &[u8; 32]) -> [u8; 32];

    /// Derive the Bucket Config Key from the node key. Seals each bucket's
    /// config sidecar (owner, ACL, quota, and bucket key material).
    fn derive_bucket_config_key(&self, node_key: &[u8; 32]) -> [u8; 32];

    /// Seal a metadata JSON blob under a derived key (OMK for object
    /// metadata, the bucket config key for bucket config) for storage,
    /// bound to `object_id` via AAD so the blob cannot be relocated to a
    /// different object's/bucket's storage location and still decrypt.
    fn encrypt_meta(&self, key: &[u8; 32], json: &[u8], object_id: &str) -> Result<Vec<u8>, Self::Error>;

    /// Open a metadata blob under a derived key, requiring it to have been
    /// sealed for the same `object_id`. A blob without the recognized
    /// version byte is rejected rather than treated as legacy plaintext; a
    /// blob sealed for a different object fails the same way as a tampered
    /// blob.
    fn decrypt_meta(&self, key: &[u8; 32], blob: &[u8], object_id: &str) -> Result<Vec<u8>, Self::Error>;
}

/// Shared, in-memory holder for the node-derived structural keys (Index Key,
/// Path Key, Object Metadata Key, Bucket Config Key).
///
/// Installed exactly once, at boot, from the operator-supplied node key —
/// never from a login. There is no idle-drop or per-session lifetime: the
/// daemon cannot serve anything without these, so once installed they live
/// for the process lifetime. Shared (behind an `Arc`) by the storage backend
/// and its metadata index so a single install covers both. Implementations
/// are expected to zeroize key material if the slot is ever replaced and to
/// support concurrent access from request handlers.
pub trait KeySlot: Send + Sync {
    /// Install `node_key`, deriving and storing the four structural keys.
    /// Replaces any prior value. Called exactly once, at boot.
    fn install(&self, node_key: [u8; 32]);

    /// A copy of the Index Key, if installed.
    fn index_key(&self) -> Option<[u8; 32]>;

    /// A copy of the Path Key, if installed.
    fn path_key(&self) -> Option<[u8; 32]>;

    /// A copy of the Object Metadata Key, if installed.
    fn object_metadata_key(&self) -> Option<[u8; 32]>;

    /// A copy of the Bucket Config Key, if installed.
    fn bucket_config_key(&self) -> Option<[u8; 32]>;

    /// Whether the node key has been installed.
    fn is_set(&self) -> bool;
}
