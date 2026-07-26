//! Resolve the operator-supplied node key at boot.
//!
//! The node key is never auto-generated — the daemon refuses to start
//! without one. It may be supplied as raw bytes, hex, or base64, via either
//! `Y2QD_NODE_KEY` (takes precedence) or a file named by `[crypto]
//! node_key_file`. Whatever the input encoding or length (≥ 32 bytes),
//! [`extract_node_key`] canonicalizes it to one deterministic 32-byte key.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::CryptoError;

/// Env var carrying the node key directly. Takes precedence over
/// `node_key_file` when both are set.
pub const NODE_KEY_ENV_VAR: &str = "Y2QD_NODE_KEY";

/// Env var carrying the *new* node key for `--rotate-node-key`. Takes
/// precedence over `--new-node-key-file`, mirroring [`NODE_KEY_ENV_VAR`]'s
/// relationship to `node_key_file`.
pub const NEW_NODE_KEY_ENV_VAR: &str = "Y2QD_NEW_NODE_KEY";

/// HKDF-Extract salt used to canonicalize operator-supplied key material to
/// the 32-byte node key. Bumped if the canonicalization changes.
const NODE_KEY_EXTRACT_SALT: &[u8] = b"y2q/v3/node-key";

/// Minimum accepted length, in raw decoded bytes, of supplied node-key
/// material. A floor against a truncated or half-pasted secret — it does
/// **not** prove entropy; see the module-level docs on why the operator must
/// still supply CSPRNG output.
const MIN_NODE_KEY_BYTES: usize = 32;

/// Resolve the node key. `Y2QD_NODE_KEY` takes precedence over
/// `node_key_file`. Returns [`CryptoError::NodeKeyMissing`] when neither is
/// set, and never falls back to generating one.
pub fn load_node_key(node_key_file: &str) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    load_node_key_via(NODE_KEY_ENV_VAR, node_key_file)
}

/// Resolve the *new* node key for `--rotate-node-key`. `Y2QD_NEW_NODE_KEY`
/// takes precedence over `new_node_key_file`. Same rules as
/// [`load_node_key`], just a different env var / file.
pub fn load_new_node_key(new_node_key_file: &str) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    load_node_key_via(NEW_NODE_KEY_ENV_VAR, new_node_key_file)
}

fn load_node_key_via(env_var: &str, node_key_file: &str) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if let Ok(env_val) = std::env::var(env_var) {
        let raw = decode_node_key(&env_val)?;
        return Ok(Zeroizing::new(*extract_node_key(&raw)));
    }
    if node_key_file.trim().is_empty() {
        return Err(CryptoError::NodeKeyMissing);
    }
    let bytes = std::fs::read(node_key_file).map_err(|e| {
        CryptoError::NodeKeyMalformed(format!("read {node_key_file}: {e}"))
    })?;
    let raw = match std::str::from_utf8(&bytes) {
        Ok(text) => decode_node_key(text.trim())?,
        Err(_) => bytes,
    };
    Ok(Zeroizing::new(*extract_node_key(&raw)))
}

/// Canonicalize operator-supplied key material to the 32-byte node key.
///
/// `ikm` is the raw decoded input, any length from 32 bytes up. The node key
/// is `HKDF-SHA256-Extract(salt = b"y2q/v3/node-key", ikm)`, so a supplied
/// key of any size ≥ 32 bytes is accepted and always canonicalizes to the
/// same 32 bytes for the same input.
///
/// Every key derived from the node key is a 256-bit AES/HMAC key, so the
/// security of the whole hierarchy is capped at 256 bits no matter how much
/// material is supplied — more than 32 bytes buys nothing. The 32-byte floor
/// (enforced by [`decode_node_key`] and the raw-bytes fallback in
/// [`load_node_key`]) is an accident guard against a truncated secret, not
/// an entropy proof: a 43-character passphrase that happens to decode to 32
/// bytes passes every check here. The operator must supply CSPRNG output —
/// see the `node_key_file` config doc comment and `docs/operations.md`.
pub fn extract_node_key(ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(NODE_KEY_EXTRACT_SALT), ikm);
    Zeroizing::new(prk.into())
}

/// Decode text key material to raw bytes.
///
/// Accepted: hex (even number of digits, either case), or base64 (standard
/// or URL-safe alphabet, padded or unpadded). Surrounding ASCII whitespace
/// must already be trimmed by the caller. Anything that decodes to fewer
/// than [`MIN_NODE_KEY_BYTES`] bytes, or fails every decoding, is
/// [`CryptoError::NodeKeyMalformed`].
pub fn decode_node_key(text: &str) -> Result<Vec<u8>, CryptoError> {
    let decoded = decode_hex(text)
        .or_else(|| STANDARD.decode(text).ok())
        .or_else(|| STANDARD_NO_PAD.decode(text).ok())
        .or_else(|| URL_SAFE.decode(text).ok())
        .or_else(|| URL_SAFE_NO_PAD.decode(text).ok())
        .ok_or_else(|| {
            CryptoError::NodeKeyMalformed(
                "not valid hex or base64 (standard or URL-safe, padded or unpadded)".to_owned(),
            )
        })?;
    if decoded.len() < MIN_NODE_KEY_BYTES {
        return Err(CryptoError::NodeKeyMalformed(format!(
            "decoded to {} bytes, need at least {MIN_NODE_KEY_BYTES}",
            decoded.len()
        )));
    }
    Ok(decoded)
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// Refuse a `node_key_file` that resolves inside `storage.base_path` or
/// `crypto.keystore_dir` — a copy of the storage tree must not carry the key
/// that protects it.
///
/// A real startup guard, not advice: canonicalizes all three paths (so
/// symlinks and `..` components can't evade it) and errors with an
/// actionable message if the node-key file sits inside either directory.
/// The env var supply path is exempt — it has no filesystem location to
/// leak.
pub fn check_node_key_location(
    node_key_file: &str,
    storage_base_path: &Path,
    keystore_dir: &Path,
) -> Result<(), String> {
    if node_key_file.trim().is_empty() {
        return Ok(());
    }
    let key_path = PathBuf::from(node_key_file);
    let canon_key = std::fs::canonicalize(&key_path).unwrap_or(key_path);
    for (label, dir) in [
        ("storage.base_path", storage_base_path),
        ("crypto.keystore_dir", keystore_dir),
    ] {
        let canon_dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
        if canon_key.starts_with(&canon_dir) {
            return Err(format!(
                "[crypto] node_key_file {} is inside {label} ({}); the node key must not sit \
                 beside the data it protects — a copy of the storage tree would carry it",
                canon_key.display(),
                canon_dir.display()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_base64_and_raw_canonicalize_identically() {
        let raw: [u8; 32] = std::array::from_fn(|i| i as u8);
        let hex_lower: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let hex_upper: String = raw.iter().map(|b| format!("{b:02X}")).collect();
        let b64_std = STANDARD.encode(raw);
        let b64_std_nopad = STANDARD_NO_PAD.encode(raw);
        let b64_url = URL_SAFE.encode(raw);
        let b64_url_nopad = URL_SAFE_NO_PAD.encode(raw);

        let expected = extract_node_key(&raw);
        for text in [
            hex_lower,
            hex_upper,
            b64_std,
            b64_std_nopad,
            b64_url,
            b64_url_nopad,
        ] {
            let decoded = decode_node_key(&text).unwrap();
            assert_eq!(*extract_node_key(&decoded), *expected, "input {text:?}");
        }

        // Raw bytes (no text decoding) canonicalize the same way too.
        assert_eq!(*extract_node_key(&raw), *expected);
    }

    #[test]
    fn longer_inputs_are_accepted_and_stable() {
        let a = [7u8; 64];
        let b = [7u8; 64];
        assert_eq!(*extract_node_key(&a), *extract_node_key(&b));

        let big = vec![9u8; 4096];
        let out1 = extract_node_key(&big);
        let out2 = extract_node_key(&big);
        assert_eq!(*out1, *out2);
    }

    #[test]
    fn short_or_garbage_input_is_malformed() {
        assert!(matches!(
            decode_node_key(""),
            Err(CryptoError::NodeKeyMalformed(_))
        ));
        // 31 raw bytes, hex-encoded (62 hex chars) -> decodes to 31 bytes, too short.
        let short_hex: String = std::iter::repeat("ab").take(31).collect();
        assert!(matches!(
            decode_node_key(&short_hex),
            Err(CryptoError::NodeKeyMalformed(_))
        ));
        let garbage = "!!!not-hex-or-base64-and-forty-chars-long!!!";
        assert!(matches!(
            decode_node_key(garbage),
            Err(CryptoError::NodeKeyMalformed(_))
        ));
    }

    #[test]
    fn missing_supply_is_node_key_missing() {
        // SAFETY: test-only env var manipulation, no concurrent access in
        // this process during the test.
        unsafe { std::env::remove_var(NODE_KEY_ENV_VAR) };
        assert!(matches!(
            load_node_key(""),
            Err(CryptoError::NodeKeyMissing)
        ));
    }

    #[test]
    fn location_guard_rejects_key_inside_protected_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let storage_dir = dir.path().join("objects");
        let keystore_dir = dir.path().join("keystore");
        std::fs::create_dir_all(&storage_dir).unwrap();
        std::fs::create_dir_all(&keystore_dir).unwrap();

        let inside_storage = storage_dir.join("node.key");
        std::fs::write(&inside_storage, b"x").unwrap();
        assert!(
            check_node_key_location(
                inside_storage.to_str().unwrap(),
                &storage_dir,
                &keystore_dir
            )
            .is_err()
        );

        let inside_keystore = keystore_dir.join("node.key");
        std::fs::write(&inside_keystore, b"x").unwrap();
        assert!(
            check_node_key_location(
                inside_keystore.to_str().unwrap(),
                &storage_dir,
                &keystore_dir
            )
            .is_err()
        );

        let outside = dir.path().join("secrets").join("node.key");
        std::fs::create_dir_all(outside.parent().unwrap()).unwrap();
        std::fs::write(&outside, b"x").unwrap();
        assert!(
            check_node_key_location(outside.to_str().unwrap(), &storage_dir, &keystore_dir)
                .is_ok()
        );
    }
}
