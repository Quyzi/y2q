//! Registry format, wraps, authenticated state, grants and authority.
//!
//! Key hierarchy (every KEK is symmetric; no classical asymmetric sealing of
//! key material exists anywhere in this feature):
//!
//! ```text
//! RMK              = 32 CSPRNG bytes, generated once at registry init
//! KEK_device       = HKDF-SHA256(device_secret, salt "y2q/v1/device-kek",    info device_id[16])
//! KEK_emergency_i  = HKDF-SHA256(code_bytes,    salt "y2q/v1/emergency-kek", info [i])
//! NK_WRAP_KEY      = HKDF-SHA256(RMK,           salt "y2q/v1/nk-wrap-key")
//! KEK_CACHE_KEY    = HKDF-SHA256(RMK,           salt "y2q/v1/kek-cache-key")
//! STATE_MAC_KEY    = HKDF-SHA256(RMK,           salt "y2q/v1/registry-state-key")
//! ```
//!
//! Home wraps, away grants and emergency wraps all seal RMK; `nk_wrap` seals
//! NK under an RMK-derived key. Mutable state is covered by `state_mac`, which
//! is verified inside the unlock paths (it needs RMK), never in [`load`].

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::types::*;
use super::{devices_path, fido2, tpm2};
use crate::crypto::CryptoError;

type HmacSha256 = Hmac<Sha256>;

pub(crate) const AAD_DEVICE_WRAP_LABEL: &[u8; 18] = b"y2q/v1/device-wrap";
pub(crate) const AAD_GRANT_LABEL: &[u8; 17] = b"y2q/v1/away-grant";
pub(crate) const AAD_EMERGENCY_WRAP_LABEL: &[u8; 21] = b"y2q/v1/emergency-wrap";
pub(crate) const AAD_NK_WRAP_LABEL: &[u8; 14] = b"y2q/v1/nk-wrap";
pub(crate) const AAD_KEK_CACHE_LABEL: &[u8; 16] = b"y2q/v1/kek-cache";
pub(crate) const MAC_STATE_LABEL: &[u8; 27] = b"y2q/v1/registry-state-bytes";

pub(crate) const DEVICE_WRAP_AAD_LEN: usize = 69;
pub(crate) const GRANT_AAD_LEN: usize = 79;
pub(crate) const EMERGENCY_WRAP_AAD_LEN: usize = 55;
pub(crate) const NK_WRAP_AAD_LEN: usize = 51;
pub(crate) const KEK_CACHE_AAD_LEN: usize = 65;
pub(crate) const NONCE_LEN: usize = 12;
pub(crate) const WRAP_CT_LEN: usize = 48;

/// Registry file name for the atomic-write temp file.
pub(crate) const TMP_FILE: &str = "devices.json.tmp";

/// Upper bound on records, so the state MAC's `u16` count can never overflow.
const MAX_DEVICES: usize = 4096;

// ---------------------------------------------------------------------------
// AAD builders
// ---------------------------------------------------------------------------

fn kind_byte(kind: DeviceKind) -> u8 {
    match kind {
        DeviceKind::Tpm2 => 1,
        DeviceKind::Fido2 => 2,
    }
}

/// `label || 0x00 || device_id[16] || kind_byte || uv_byte || ESC[32]` = 69 bytes.
pub(crate) fn device_wrap_aad(
    device_id: &[u8; 16],
    kind: DeviceKind,
    uv_required: bool,
    esc: &[u8; 32],
) -> [u8; DEVICE_WRAP_AAD_LEN] {
    let mut a = [0u8; DEVICE_WRAP_AAD_LEN];
    a[0..18].copy_from_slice(AAD_DEVICE_WRAP_LABEL);
    a[18] = 0;
    a[19..35].copy_from_slice(device_id);
    a[35] = kind_byte(kind);
    a[36] = u8::from(uv_required);
    a[37..69].copy_from_slice(esc);
    a
}

/// `label || 0x00 || device_id[16] || uv_byte || u64_le(not_after) || u32_le(secs) || ESC[32]` = 79 bytes.
pub(crate) fn grant_aad(
    device_id: &[u8; 16],
    uv_required: bool,
    not_after_unix: u64,
    away_grant_seconds: u32,
    esc: &[u8; 32],
) -> [u8; GRANT_AAD_LEN] {
    let mut a = [0u8; GRANT_AAD_LEN];
    a[0..17].copy_from_slice(AAD_GRANT_LABEL);
    a[17] = 0;
    a[18..34].copy_from_slice(device_id);
    a[34] = u8::from(uv_required);
    a[35..43].copy_from_slice(&not_after_unix.to_le_bytes());
    a[43..47].copy_from_slice(&away_grant_seconds.to_le_bytes());
    a[47..79].copy_from_slice(esc);
    a
}

/// `label || 0x00 || index || ESC[32]` = 55 bytes.
pub(crate) fn emergency_wrap_aad(index: u8, esc: &[u8; 32]) -> [u8; EMERGENCY_WRAP_AAD_LEN] {
    let mut a = [0u8; EMERGENCY_WRAP_AAD_LEN];
    a[0..21].copy_from_slice(AAD_EMERGENCY_WRAP_LABEL);
    a[21] = 0;
    a[22] = index;
    a[23..55].copy_from_slice(esc);
    a
}

/// `label || 0x00 || ESC[32] || u32_le(away_grant_seconds)` = 51 bytes.
pub(crate) fn nk_wrap_aad(esc: &[u8; 32], away_grant_seconds: u32) -> [u8; NK_WRAP_AAD_LEN] {
    let mut a = [0u8; NK_WRAP_AAD_LEN];
    a[0..14].copy_from_slice(AAD_NK_WRAP_LABEL);
    a[14] = 0;
    a[15..47].copy_from_slice(esc);
    a[47..51].copy_from_slice(&away_grant_seconds.to_le_bytes());
    a
}

/// `label || 0x00 || device_id[16] || ESC[32]` = 65 bytes. Free of the grant
/// deadline and the policy, so re-granting never re-encrypts it.
pub(crate) fn kek_cache_aad(device_id: &[u8; 16], esc: &[u8; 32]) -> [u8; KEK_CACHE_AAD_LEN] {
    let mut a = [0u8; KEK_CACHE_AAD_LEN];
    a[0..16].copy_from_slice(AAD_KEK_CACHE_LABEL);
    a[16] = 0;
    a[17..33].copy_from_slice(device_id);
    a[33..65].copy_from_slice(esc);
    a
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Key32, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut *out)
        .map_err(|_| CryptoError::Aead("hkdf expand"))?;
    Ok(out)
}

pub(crate) fn derive_device_kek(secret: &[u8], device_id: &[u8; 16]) -> Result<Key32, CryptoError> {
    hkdf32(secret, b"y2q/v1/device-kek", device_id)
}

pub(crate) fn derive_emergency_kek(code: &[u8], index: u8) -> Result<Key32, CryptoError> {
    hkdf32(code, b"y2q/v1/emergency-kek", &[index])
}

pub(crate) fn nk_wrap_key(rmk: &[u8; 32]) -> Result<Key32, CryptoError> {
    hkdf32(rmk, b"y2q/v1/nk-wrap-key", b"")
}

pub(crate) fn kek_cache_key(rmk: &[u8; 32]) -> Result<Key32, CryptoError> {
    hkdf32(rmk, b"y2q/v1/kek-cache-key", b"")
}

/// `HKDF(RMK, "y2q/v1/registry-state-key")`: the state MAC key, which the
/// daemon's grant sweeper holds for its lifetime.
pub fn derive_state_key(rmk: &[u8; 32]) -> Result<Key32, CryptoError> {
    hkdf32(rmk, b"y2q/v1/registry-state-key", b"")
}

// ---------------------------------------------------------------------------
// Wrap / unwrap
// ---------------------------------------------------------------------------

pub(crate) fn wrap_secret(
    kek: &[u8; 32],
    secret: &[u8; 32],
    aad: &[u8],
) -> Result<Wrap, CryptoError> {
    let cipher = Aes256Gcm::new(kek.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = &aes_gcm::Nonce::from(nonce_bytes);
    let ct = cipher
        .encrypt(nonce, Payload { msg: secret, aad })
        .map_err(|_| CryptoError::Aead("device wrap encrypt"))?;
    Ok(Wrap {
        nonce_b64: STANDARD.encode(nonce_bytes),
        ct_b64: STANDARD.encode(ct),
    })
}

pub(crate) fn unwrap_secret(
    kek: &[u8; 32],
    wrap: &Wrap,
    aad: &[u8],
    path: &Path,
) -> Result<Key32, CryptoError> {
    let corrupt = |reason: String| CryptoError::DeviceRegistryCorrupt {
        path: path.display().to_string(),
        reason,
    };
    let nonce_raw = STANDARD
        .decode(&wrap.nonce_b64)
        .map_err(|e| corrupt(format!("wrap nonce base64: {e}")))?;
    let ct = STANDARD
        .decode(&wrap.ct_b64)
        .map_err(|e| corrupt(format!("wrap ciphertext base64: {e}")))?;
    if nonce_raw.len() != NONCE_LEN {
        return Err(corrupt(format!(
            "wrap nonce is {} bytes, expected {NONCE_LEN}",
            nonce_raw.len()
        )));
    }
    if ct.len() != WRAP_CT_LEN {
        return Err(corrupt(format!(
            "wrap ciphertext is {} bytes, expected {WRAP_CT_LEN}",
            ct.len()
        )));
    }
    let nonce = &aes_gcm::Nonce::try_from(&nonce_raw[..]).expect("length checked above");
    let cipher = Aes256Gcm::new(kek.into());
    let plain = Zeroizing::new(
        cipher
            .decrypt(nonce, Payload { msg: &ct, aad })
            .map_err(|_| CryptoError::DeviceUnwrapFailed)?,
    );
    let arr: [u8; 32] = plain.as_slice().try_into().map_err(|_| {
        corrupt(format!(
            "wrap plaintext is {} bytes, expected 32",
            plain.len()
        ))
    })?;
    Ok(Zeroizing::new(arr))
}

// ---------------------------------------------------------------------------
// State MAC
// ---------------------------------------------------------------------------

fn sha256_wrap(w: &Wrap) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(w.nonce_b64.as_bytes());
    h.update([0u8]);
    h.update(w.ct_b64.as_bytes());
    h.finalize().into()
}

/// `HMAC-SHA256(state_key, canonical_state_bytes)` over every mutable field.
///
/// `esc_b64` is outside the MAC because all five AADs bind ESC, so editing it
/// makes every unwrap fail before the MAC is reached. `away_grant_seconds` is
/// inside it *and* in two AADs: the AADs make an edit unrecoverable, the MAC
/// makes it diagnosable.
pub(crate) fn state_mac(state_key: &[u8; 32], reg: &DeviceRegistryFile) -> [u8; 32] {
    let mut b: Vec<u8> = Vec::with_capacity(256 + reg.devices.len() * 160);
    b.extend_from_slice(MAC_STATE_LABEL);
    b.push(0);
    b.extend_from_slice(&reg.format_version.to_le_bytes());
    b.extend_from_slice(&reg.away_grant_seconds.to_le_bytes());
    b.push(u8::from(reg.permanent_away));
    b.extend_from_slice(&sha256_wrap(&reg.nk_wrap));
    b.extend_from_slice(
        &u16::try_from(reg.devices.len())
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    for d in &reg.devices {
        b.extend_from_slice(&d.id_bytes);
        b.push(kind_byte(d.kind));
        b.push(u8::from(d.wrap.is_some()));
        b.push(u8::from(d.grant.is_some()));
        b.push(u8::from(d.kek_wrap.is_some()));
        b.extend_from_slice(
            &d.grant
                .as_ref()
                .map_or(0, |g| g.not_after_unix)
                .to_le_bytes(),
        );
        b.extend_from_slice(
            &d.grant
                .as_ref()
                .map_or(0, |g| g.issued_at_unix)
                .to_le_bytes(),
        );
        b.extend_from_slice(&d.sign_count_last.unwrap_or(0).to_le_bytes());
        b.extend_from_slice(&d.added_at_unix.to_le_bytes());
        b.push(u8::from(d.tpm2.is_some()));
        b.push(u8::from(d.fido2.is_some()));
        match d.kind {
            DeviceKind::Tpm2 => {
                if let Some(t) = &d.tpm2 {
                    b.push(u8::try_from(t.pcr_bank.len()).unwrap_or(u8::MAX));
                    b.extend_from_slice(t.pcr_bank.as_bytes());
                    b.push(u8::try_from(t.pcr_slots.len()).unwrap_or(u8::MAX));
                    b.extend_from_slice(&t.pcr_slots);
                }
            }
            DeviceKind::Fido2 => {
                b.push(u8::from(d.fido2.as_ref().is_some_and(|f| f.uv_required)));
                match &d.kek_wrap {
                    Some(w) => b.extend_from_slice(&sha256_wrap(w)),
                    None => b.extend_from_slice(&[0u8; 32]),
                }
            }
        }
        b.push(u8::try_from(d.label.len()).unwrap_or(u8::MAX));
        b.extend_from_slice(d.label.as_bytes());
    }
    b.push(u8::try_from(reg.emergency_slots.len()).unwrap_or(u8::MAX));
    for s in &reg.emergency_slots {
        b.push(u8::from(s.wrap.is_some()));
        b.extend_from_slice(&s.burned_at_unix.unwrap_or(0).to_le_bytes());
    }
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(state_key).expect("HMAC accepts any key size");
    mac.update(&b);
    mac.finalize().into_bytes().into()
}

/// Verify the stored MAC under `state_key`, in constant time.
pub(crate) fn verify_state_mac(
    state_key: &[u8; 32],
    reg: &DeviceRegistryFile,
    path: &Path,
) -> Result<(), CryptoError> {
    let stored = STANDARD
        .decode(&reg.state_mac_b64)
        .ok()
        .filter(|v| v.len() == 32)
        .ok_or_else(|| CryptoError::DeviceRegistryCorrupt {
            path: path.display().to_string(),
            reason: "state_mac_b64 must decode to 32 bytes".to_owned(),
        })?;
    let computed = state_mac(state_key, reg);
    if bool::from(stored.as_slice().ct_eq(&computed)) {
        Ok(())
    } else {
        Err(CryptoError::DeviceStateTampered)
    }
}

// ---------------------------------------------------------------------------
// Load / check / persist
// ---------------------------------------------------------------------------

pub(crate) fn corrupt(path: &Path, reason: impl Into<String>) -> CryptoError {
    CryptoError::DeviceRegistryCorrupt {
        path: path.display().to_string(),
        reason: reason.into(),
    }
}

pub(crate) fn valid_label(label: &str) -> Result<(), String> {
    if label.is_empty() {
        return Err("label must not be empty".to_owned());
    }
    if label.len() > MAX_LABEL_LEN {
        return Err(format!("label is longer than {MAX_LABEL_LEN} bytes"));
    }
    if let Some(b) = label.bytes().find(|b| !(0x20..=0x7e).contains(b)) {
        return Err(format!(
            "label contains byte {b:#04x}; only 0x20..=0x7e are allowed"
        ));
    }
    Ok(())
}

fn decode_hex_id(id: &str) -> Option<[u8; 16]> {
    if id.len() != 32
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in id.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Fill the `#[serde(skip)]` caches (`esc`, `id_bytes`) from their string forms.
fn fill_derived(reg: &mut DeviceRegistryFile, path: &Path) -> Result<(), CryptoError> {
    let esc = STANDARD
        .decode(&reg.esc_b64)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or_else(|| corrupt(path, "esc_b64 must decode to 32 bytes"))?;
    reg.esc = esc;
    for d in &mut reg.devices {
        d.id_bytes = decode_hex_id(&d.id).ok_or_else(|| {
            corrupt(
                path,
                format!("device id '{}' must be 32 lowercase hex chars", d.id),
            )
        })?;
    }
    Ok(())
}

/// Structural validation shared by [`load`] and [`persist`]: steps 4-10 of the
/// documented check order.
pub(crate) fn check(reg: &DeviceRegistryFile, path: &Path) -> Result<(), CryptoError> {
    // 4. esc / state_mac decode.
    if STANDARD
        .decode(&reg.esc_b64)
        .ok()
        .is_none_or(|v| v.len() != 32)
    {
        return Err(corrupt(path, "esc_b64 must decode to 32 bytes"));
    }
    if STANDARD
        .decode(&reg.state_mac_b64)
        .ok()
        .is_none_or(|v| v.len() != 32)
    {
        return Err(corrupt(path, "state_mac_b64 must decode to 32 bytes"));
    }
    // 5. grant period.
    if !(MIN_AWAY_GRANT_SECONDS..=MAX_AWAY_GRANT_SECONDS).contains(&reg.away_grant_seconds) {
        return Err(CryptoError::DeviceGrantPeriodInvalid {
            seconds: reg.away_grant_seconds,
        });
    }
    // 6. emergency slots.
    if reg.emergency_slots.len() != EMERGENCY_SLOTS {
        return Err(corrupt(
            path,
            format!(
                "expected {EMERGENCY_SLOTS} emergency slots, found {}",
                reg.emergency_slots.len()
            ),
        ));
    }
    for (i, s) in reg.emergency_slots.iter().enumerate() {
        if usize::from(s.index) != i {
            return Err(corrupt(
                path,
                format!("emergency slot at position {i} has index {}", s.index),
            ));
        }
        if s.wrap.is_some() == s.burned_at_unix.is_some() {
            return Err(corrupt(
                path,
                format!("emergency slot {i} must have exactly one of wrap / burned_at_unix"),
            ));
        }
    }
    // 7. devices.
    if reg.devices.len() > MAX_DEVICES {
        return Err(corrupt(path, "too many device records"));
    }
    let mut ids = std::collections::HashSet::new();
    let mut labels = std::collections::HashSet::new();
    for d in &reg.devices {
        let id_bytes = decode_hex_id(&d.id).ok_or_else(|| {
            corrupt(
                path,
                format!("device id '{}' must be 32 lowercase hex chars", d.id),
            )
        })?;
        if id_bytes != d.id_bytes {
            return Err(corrupt(
                path,
                format!("device {} id cache is out of sync", d.id),
            ));
        }
        valid_label(&d.label).map_err(|e| corrupt(path, format!("device {}: {e}", d.id)))?;
        if !labels.insert(d.label.to_ascii_lowercase()) {
            return Err(corrupt(
                path,
                format!("duplicate device label '{}'", d.label),
            ));
        }
        if !ids.insert(d.id.clone()) {
            return Err(corrupt(path, format!("duplicate device id {}", d.id)));
        }
        let kind_ok = match d.kind {
            DeviceKind::Tpm2 => d.tpm2.is_some() && d.fido2.is_none(),
            DeviceKind::Fido2 => d.fido2.is_some() && d.tpm2.is_none(),
        };
        if !kind_ok {
            return Err(corrupt(
                path,
                format!("device {} parameter block does not match its kind", d.id),
            ));
        }
    }
    let homes = home_count(reg);
    for d in &reg.devices {
        match d.kind {
            // 8.
            DeviceKind::Tpm2 => {
                if d.wrap.is_none() {
                    return Err(corrupt(path, format!("home device {} has no wrap", d.id)));
                }
                if d.grant.is_some() || d.sign_count_last.is_some() || d.kek_wrap.is_some() {
                    return Err(corrupt(
                        path,
                        format!("home device {} carries away-only fields", d.id),
                    ));
                }
            }
            // 9.
            DeviceKind::Fido2 => {
                if d.sign_count_last.is_none() || d.kek_wrap.is_none() {
                    return Err(corrupt(
                        path,
                        format!(
                            "away device {} is missing kek_wrap or sign_count_last",
                            d.id
                        ),
                    ));
                }
                if d.wrap.is_some() && d.grant.is_some() {
                    return Err(corrupt(
                        path,
                        format!("away device {} has both a permanent wrap and a grant", d.id),
                    ));
                }
                if d.wrap.is_some() && !reg.permanent_away {
                    return Err(corrupt(
                        path,
                        format!(
                            "away device {} holds a permanent wrap in a registry that is not permanent_away",
                            d.id
                        ),
                    ));
                }
                if d.grant.is_some() && homes == 0 {
                    return Err(corrupt(
                        path,
                        format!(
                            "away device {} holds a grant but no home device is registered",
                            d.id
                        ),
                    ));
                }
            }
        }
    }
    // 10.
    if reg.permanent_away != (!reg.devices.is_empty() && homes == 0) {
        return Err(corrupt(
            path,
            "permanent_away does not match the home-device count",
        ));
    }
    if reg.permanent_away
        && reg
            .devices
            .iter()
            .any(|d| d.kind == DeviceKind::Fido2 && (d.wrap.is_none() || d.grant.is_some()))
    {
        return Err(corrupt(
            path,
            "permanent_away registry has an away device without a permanent wrap",
        ));
    }
    Ok(())
}

/// Read and structurally validate `<dir>/devices.json`. The state MAC is NOT
/// verified here (it needs RMK) and nothing is erased: loading reads no clock.
pub fn load(dir: &Path) -> Result<DeviceRegistryFile, CryptoError> {
    let path = devices_path(dir);
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CryptoError::DeviceRegistryMissing(
                path.display().to_string(),
            ));
        }
        Err(e) => {
            return Err(CryptoError::DeviceRegistryIo(format!(
                "read {}: {e}",
                path.display()
            )));
        }
    };
    let mut reg: DeviceRegistryFile =
        serde_json::from_slice(&bytes).map_err(|e| corrupt(&path, format!("parse: {e}")))?;
    if reg.format_version != DEVICES_FORMAT_VERSION {
        return Err(CryptoError::DeviceRegistryVersion {
            path: path.display().to_string(),
            found: reg.format_version,
            expected: DEVICES_FORMAT_VERSION,
        });
    }
    fill_derived(&mut reg, &path)?;
    check(&reg, &path)?;
    Ok(reg)
}

pub(crate) fn fsync_dir(dir: &Path) -> Result<(), CryptoError> {
    fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| CryptoError::DeviceRegistryIo(format!("fsync {}: {e}", dir.display())))
}

/// Recompute the MAC, validate, and atomically replace `devices.json`
/// (temp file, `sync_all`, rename, parent-directory fsync with its error
/// propagated: grant erasure and burn-before-serve are only correct if the
/// rename is durable before the caller proceeds).
pub fn persist(
    dir: &Path,
    reg: &mut DeviceRegistryFile,
    state_key: &[u8; 32],
) -> Result<(), CryptoError> {
    let path = devices_path(dir);
    fill_derived(reg, &path)?;
    reg.state_mac_b64 = STANDARD.encode(state_mac(state_key, reg));
    check(reg, &path)?;
    let bytes = serde_json::to_vec_pretty(reg)
        .map_err(|e| CryptoError::DeviceRegistryIo(format!("serialize: {e}")))?;
    let tmp = dir.join(TMP_FILE);
    let io = |what: &str, e: std::io::Error| {
        CryptoError::DeviceRegistryIo(format!("{what} {}: {e}", tmp.display()))
    };
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| io("open", e))?;
    f.write_all(&bytes).map_err(|e| io("write", e))?;
    f.sync_all().map_err(|e| io("sync", e))?;
    drop(f);
    fs::rename(&tmp, &path).map_err(|e| {
        CryptoError::DeviceRegistryIo(format!(
            "rename {} -> {}: {e}",
            tmp.display(),
            path.display()
        ))
    })?;
    fsync_dir(dir)
}

/// Whether a registry file exists in `dir`.
pub fn exists(dir: &Path) -> bool {
    devices_path(dir).exists()
}

/// Number of home (TPM) devices in `reg`.
pub fn home_count(reg: &DeviceRegistryFile) -> usize {
    reg.devices
        .iter()
        .filter(|d| d.kind == DeviceKind::Tpm2)
        .count()
}

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

fn insufficient(operation: &str, required: &str, by: &Authority) -> CryptoError {
    CryptoError::DeviceAuthorityInsufficient {
        operation: operation.to_owned(),
        required: required.to_owned(),
        by: by.describe(),
    }
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

/// In-memory only; the caller persists. Returns the number of grants erased.
/// `attested_now` MUST be attested time.
pub fn sweep_grants(reg: &mut DeviceRegistryFile, attested_now: u64) -> usize {
    let mut erased = 0;
    for d in &mut reg.devices {
        if let Some(g) = &d.grant
            && g.not_after_unix < attested_now
        {
            tracing::warn!(
                device_id = %d.id,
                label = %d.label,
                not_after_unix = g.not_after_unix,
                "away grant expired; wrapped key erased"
            );
            d.grant = None;
            erased += 1;
        }
    }
    erased
}

/// Mint a fresh grant for every `Fido2` record, replacing any existing grant
/// (row 2). A record whose `kek_wrap` does not open is skipped with a warning.
/// Returns the number minted. No-op in a `permanent_away` registry.
fn mint_grants(
    reg: &mut DeviceRegistryFile,
    rmk: &[u8; 32],
    attested_now: u64,
    path: &Path,
) -> Result<usize, CryptoError> {
    if reg.permanent_away {
        return Ok(0);
    }
    let cache_key = kek_cache_key(rmk)?;
    let secs = reg.away_grant_seconds;
    let esc = reg.esc;
    let not_after_unix = attested_now.saturating_add(u64::from(secs));
    let mut minted = 0;
    for d in &mut reg.devices {
        if d.kind != DeviceKind::Fido2 || d.wrap.is_some() {
            continue;
        }
        let Some(kek_wrap) = &d.kek_wrap else {
            continue;
        };
        let kek = match unwrap_secret(
            &cache_key,
            kek_wrap,
            &kek_cache_aad(&d.id_bytes, &esc),
            path,
        ) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(
                    device_id = %d.id,
                    label = %d.label,
                    error = %e,
                    "away device kek_wrap does not open; no grant minted — remove and re-add this device"
                );
                continue;
            }
        };
        let uv = d.fido2.as_ref().is_some_and(|f| f.uv_required);
        let wrap = wrap_secret(
            &kek,
            rmk,
            &grant_aad(&d.id_bytes, uv, not_after_unix, secs, &esc),
        )?;
        d.grant = Some(Grant {
            not_after_unix,
            issued_at_unix: attested_now,
            wrap,
        });
        minted += 1;
    }
    if minted > 0 {
        tracing::info!(
            devices = minted,
            away_grant_seconds = secs,
            not_after_unix,
            "away grants issued by home unlock"
        );
    }
    Ok(minted)
}

fn open_nk(reg: &DeviceRegistryFile, rmk: &[u8; 32], path: &Path) -> Result<Key32, CryptoError> {
    let key = nk_wrap_key(rmk)?;
    unwrap_secret(
        &key,
        &reg.nk_wrap,
        &nk_wrap_aad(&reg.esc, reg.away_grant_seconds),
        path,
    )
    .map_err(|e| match e {
        CryptoError::DeviceUnwrapFailed => corrupt(
            path,
            "nk_wrap does not open under this registry's master key and grant policy",
        ),
        other => other,
    })
}

pub(crate) fn open_nk_pub(
    reg: &DeviceRegistryFile,
    rmk: &[u8; 32],
    dir: &Path,
) -> Result<Key32, CryptoError> {
    open_nk(reg, rmk, &devices_path(dir))
}

fn secret32(label: &str, secret: &[u8]) -> Result<(), CryptoError> {
    if secret.len() == 32 {
        Ok(())
    } else {
        Err(CryptoError::DeviceSecretLength {
            label: label.to_owned(),
            len: secret.len(),
        })
    }
}

/// Recover RMK from a record's permanent `wrap`, verifying nothing else.
fn rmk_from_permanent(
    reg: &DeviceRegistryFile,
    index: usize,
    kek: &[u8; 32],
    path: &Path,
) -> Result<Key32, CryptoError> {
    let d = &reg.devices[index];
    let wrap = d
        .wrap
        .as_ref()
        .ok_or_else(|| corrupt(path, format!("device {} has no permanent wrap", d.id)))?;
    let uv = d.fido2.as_ref().is_some_and(|f| f.uv_required);
    unwrap_secret(
        kek,
        wrap,
        &device_wrap_aad(&d.id_bytes, d.kind, uv, &reg.esc),
        path,
    )
}

/// Home unlock: unwrap RMK from the TPM record, verify the state MAC, then
/// sweep and re-mint grants on attested time (rows 2-4). Persists once when
/// anything changed, before NK is returned.
pub fn unlock_with_home(
    dir: &Path,
    reg: &mut DeviceRegistryFile,
    index: usize,
    device_secret: &[u8],
    time: &dyn TimeSource,
    _policy: &DevicePolicy,
) -> Result<Unlock, CryptoError> {
    let path = devices_path(dir);
    let label = reg.devices[index].label.clone();
    secret32(&label, device_secret)?;
    if reg.devices[index].kind != DeviceKind::Tpm2 {
        return Err(corrupt(
            &path,
            format!("device {label} is not a home device"),
        ));
    }
    let kek = derive_device_kek(device_secret, &reg.devices[index].id_bytes)?;
    let rmk = rmk_from_permanent(reg, index, &kek, &path)?;
    let state_key = derive_state_key(&rmk)?;
    verify_state_mac(&state_key, reg, &path)?;
    // NK first: a corrupt nk_wrap must not cost a persist.
    let nk = open_nk(reg, &rmk, &path)?;

    let (mut issued, mut erased) = (0, 0);
    match time.attested_now() {
        Ok(now) => {
            erased = sweep_grants(reg, now);
            issued = mint_grants(reg, &rmk, now, &path)?;
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "home unlock could not attest the time; away grants not refreshed"
            );
        }
    }
    if issued > 0 || erased > 0 {
        persist(dir, reg, &state_key)?;
    }
    Ok(Unlock {
        nk,
        rmk,
        grants_issued: issued,
        grants_erased: erased,
    })
}

/// Away unlock; ordered checks 1-7 of the documented lifecycle. Persists
/// before NK is returned.
pub fn unlock_with_away(
    dir: &Path,
    reg: &mut DeviceRegistryFile,
    index: usize,
    device_secret: &[u8],
    asserted_sign_count: u32,
    time: &dyn TimeSource,
    _policy: &DevicePolicy,
) -> Result<Unlock, CryptoError> {
    let path = devices_path(dir);
    let label = reg.devices[index].label.clone();
    // 1.
    secret32(&label, device_secret)?;
    if reg.devices[index].kind != DeviceKind::Fido2 {
        return Err(corrupt(
            &path,
            format!("device {label} is not an away device"),
        ));
    }
    // 2.
    let has_wrap = reg.devices[index].wrap.is_some();
    let grant_deadline = reg.devices[index].grant.as_ref().map(|g| g.not_after_unix);
    if !has_wrap && grant_deadline.is_none() {
        return Err(CryptoError::DeviceGrantAbsent { label });
    }
    // 3.
    let kek = derive_device_kek(device_secret, &reg.devices[index].id_bytes)?;
    let rmk = if has_wrap {
        rmk_from_permanent(reg, index, &kek, &path)?
    } else {
        let d = &reg.devices[index];
        let grant = d.grant.as_ref().expect("grant presence checked above");
        let uv = d.fido2.as_ref().is_some_and(|f| f.uv_required);
        unwrap_secret(
            &kek,
            &grant.wrap,
            &grant_aad(
                &d.id_bytes,
                uv,
                grant.not_after_unix,
                reg.away_grant_seconds,
                &reg.esc,
            ),
            &path,
        )?
    };
    // 4.
    let state_key = derive_state_key(&rmk)?;
    verify_state_mac(&state_key, reg, &path)?;
    // 5.
    let mut erased = 0;
    if !has_wrap {
        let not_after_unix = grant_deadline.expect("grant presence checked above");
        let now = time.attested_now()?;
        erased = sweep_grants(reg, now);
        if now > not_after_unix {
            persist(dir, reg, &state_key)?;
            return Err(CryptoError::DeviceGrantExpired {
                label,
                not_after_unix,
                attested_now: now,
            });
        }
    }
    // 6.
    let last = reg.devices[index]
        .sign_count_last
        .ok_or_else(|| corrupt(&path, format!("away device {label} has no sign_count_last")))?;
    if asserted_sign_count <= last {
        return Err(CryptoError::DeviceSignCountRollback {
            label,
            asserted: asserted_sign_count,
            last,
        });
    }
    // 7.
    let nk = open_nk(reg, &rmk, &path)?;
    reg.devices[index].sign_count_last = Some(asserted_sign_count);
    persist(dir, reg, &state_key)?;
    Ok(Unlock {
        nk,
        rmk,
        grants_issued: 0,
        grants_erased: erased,
    })
}

/// Attested-time sweep for the daemon timer.
///
/// Verifies the state MAC under `state_key` first and never re-signs state it
/// did not verify. Re-mints grants (row 13) iff `rmk` is `Some`. When nothing
/// is to be done it returns `Ok((0, 0))` before any `TimeSource` call, so a
/// zero-home registry never requests attested time. With no attested time it
/// does nothing. Returns `(minted, erased)`.
pub fn sweep_now(
    dir: &Path,
    state_key: &[u8; 32],
    rmk: Option<&[u8; 32]>,
    time: &dyn TimeSource,
) -> Result<(usize, usize), CryptoError> {
    let path = devices_path(dir);
    let mut reg = load(dir)?;
    if let Err(e) = verify_state_mac(state_key, &reg, &path) {
        tracing::warn!(error = %e, "grant sweep skipped: registry state does not authenticate");
        return Ok((0, 0));
    }
    let any_grant = reg.devices.iter().any(|d| d.grant.is_some());
    let can_mint = rmk.is_some()
        && !reg.permanent_away
        && reg.devices.iter().any(|d| d.kind == DeviceKind::Fido2);
    if !any_grant && !can_mint {
        return Ok((0, 0));
    }
    let now = match time.attested_now() {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "attested sweep skipped; grants not erased");
            return Ok((0, 0));
        }
    };
    let erased = sweep_grants(&mut reg, now);
    let issued = match rmk {
        Some(rmk) => mint_grants(&mut reg, rmk, now, &path)?,
        None => 0,
    };
    if issued > 0 || erased > 0 {
        persist(dir, &mut reg, state_key)?;
    }
    Ok((issued, erased))
}

// ---------------------------------------------------------------------------
// Mutations (in-memory only; the CLI persists once afterwards)
// ---------------------------------------------------------------------------

/// Context for mutating operations.
pub struct Ctx<'a> {
    /// Attested time source (used by grant-minting operations only).
    pub time: &'a dyn TimeSource,
    /// Host clock, stamping `added_at_unix` only.
    pub now_host: u64,
    /// Hardware access policy.
    pub policy: &'a DevicePolicy,
}

/// Enroll a freshly provisioned device. In-memory only. Returns the new id.
pub fn enroll_device(
    dir: &Path,
    reg: &mut DeviceRegistryFile,
    new: NewDevice,
    rmk: &[u8; 32],
    by: &Authority,
    ctx: &Ctx<'_>,
) -> Result<String, CryptoError> {
    let path = devices_path(dir);
    let homes_before = home_count(reg);
    // Authority first, so nothing (including attestation) runs for a refused caller.
    match new.kind {
        DeviceKind::Tpm2 => {
            let ok = match by {
                Authority::Home { .. } => true,
                Authority::Away { .. } => homes_before == 0,
                Authority::Emergency { .. } => false,
            };
            if !ok {
                return Err(insufficient(
                    "add-tpm",
                    "a home device, or an away device with no home devices",
                    by,
                ));
            }
        }
        DeviceKind::Fido2 => {
            let ok = match by {
                Authority::Home { .. } => true,
                Authority::Away { .. } => homes_before == 0,
                Authority::Emergency { .. } => false,
            };
            if !ok {
                return Err(insufficient(
                    "add-fido2",
                    "a home device, or an away device with no home devices",
                    by,
                ));
            }
        }
    }
    valid_label(&new.label).map_err(CryptoError::DeviceLabelInvalid)?;
    if reg
        .devices
        .iter()
        .any(|d| d.label.eq_ignore_ascii_case(&new.label))
    {
        return Err(CryptoError::DeviceLabelInUse(new.label));
    }
    let guard = new.secret.unlock()?;
    secret32(&new.label, &guard)?;

    let mut id_bytes = [0u8; 16];
    let mut found = false;
    for _ in 0..8 {
        rand::rng().fill_bytes(&mut id_bytes);
        let id = hex(&id_bytes);
        if !reg.devices.iter().any(|d| d.id == id) {
            found = true;
            break;
        }
    }
    if !found {
        return Err(corrupt(&path, "could not generate a unique device id"));
    }
    let id = hex(&id_bytes);
    let esc = reg.esc;
    let kek = derive_device_kek(&guard, &id_bytes)?;

    let mut rec = DeviceRecord {
        id: id.clone(),
        label: new.label.clone(),
        kind: new.kind,
        added_at_unix: ctx.now_host,
        wrap: None,
        grant: None,
        tpm2: None,
        fido2: None,
        sign_count_last: None,
        kek_wrap: None,
        id_bytes,
    };
    match new.kind {
        DeviceKind::Tpm2 => {
            rec.tpm2 = Some(new.tpm2.clone().ok_or_else(|| {
                CryptoError::DeviceBackend(
                    "enrollment result carries no tpm2 parameters".to_owned(),
                )
            })?);
            rec.wrap = Some(wrap_secret(
                &kek,
                rmk,
                &device_wrap_aad(&id_bytes, DeviceKind::Tpm2, false, &esc),
            )?);
        }
        DeviceKind::Fido2 => {
            let params = new.fido2.clone().ok_or_else(|| {
                CryptoError::DeviceBackend(
                    "enrollment result carries no fido2 parameters".to_owned(),
                )
            })?;
            rec.kek_wrap = Some(wrap_secret(
                &*kek_cache_key(rmk)?,
                &kek,
                &kek_cache_aad(&id_bytes, &esc),
            )?);
            rec.sign_count_last = Some(new.sign_count);
            if homes_before == 0 {
                rec.wrap = Some(wrap_secret(
                    &kek,
                    rmk,
                    &device_wrap_aad(&id_bytes, DeviceKind::Fido2, params.uv_required, &esc),
                )?);
            }
            rec.fido2 = Some(params);
        }
    }
    drop(guard);

    let first_home_over_away = new.kind == DeviceKind::Tpm2
        && homes_before == 0
        && reg.devices.iter().any(|d| d.kind == DeviceKind::Fido2);
    reg.devices.push(rec);
    reg.permanent_away = home_count(reg) == 0 && !reg.devices.is_empty();

    if first_home_over_away {
        // Row 9: delete every permanent away wrap; mint grants when time can be attested.
        let mut stripped = Vec::new();
        for d in &mut reg.devices {
            if d.kind == DeviceKind::Fido2 && d.wrap.take().is_some() {
                stripped.push(d.label.clone());
            }
        }
        match ctx.time.attested_now() {
            Ok(now) => {
                mint_grants(reg, rmk, now, &path)?;
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    devices = %stripped.join(", "),
                    "first home device added but time could not be attested; \
                     away devices hold no grant until the next home unlock"
                );
            }
        }
    }
    Ok(id)
}

fn resolve_selector(reg: &DeviceRegistryFile, selector: &str) -> Result<usize, CryptoError> {
    if let Some(i) = reg.devices.iter().position(|d| d.id == selector) {
        return Ok(i);
    }
    let mut matches = reg
        .devices
        .iter()
        .enumerate()
        .filter(|(_, d)| d.label.eq_ignore_ascii_case(selector))
        .map(|(i, _)| i);
    match (matches.next(), matches.next()) {
        (Some(i), None) => Ok(i),
        _ => Err(CryptoError::DeviceNotFound(selector.to_owned())),
    }
}

/// Remove a device record. In-memory only.
pub fn remove_device(
    _dir: &Path,
    reg: &mut DeviceRegistryFile,
    selector: &str,
    _rmk: &[u8; 32],
    by: &Authority,
    _ctx: &Ctx<'_>,
) -> Result<(), CryptoError> {
    let idx = resolve_selector(reg, selector)?;
    if !matches!(by, Authority::Home { .. } | Authority::Emergency { .. }) {
        return Err(insufficient(
            "remove",
            "a home device or an emergency code",
            by,
        ));
    }
    let label = reg.devices[idx].label.clone();
    if reg.devices.len() == 1 {
        return Err(CryptoError::DeviceRegistryLastDevice);
    }
    if reg.devices[idx].kind == DeviceKind::Tpm2 && home_count(reg) == 1 {
        return Err(CryptoError::DeviceLastHomeRemovalRefused { label });
    }
    reg.devices.remove(idx);
    reg.permanent_away = home_count(reg) == 0 && !reg.devices.is_empty();
    Ok(())
}

/// Row 2 without a daemon restart: sweep, then mint a fresh grant for every
/// away record. Home authority only. In-memory only. Returns grants minted.
pub fn refresh_grants(
    dir: &Path,
    reg: &mut DeviceRegistryFile,
    rmk: &[u8; 32],
    by: &Authority,
    ctx: &Ctx<'_>,
) -> Result<usize, CryptoError> {
    if !matches!(by, Authority::Home { .. }) {
        return Err(insufficient("refresh", "a home device", by));
    }
    let now = ctx.time.attested_now()?;
    sweep_grants(reg, now);
    mint_grants(reg, rmk, now, &devices_path(dir))
}

/// Change the away-grant period, re-wrapping `nk_wrap` under the new AAD and
/// dropping every grant. Fresh grants only under `Home` with attested time.
/// In-memory only.
pub fn set_grant_period(
    dir: &Path,
    reg: &mut DeviceRegistryFile,
    seconds: u32,
    nk: &[u8; 32],
    rmk: &[u8; 32],
    by: &Authority,
    ctx: &Ctx<'_>,
) -> Result<(), CryptoError> {
    if !(MIN_AWAY_GRANT_SECONDS..=MAX_AWAY_GRANT_SECONDS).contains(&seconds) {
        return Err(CryptoError::DeviceGrantPeriodInvalid { seconds });
    }
    match by {
        Authority::Home { .. } => {}
        Authority::Emergency { .. } => {
            if seconds >= reg.away_grant_seconds {
                return Err(insufficient(
                    "set-grant-period",
                    "a home device, or an emergency code with a strictly shorter period",
                    by,
                ));
            }
        }
        Authority::Away { .. } => {
            return Err(insufficient(
                "set-grant-period",
                "a home device or an emergency code",
                by,
            ));
        }
    }
    reg.away_grant_seconds = seconds;
    reg.nk_wrap = wrap_secret(&*nk_wrap_key(rmk)?, nk, &nk_wrap_aad(&reg.esc, seconds))?;
    for d in &mut reg.devices {
        d.grant = None;
    }
    if matches!(by, Authority::Home { .. }) {
        match ctx.time.attested_now() {
            Ok(now) => {
                mint_grants(reg, rmk, now, &devices_path(dir))?;
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "grant period changed but time could not be attested; away grants not minted"
                );
            }
        }
    }
    Ok(())
}

/// `reseal-tpm`: re-seal the `Tpm2` record `id` to the current PCR values.
/// Home or Emergency only. In-memory only; the TPM is contacted first, so an
/// unreachable TPM changes nothing.
pub fn reseal_device(
    dir: &Path,
    reg: &mut DeviceRegistryFile,
    id: &str,
    rmk: &[u8; 32],
    by: &Authority,
    ctx: &Ctx<'_>,
) -> Result<(), CryptoError> {
    if !matches!(by, Authority::Home { .. } | Authority::Emergency { .. }) {
        return Err(insufficient(
            "reseal-tpm",
            "a home device or an emergency code",
            by,
        ));
    }
    let idx = resolve_selector(reg, id)?;
    let params = match (&reg.devices[idx].kind, &reg.devices[idx].tpm2) {
        (DeviceKind::Tpm2, Some(p)) => p.clone(),
        _ => return Err(CryptoError::DeviceNotFound(id.to_owned())),
    };
    let (new_params, new_secret) = tpm2::reseal(&params, &ctx.policy.tpm_tcti)?;
    let guard = new_secret.unlock()?;
    secret32(&reg.devices[idx].label, &guard)?;
    let d = &reg.devices[idx];
    let kek = derive_device_kek(&guard, &d.id_bytes)?;
    let wrap = wrap_secret(
        &kek,
        rmk,
        &device_wrap_aad(&d.id_bytes, DeviceKind::Tpm2, false, &reg.esc),
    )?;
    let _ = dir;
    let d = &mut reg.devices[idx];
    d.tpm2 = Some(new_params);
    d.wrap = Some(wrap);
    Ok(())
}

// ---------------------------------------------------------------------------
// Repair (the only MAC bypass)
// ---------------------------------------------------------------------------

/// Recover RMK from a record holding a permanent `wrap`, WITHOUT comparing the
/// state MAC. No sweep, no grant check, no attested time, no persist.
/// Callers pass only records holding a permanent `wrap`; a grant-only record is
/// never an input (see [`repair_state_entry`]).
pub(crate) fn unlock_for_repair(
    dir: &Path,
    reg: &DeviceRegistryFile,
    index: usize,
    device_secret: &[u8],
) -> Result<Key32, CryptoError> {
    let d = &reg.devices[index];
    secret32(&d.label, device_secret)?;
    tracing::warn!(device_id = %d.id, "state MAC unverified: repair path");
    let kek = derive_device_kek(device_secret, &d.id_bytes)?;
    rmk_from_permanent(reg, index, &kek, &devices_path(dir))
}

/// Repair a registry whose state MAC does not verify. Tries each eligible
/// device record, then the emergency slot path when `Y2QD_EMERGENCY_KEY` is
/// set. Performs exactly one `persist`. `now` is the host clock: it only
/// timestamps a burn, never a grant, because repair never mints one.
/// `accept_inventory` is the caller's acknowledgement that the operator
/// reviewed the printed inventory; when false this returns
/// `DeviceRepairNotAccepted` before touching any hardware and before any write.
pub fn repair_state_entry(
    dir: &Path,
    now: u64,
    policy: &DevicePolicy,
    pins: &dyn PinProvider,
    allow_away_repair: bool,
    accept_inventory: bool,
) -> Result<Authority, CryptoError> {
    if !accept_inventory {
        return Err(CryptoError::DeviceRepairNotAccepted);
    }
    let path = devices_path(dir);
    let mut reg = load(dir)?;
    let homes = home_count(&reg);
    // The MAC is checked against the registry exactly as loaded: an emergency
    // burn below mutates `reg` in memory before the check.
    let pristine = reg.clone();

    let mut rmk: Option<(Key32, Authority)> = None;
    let mut reasons: Vec<String> = Vec::new();
    let mut first_refused_away: Option<String> = None;

    for i in 0..reg.devices.len() {
        let label = reg.devices[i].label.clone();
        let id = reg.devices[i].id.clone();
        let result = match reg.devices[i].kind {
            DeviceKind::Tpm2 => {
                let params = reg.devices[i].tpm2.clone().expect("validated by load");
                tpm2::unseal(&params, &policy.tpm_tcti)
                    .and_then(|s| {
                        let g = s.unlock()?;
                        unlock_for_repair(dir, &reg, i, &g)
                    })
                    .map(|k| {
                        (
                            k,
                            Authority::Home {
                                id,
                                label: label.clone(),
                            },
                        )
                    })
            }
            DeviceKind::Fido2 => {
                let eligible = reg.devices[i].wrap.is_some() && homes == 0 && allow_away_repair;
                if !eligible {
                    first_refused_away.get_or_insert_with(|| label.clone());
                    continue;
                }
                let params = reg.devices[i].fido2.clone().expect("validated by load");
                fido2::hmac_secret(&params, &label, pins)
                    .and_then(|(s, _)| {
                        let g = s.unlock()?;
                        unlock_for_repair(dir, &reg, i, &g)
                    })
                    .map(|k| {
                        (
                            k,
                            Authority::Away {
                                id,
                                label: label.clone(),
                                not_after_unix: None,
                            },
                        )
                    })
            }
        };
        match result {
            Ok(found) => {
                rmk = Some(found);
                break;
            }
            Err(
                e @ (CryptoError::DeviceRegistryIo(_) | CryptoError::DeviceRegistryCorrupt { .. }),
            ) => {
                return Err(e);
            }
            Err(e) => reasons.push(format!("{label}: {e}")),
        }
    }

    if rmk.is_none() && std::env::var_os(super::EMERGENCY_KEY_ENV_VAR).is_some() {
        match super::emergency::unlock_for_repair(dir, &mut reg, now) {
            Ok((k, slot)) => rmk = Some((k, Authority::Emergency { index: slot })),
            Err(e) => reasons.push(format!("emergency code: {e}")),
        }
    }

    let Some((rmk, authority)) = rmk else {
        if let Some(label) = first_refused_away {
            return Err(CryptoError::DeviceAuthorityInsufficient {
                operation: "repair-state".to_owned(),
                required: "a home device or an emergency code".to_owned(),
                by: format!("away device '{label}'"),
            });
        }
        if reasons.is_empty() {
            return Err(CryptoError::DeviceAuthorityInsufficient {
                operation: "repair-state".to_owned(),
                required: "a home device or an emergency code".to_owned(),
                by: "no device record holding a permanent wrap".to_owned(),
            });
        }
        return Err(CryptoError::DeviceUnlockUnavailable(reasons.join("; ")));
    };

    // Open nk_wrap so a spliced or pre-rotation ciphertext cannot be re-signed.
    let nk = open_nk(&reg, &rmk, &path)?;
    if dir.join("keystore.json").exists() && !crate::crypto::keystore::rotation_journal_exists(dir)
    {
        crate::crypto::keystore::verify_node_key(dir, &nk)?;
    }
    let state_key = derive_state_key(&rmk)?;
    if verify_state_mac(&state_key, &pristine, &path).is_ok() {
        return Err(CryptoError::DeviceStateIntact);
    }
    for d in &mut reg.devices {
        d.grant = None;
    }
    persist(dir, &mut reg, &state_key)?;
    tracing::warn!("device registry state repaired: grants dropped, state re-signed as found");
    Ok(authority)
}
