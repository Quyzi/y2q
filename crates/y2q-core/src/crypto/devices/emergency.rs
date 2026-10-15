//! Emergency codes and registry initialisation.
//!
//! Ten one-time codes are printed once, by [`init_registry`], and never stored.
//! Only their commitment `ESC` is persisted; `ESC` is bound into every AAD, so
//! a replaced set cannot open existing data and codes cannot be regenerated
//! inside an existing registry.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use hkdf::Hkdf;
use rand::Rng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::registry::{
    self, check, derive_device_kek, derive_emergency_kek, derive_state_key, device_wrap_aad,
    emergency_wrap_aad, fsync_dir, hex, kek_cache_aad, kek_cache_key, nk_wrap_aad, nk_wrap_key,
    state_mac, unwrap_secret, valid_label, verify_state_mac, wrap_secret,
};
use super::types::*;
use super::{EMERGENCY_KEY_ENV_VAR, devices_path};
use crate::crypto::CryptoError;

const NODE_KEY_ROOT_SALT: &[u8] = b"y2q/v4/node-key-root";
const EMERGENCY_SET_LABEL: &[u8] = b"y2q/v1/emergency-set";
/// 32 bytes, so the emergency path does not lower the hierarchy's documented
/// 256-bit ceiling: each slot is an offline oracle for anyone holding the
/// drive, so a shorter code would become the cheapest attack on RMK.
const EMERGENCY_CODE_BYTES: usize = 32;

/// Result of [`init_registry`].
pub struct InitOutcome {
    /// The node key the registry now wraps.
    pub node_key: Key32,
    /// The registry exactly as written.
    pub registry: DeviceRegistryFile,
}

fn path_string(dir: &Path) -> String {
    devices_path(dir).display().to_string()
}

fn io_err(what: &str, e: std::io::Error) -> CryptoError {
    CryptoError::DeviceRegistryIo(format!("{what}: {e}"))
}

/// Create a new registry in `dir` with `first` as its first device.
///
/// `adopt`: `None` generates a fresh NK; `Some(nk)` wraps an existing
/// operator-supplied NK instead (the migration path).
///
/// The twelve-line code sheet is printed to `out` and flushed *before* anything
/// touches disk: an unprintable set must not become the committed set.
pub fn init_registry(
    dir: &Path,
    first: NewDevice,
    away_grant_seconds: u32,
    permanent_away: bool,
    now: u64,
    adopt: Option<&[u8; 32]>,
    out: &mut impl Write,
) -> Result<InitOutcome, CryptoError> {
    let path = devices_path(dir);
    // 1.
    if registry::exists(dir) {
        return Err(CryptoError::DeviceRegistryExists(path_string(dir)));
    }
    if permanent_away != (first.kind == DeviceKind::Fido2) {
        return Err(CryptoError::DevicePermanentAwayMismatch { kind: first.kind });
    }
    if !(MIN_AWAY_GRANT_SECONDS..=MAX_AWAY_GRANT_SECONDS).contains(&away_grant_seconds) {
        return Err(CryptoError::DeviceGrantPeriodInvalid {
            seconds: away_grant_seconds,
        });
    }
    valid_label(&first.label).map_err(CryptoError::DeviceLabelInvalid)?;
    let first_guard = first.secret.unlock()?;
    if first_guard.len() != 32 {
        return Err(CryptoError::DeviceSecretLength {
            label: first.label.clone(),
            len: first_guard.len(),
        });
    }

    // 2.
    let mut rmk = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(&mut *rmk);

    // 3. Never persisted, never returned: NK is not a pure function of the codes.
    let root_secret = match adopt {
        None => {
            let mut r = Zeroizing::new([0u8; 32]);
            rand::rng().fill_bytes(&mut *r);
            Some(r)
        }
        Some(nk) => {
            if dir.join("keystore.json").exists() {
                crate::crypto::keystore::verify_node_key(dir, nk)?;
            }
            None
        }
    };

    // 4.
    let mut codes: Vec<Zeroizing<[u8; EMERGENCY_CODE_BYTES]>> = Vec::with_capacity(EMERGENCY_SLOTS);
    for _ in 0..EMERGENCY_SLOTS {
        let mut c = Zeroizing::new([0u8; EMERGENCY_CODE_BYTES]);
        rand::rng().fill_bytes(&mut *c);
        codes.push(c);
    }

    // 5.
    let mut esc_hasher = Sha256::new();
    esc_hasher.update(EMERGENCY_SET_LABEL);
    for c in &codes {
        esc_hasher.update(Sha256::digest(&c[..]));
    }
    let esc: [u8; 32] = esc_hasher.finalize().into();

    // 6.
    let nk: Key32 = match (adopt, &root_secret) {
        (Some(nk), _) => Zeroizing::new(*nk),
        (None, Some(root)) => {
            let mut ikm = Zeroizing::new([0u8; 64]);
            ikm[..32].copy_from_slice(&root[..]);
            ikm[32..].copy_from_slice(&esc);
            let (prk, _) = Hkdf::<Sha256>::extract(Some(NODE_KEY_ROOT_SALT), &ikm[..]);
            Zeroizing::new(prk.into())
        }
        (None, None) => unreachable!("root_secret is Some whenever adopt is None"),
    };

    // 7.
    let nk_wrap = wrap_secret(
        &*nk_wrap_key(&rmk)?,
        &nk,
        &nk_wrap_aad(&esc, away_grant_seconds),
    )?;

    // 8.
    let mut slots = Vec::with_capacity(EMERGENCY_SLOTS);
    for (i, c) in codes.iter().enumerate() {
        let index = u8::try_from(i).expect("EMERGENCY_SLOTS fits in u8");
        let kek = derive_emergency_kek(&c[..], index)?;
        slots.push(EmergencySlot {
            index,
            wrap: Some(wrap_secret(&kek, &rmk, &emergency_wrap_aad(index, &esc))?),
            burned_at_unix: None,
        });
    }

    // 9.
    let mut id_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut id_bytes);
    let kek_device = derive_device_kek(&first_guard, &id_bytes)?;
    let mut rec = DeviceRecord {
        id: hex(&id_bytes),
        label: first.label.clone(),
        kind: first.kind,
        added_at_unix: now,
        wrap: None,
        grant: None,
        tpm2: None,
        fido2: None,
        sign_count_last: None,
        kek_wrap: None,
        home_factor: None,
        id_bytes,
    };
    match first.kind {
        DeviceKind::Tpm2 => {
            rec.tpm2 = Some(first.tpm2.clone().ok_or_else(|| {
                CryptoError::DeviceBackend(
                    "enrollment result carries no tpm2 parameters".to_owned(),
                )
            })?);
            rec.wrap = Some(wrap_secret(
                &kek_device,
                &rmk,
                &device_wrap_aad(&id_bytes, DeviceKind::Tpm2, false, &esc),
            )?);
        }
        DeviceKind::Fido2 => {
            let params = first.fido2.clone().ok_or_else(|| {
                CryptoError::DeviceBackend(
                    "enrollment result carries no fido2 parameters".to_owned(),
                )
            })?;
            rec.wrap = Some(wrap_secret(
                &kek_device,
                &rmk,
                &device_wrap_aad(&id_bytes, DeviceKind::Fido2, params.uv_required, &esc),
            )?);
            rec.kek_wrap = Some(wrap_secret(
                &*kek_cache_key(&rmk)?,
                &kek_device,
                &kek_cache_aad(&id_bytes, &esc),
            )?);
            rec.sign_count_last = Some(first.sign_count);
            rec.fido2 = Some(params);
        }
    }
    drop(first_guard);

    // 10.
    let mut reg = DeviceRegistryFile {
        format_version: DEVICES_FORMAT_VERSION,
        esc_b64: STANDARD.encode(esc),
        away_grant_seconds,
        permanent_away,
        nk_wrap,
        state_mac_b64: String::new(),
        devices: vec![rec],
        emergency_slots: slots,
        esc,
    };
    let state_key = derive_state_key(&rmk)?;
    reg.state_mac_b64 = STANDARD.encode(state_mac(&state_key, &reg));
    check(&reg, &path)?;
    let bytes = serde_json::to_vec_pretty(&reg)
        .map_err(|e| CryptoError::DeviceRegistryIo(format!("serialize: {e}")))?;

    // 11. Print before anything touches disk.
    print_codes(&codes, out)?;
    drop(codes);

    // 12. Atomic write, no clobber.
    let tmp = dir.join(registry::TMP_FILE);
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(&format!("remove stale {}", tmp.display()), e)),
    }
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| io_err(&format!("create {}", tmp.display()), e))?;
    f.write_all(&bytes)
        .and_then(|()| f.sync_all())
        .map_err(|e| io_err(&format!("write {}", tmp.display()), e))?;
    drop(f);
    if registry::exists(dir) {
        let _ = fs::remove_file(&tmp);
        return Err(CryptoError::DeviceRegistryExists(path_string(dir)));
    }
    fs::rename(&tmp, &path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_err(
            &format!("rename {} -> {}", tmp.display(), path.display()),
            e,
        )
    })?;
    // A directory-fsync error after the rename is reported; the printed set stands.
    fsync_dir(dir)?;

    // 13. `codes`, `rmk` and `root_secret` zeroize on drop.
    Ok(InitOutcome {
        node_key: nk,
        registry: reg,
    })
}

/// Print the twelve-line sheet and flush. Each code is `STANDARD.encode` of
/// 32 bytes = 44 characters.
fn print_codes(
    codes: &[Zeroizing<[u8; EMERGENCY_CODE_BYTES]>],
    out: &mut impl Write,
) -> Result<(), CryptoError> {
    let werr =
        |e: std::io::Error| CryptoError::DeviceRegistryIo(format!("print emergency codes: {e}"));
    writeln!(
        out,
        "emergency access codes (printed once, never stored, cannot be regenerated):"
    )
    .map_err(werr)?;
    for (i, c) in codes.iter().enumerate() {
        let text = Zeroizing::new(STANDARD.encode(&c[..]));
        writeln!(out, "{:>2}: {}", i + 1, text.as_str()).map_err(werr)?;
    }
    writeln!(
        out,
        "WARNING: write these down now. Each code unlocks this node exactly once and is erased on use. There is no way to print them again and no way to generate new ones. Keep at least two unused."
    )
    .map_err(werr)?;
    out.flush().map_err(werr)
}

/// Take `Y2QD_EMERGENCY_KEY` out of the environment and decode it to 32 bytes.
fn take_code() -> Result<Option<Zeroizing<Vec<u8>>>, CryptoError> {
    let text = match crate::crypto::node_key::take_env_secret(EMERGENCY_KEY_ENV_VAR) {
        Ok(Some(t)) => t,
        Ok(None) => return Ok(None),
        Err(CryptoError::NodeKeyMalformed(_)) => {
            return Err(CryptoError::EmergencyCodeMalformed(
                "Y2QD_EMERGENCY_KEY is not valid UTF-8".to_owned(),
            ));
        }
        Err(e) => return Err(e),
    };
    Ok(Some(decode_code(text.trim())?))
}

fn decode_code(text: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let malformed = || {
        CryptoError::EmergencyCodeMalformed(
            "expected 32 bytes of standard base64 — paste the exact string printed at registry init"
                .to_owned(),
        )
    };
    let raw = STANDARD
        .decode(text)
        .or_else(|_| STANDARD_NO_PAD.decode(text))
        .map_err(|_| malformed())?;
    let raw = Zeroizing::new(raw);
    if raw.len() != EMERGENCY_CODE_BYTES {
        return Err(malformed());
    }
    Ok(raw)
}

/// Try `code` against every unburned slot in ascending index. Returns RMK and
/// the position of the slot that opened.
fn open_slot(
    reg: &DeviceRegistryFile,
    code: &[u8],
    path: &Path,
) -> Result<(Key32, usize), CryptoError> {
    if reg.emergency_slots.iter().all(|s| s.wrap.is_none()) {
        return Err(CryptoError::EmergencyCodesExhausted);
    }
    for (pos, slot) in reg.emergency_slots.iter().enumerate() {
        let Some(wrap) = &slot.wrap else { continue };
        let kek = derive_emergency_kek(code, slot.index)?;
        match unwrap_secret(&kek, wrap, &emergency_wrap_aad(slot.index, &reg.esc), path) {
            Ok(rmk) => return Ok((rmk, pos)),
            Err(CryptoError::DeviceUnwrapFailed) => {}
            Err(e) => return Err(e),
        }
    }
    Err(CryptoError::EmergencyCodeRejected)
}

/// Unlock with `code` (the operator-supplied emergency code text, normally
/// from [`PinProvider::emergency_code`]); `Ok(None)` when no code was supplied.
///
/// Performs no grant sweep and reads no attested time: a printed code is
/// out-of-band authority and must work on a host with a wrong clock. This path
/// neither erases nor mints grants. `now_host` only stamps `burned_at_unix`
/// for audit; nothing reads it for a decision.
///
/// Burn-before-serve: NK is opened first (a corrupt `nk_wrap` consumes no
/// code), then the slot is burned and persisted, and only then is NK returned.
pub fn emergency_unlock(
    dir: &Path,
    reg: &mut DeviceRegistryFile,
    now_host: u64,
    code: Option<Zeroizing<String>>,
) -> Result<Option<EmergencyUnlock>, CryptoError> {
    let Some(text) = code else {
        return Ok(None);
    };
    let code = decode_code(text.trim())?;
    let path = devices_path(dir);
    let (rmk, pos) = open_slot(reg, &code, &path)?;
    let state_key = derive_state_key(&rmk)?;
    verify_state_mac(&state_key, reg, &path)?;
    let nk = registry::open_nk_pub(reg, &rmk, dir)?;
    let slot = &mut reg.emergency_slots[pos];
    let index = slot.index;
    slot.wrap = None;
    slot.burned_at_unix = Some(now_host);
    registry::persist(dir, reg, &state_key)?;
    Ok(Some(EmergencyUnlock {
        nk,
        rmk,
        slot: index,
    }))
}

/// Repair-path emergency unlock: recovers RMK from `Y2QD_EMERGENCY_KEY`
/// WITHOUT verifying the state MAC and burns the slot IN MEMORY only
/// (`wrap = None`, `burned_at_unix = Some(now)`, so `check()` still passes);
/// the caller's single `persist` commits it.
pub(crate) fn unlock_for_repair(
    dir: &Path,
    reg: &mut DeviceRegistryFile,
    now: u64,
) -> Result<(Key32, u8), CryptoError> {
    let Some(code) = take_code()? else {
        return Err(CryptoError::EmergencyCodeMalformed(
            "Y2QD_EMERGENCY_KEY is not set".to_owned(),
        ));
    };
    tracing::warn!("state MAC unverified: repair path");
    let (rmk, pos) = open_slot(reg, &code, &devices_path(dir))?;
    let slot = &mut reg.emergency_slots[pos];
    let index = slot.index;
    slot.wrap = None;
    slot.burned_at_unix = Some(now);
    Ok((rmk, index))
}

/// Replace `nk_wrap` with `AES-256-GCM(HKDF(rmk, "y2q/v1/nk-wrap-key"), new_nk,
/// nk_wrap_aad(esc, away_grant_seconds))` and persist. Needs only RMK, so no
/// device and no code must be present. Used by node-key rotation.
pub fn rewrite_nk_wrap(
    dir: &Path,
    reg: &mut DeviceRegistryFile,
    rmk: &[u8; 32],
    new_nk: &[u8; 32],
) -> Result<(), CryptoError> {
    reg.nk_wrap = wrap_secret(
        &*nk_wrap_key(rmk)?,
        new_nk,
        &nk_wrap_aad(&reg.esc, reg.away_grant_seconds),
    )?;
    registry::persist(dir, reg, &*derive_state_key(rmk)?)
}
