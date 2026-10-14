//! Device-based node-key unlock: TPM 2.0 home devices and FIDO2 away devices.
//!
//! # What this is
//!
//! A *registry* (`<keystore_dir>/devices.json`) holds the node key (NK) wrapped
//! under a Registry Master Key (RMK). RMK is in turn wrapped under:
//!
//! - every **home** device (TPM 2.0, PCR-sealed): permanent wrap;
//! - every **away** device (FIDO2 `hmac-secret`): a time-boxed **grant**, minted
//!   by a successful home unlock and valid until `not_after_unix` of
//!   **attested** (Roughtime) time; with zero home devices the wrap is permanent
//!   instead (a registry created with `--permanent-away`);
//! - ten **one-time emergency codes**, burned individually on use.
//!
//! # What it does and does not guarantee
//!
//! This is the exact statement of strength; nothing may claim more.
//!
//! - A grant's `not_after_unix` is enforced in software on every away unlock,
//!   which requires an attested time. Key material enforces it only after an
//!   **attested sweep** erases the ciphertext: an unlock with attested time
//!   (daemon boot, admin CLI or away unlock), or the daemon's timer. Loading
//!   the registry alone never erases, because it reads no clock. From the first
//!   such sweep after expiry, the away authenticator opens nothing on that
//!   medium, not with a patched binary and not with a correct PIN. Until that
//!   sweep runs, a patched binary holding the token and PIN can still open an
//!   expired grant, so a powered-off medium that is never swept keeps that
//!   exposure. No cryptographic time-lock exists without a trusted clock on the
//!   medium.
//! - A **copy of the medium taken while a grant was live**, combined later with
//!   the away token (and its PIN, if `uv_required`), yields RMK and therefore
//!   NK, on any host and at any later date, until a `device init` creates a new
//!   RMK. The expiry check is software: a patched binary ignores
//!   `not_after_unix` on the copy. Erasure never reaches a copy already taken.
//!   A home-booted daemon re-mints grants every `grant_timer_interval_seconds`,
//!   so while it runs a snapshot always contains a live grant. After it stops,
//!   the last grant stays openable until the next attested sweep.
//!   `away_grant_seconds` therefore bounds only the *original* medium (once an
//!   attested sweep erases the grant), not a copy, and not the refresh chain.
//! - A **home device** plus the medium always yields NK: the home wrap is
//!   permanent by construction, because something has to be able to mint the
//!   next grant. TPM sealing bounds that: the sealed blob is useless on another
//!   machine and refuses after a boot-chain change, but it does not bound an
//!   attacker who has the whole host running. With zero home devices, each away
//!   token plus the medium yields NK permanently; that is the price of the
//!   no-network mode, chosen explicitly at init with `--permanent-away`. With
//!   zero home devices, anyone holding an away token, its PIN and the medium can
//!   also add a persistent FIDO2 record (`add-fido2` under `Away`), and only an
//!   emergency code can remove it.
//! - The authenticator's PIN retry lockout (8 attempts on commodity tokens, then
//!   the FIDO2 application resets and destroys the credential) is the only
//!   hardware bound on a drive and token stolen together inside a live window.
//!   It exists **only** for devices registered with `uv_required = true`, and
//!   only when the PIN is not stored on the same medium — `--no-uv`
//!   registration and a `Y2QD_FIDO2_PIN` written into a unit file beside
//!   `keystore_dir` each remove it. Where this text says "token and PIN", a
//!   `--no-uv` device needs the token alone.
//! - Post-quantum posture. The ML-KEM-768 secrets (tiers 1 and 2) are wrapped at
//!   rest under symmetric keys, so no Shor-reachable at-rest secret exists; the
//!   symmetric layers lose only Grover margin. The quantum-exposed links are:
//!   (a) Roughtime's Ed25519 signatures (RFC 10049 §9.5: "not quantum
//!   resistant"): a quantum adversary holding a stale medium could forge time
//!   and reopen an expired grant, though the token (and PIN) requirement still
//!   applies; and (b) the CTAP2 `hmac-secret` transport, an ECDH exchange on the
//!   local USB bus. y2q never verifies the FIDO2 assertion signature (ES256
//!   credential); the secret comes from `hmac-secret` only.
//! - Process separation. In socket-activated helper mode (`y2q-keyd.socket`
//!   spawns a fresh `y2qd --key-serve` per connection, as a different uid) no
//!   resident process holds RMK. Root arms one-time authorization (`--key-arm`,
//!   stored in a 0600 file on tmpfs); the daemon fetches once; the helper
//!   consumes the armed file, unlocks, returns NK and exits. A compromised
//!   daemon uid holds one transient raw NK copy from boot but not RMK, the TPM
//!   or registry authority, and cannot re-fetch without a root-armed
//!   authorization. In legacy in-process mode (empty `key_agent_socket`) the
//!   daemon holds RMK and TPM access, so compromising its uid yields NK and
//!   registry authority. Root on the live host defeats both modes.
//! - `devices.json` is not encrypted as a whole: labels, ids, timestamps, PCR
//!   slots, credential ids, sign counts, burn flags, grant deadlines and the
//!   device count are readable (every secret is AEAD-wrapped). A stale copy
//!   replays burned slots and revives erased grants.
//! - An older copy of `devices.json` verifies under the same state key, and RMK
//!   is never rotated, so anyone who ever unlocked this registry retains RMK and
//!   can forge registry state; a restored backup also revives already-burned
//!   emergency slots. Cutting off a party that has already unlocked takes a new
//!   RMK, which only a new registry creates: stop the daemon →
//!   `--rotate-node-key` to an operator-supplied key → delete `devices.json` →
//!   `y2q admin device init --adopt-existing-node-key`. Registry backups carry
//!   the same authority as the printed code sheet.
//! - On flash media the erased grant ciphertext may survive in unreferenced FTL
//!   blocks; erasure is a logical revocation, not guaranteed physical
//!   destruction.
//! - In a portable deployment `keystore_dir` travels on the same medium, so a
//!   stolen drive still exposes `users.redb`, whose identity keys are Argon2id-
//!   wrapped under user passwords; password strength and the configured Argon2
//!   cost remain the bound there, independent of this feature.
//! - A grant's expiry is checked against attested time only: a grant is usable
//!   while `max(L_i) <= not_after_unix`, where `L_i` is the lower bound of each
//!   usable response. True time may then exceed `not_after_unix` by up to
//!   `min(U_i) − max(L_i)`, at most `2 × MAX_RADIUS_S` = 120 s. This slack is
//!   accepted.
//!
//! The authority table (which operation each [`Authority`] may perform) bounds
//! the stock CLI and daemon and operator error. It is not a cryptographic bound
//! on a holder of the authenticator: an away unlock inside its window already
//! yields RMK and NK. The cryptographic bound is the grant's lifetime.
//!
//! A grant bounds future cold-start unlocks from an away device, not an
//! already-authorized session; killing a serving daemon on a key-management
//! timer would convert a policy boundary into an availability outage and would
//! not restore secrecy of anything the grant protects, since NK is already
//! resident.
//!
//! # Gating
//!
//! Everything touching hardware is `#[cfg(all(target_os = "linux", feature =
//! "devices"))]` (DEV-GATE). Without it, a present `devices.json` is refused
//! with [`CryptoError::DeviceSupportNotCompiled`].

use std::path::{Path, PathBuf};

use super::CryptoError;

pub mod types;
pub use types::*;

#[cfg(target_os = "linux")]
pub mod keyrpc;

#[cfg(all(target_os = "linux", feature = "devices"))]
pub mod emergency;
#[cfg(all(target_os = "linux", feature = "devices"))]
pub mod fido2;
#[cfg(all(target_os = "linux", feature = "devices"))]
pub mod registry;
#[cfg(all(target_os = "linux", feature = "devices"))]
pub mod roughtime;
#[cfg(all(target_os = "linux", feature = "devices"))]
pub mod tpm2;

/// File name of the device registry inside the keystore directory.
pub const DEVICES_FILE: &str = "devices.json";

/// Environment variable carrying an emergency code. Read by the daemon's
/// `resolve` on every target, so it stays ungated.
pub const EMERGENCY_KEY_ENV_VAR: &str = "Y2QD_EMERGENCY_KEY";

/// Path of the device registry inside `dir`.
pub fn devices_path(dir: &Path) -> PathBuf {
    dir.join(DEVICES_FILE)
}

/// Host-clock unix seconds. Used only to stamp `added_at_unix` / `burned_at_unix`
/// and for advisory display; never for an access decision.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Refuse to boot when a registry is present but this build cannot use it.
#[cfg(not(all(target_os = "linux", feature = "devices")))]
pub fn refuse_if_present(dir: &Path) -> Result<(), CryptoError> {
    if devices_path(dir).exists() {
        return Err(CryptoError::DeviceSupportNotCompiled(
            devices_path(dir).display().to_string(),
        ));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "devices"))]
pub use registry::sweep_now;

/// Unavailable in this build.
#[cfg(not(all(target_os = "linux", feature = "devices")))]
pub fn unlock(
    dir: &Path,
    _policy: &DevicePolicy,
    _pins: &dyn PinProvider,
    _time: &dyn TimeSource,
    _now_host: u64,
) -> Result<UnlockOutcome, CryptoError> {
    Err(CryptoError::DeviceSupportNotCompiled(
        devices_path(dir).display().to_string(),
    ))
}

/// Unavailable in this build.
#[cfg(not(all(target_os = "linux", feature = "devices")))]
pub fn unlock_home(
    dir: &Path,
    _policy: &DevicePolicy,
    _pins: &dyn PinProvider,
    _time: &dyn TimeSource,
    _now_host: u64,
) -> Result<UnlockOutcome, CryptoError> {
    Err(CryptoError::DeviceSupportNotCompiled(
        devices_path(dir).display().to_string(),
    ))
}

/// Unavailable in this build.
#[cfg(not(all(target_os = "linux", feature = "devices")))]
pub fn sweep_now(
    _dir: &Path,
    _state_key: &[u8; 32],
    _rmk: Option<&[u8; 32]>,
    _time: &dyn TimeSource,
) -> Result<(usize, usize), CryptoError> {
    Err(CryptoError::DeviceSupportNotCompiled(
        "(sweep_now)".to_owned(),
    ))
}

/// Whether an error is one the orchestrator keeps going past, recording
/// `label: error` for the final reason. Every other variant is fatal.
#[cfg(all(target_os = "linux", feature = "devices"))]
fn is_continue_class(e: &CryptoError) -> bool {
    matches!(
        e,
        CryptoError::TpmPcrMismatch
            | CryptoError::TpmUnavailable(_)
            | CryptoError::Tpm(_)
            | CryptoError::DeviceBackend(_)
            | CryptoError::DeviceSecretLength { .. }
            | CryptoError::DeviceUnwrapFailed
            | CryptoError::DeviceGrantAbsent { .. }
            | CryptoError::DeviceGrantExpired { .. }
            | CryptoError::DeviceSignCountRollback { .. }
            | CryptoError::AttestedTimeUnavailable(_)
            | CryptoError::AttestedTimeInconsistent { .. }
            | CryptoError::RoughtimeNotConfigured
    )
}

#[cfg(all(target_os = "linux", feature = "devices"))]
fn finish_outcome(
    reg: DeviceRegistryFile,
    nk: Key32,
    rmk: Key32,
    authority: Authority,
    grants_issued: usize,
    grants_erased: usize,
) -> Result<UnlockOutcome, CryptoError> {
    let state_key = registry::derive_state_key(&rmk)?;
    let unused = reg
        .emergency_slots
        .iter()
        .filter(|s| s.wrap.is_some())
        .count();
    Ok(UnlockOutcome {
        node_key: nk,
        registry_master_key: rmk,
        registry_state_key: state_key,
        registry: reg,
        authority,
        grants_issued,
        grants_erased,
        emergency_slots_unused: unused,
    })
}

/// Try every `Tpm2` record in file order. The first to open wins; its
/// `persist` has already written the swept and freshly minted grants.
/// Continue-class failures are appended to `reasons`; any other error is fatal.
/// The raw TPM secret is combined with the record's second factor (passcode or
/// a referenced token) by [`registry::home_device_secret`] before the unwrap.
#[cfg(all(target_os = "linux", feature = "devices"))]
fn try_home_records(
    dir: &Path,
    reg: &mut DeviceRegistryFile,
    policy: &DevicePolicy,
    pins: &dyn PinProvider,
    time: &dyn TimeSource,
    reasons: &mut Vec<String>,
) -> Result<Option<(Unlock, Authority)>, CryptoError> {
    for i in 0..reg.devices.len() {
        if reg.devices[i].kind != DeviceKind::Tpm2 {
            continue;
        }
        let label = reg.devices[i].label.clone();
        let id = reg.devices[i].id.clone();
        let attempt =
            (|| -> Result<Unlock, CryptoError> {
                let params = reg.devices[i].tpm2.clone().ok_or_else(|| {
                    CryptoError::DeviceRegistryCorrupt {
                        path: devices_path(dir).display().to_string(),
                        reason: format!("tpm2 device {id} has no tpm2 parameters"),
                    }
                })?;
                let secret = tpm2::unseal(&params, &policy.tpm_tcti)?;
                let guard = secret.unlock()?;
                let device_secret = registry::home_device_secret(reg, i, &guard, pins)?;
                registry::unlock_with_home(dir, reg, i, &device_secret, time, policy)
            })();
        match attempt {
            Ok(u) => return Ok(Some((u, Authority::Home { id, label }))),
            Err(e) if is_continue_class(&e) => reasons.push(format!("{label}: {e}")),
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// Unlock the registry with a home device only: no emergency code and no away
/// device is tried (so no authenticator PIN is requested for an away record).
/// Fails with [`CryptoError::DeviceUnlockUnavailable`] carrying the per-record
/// reasons when no home record opens.
#[cfg(all(target_os = "linux", feature = "devices"))]
pub fn unlock_home(
    dir: &Path,
    policy: &DevicePolicy,
    pins: &dyn PinProvider,
    time: &dyn TimeSource,
    _now_host: u64,
) -> Result<UnlockOutcome, CryptoError> {
    let mut reg = registry::load(dir)?;
    let mut reasons: Vec<String> = Vec::new();
    if let Some((u, authority)) = try_home_records(dir, &mut reg, policy, pins, time, &mut reasons)?
    {
        return finish_outcome(
            reg,
            u.nk,
            u.rmk,
            authority,
            u.grants_issued,
            u.grants_erased,
        );
    }
    Err(CryptoError::DeviceUnlockUnavailable(
        if reasons.is_empty() {
            "no home devices registered".to_owned()
        } else {
            reasons.join("; ")
        },
    ))
}

/// Unlock the registry in `dir` and return NK.
///
/// Order: load → emergency code (from `pins.emergency_code()`) → each TPM
/// record → each FIDO2 record. Errors from device attempts are classified
/// (fatal vs continue); see [`is_continue_class`]. The first success wins and
/// has already persisted its own bookkeeping.
#[cfg(all(target_os = "linux", feature = "devices"))]
pub fn unlock(
    dir: &Path,
    policy: &DevicePolicy,
    pins: &dyn PinProvider,
    time: &dyn TimeSource,
    now_host: u64,
) -> Result<UnlockOutcome, CryptoError> {
    let mut reg = registry::load(dir)?;

    let code = pins.emergency_code()?;
    match emergency::emergency_unlock(dir, &mut reg, now_host, code) {
        Ok(Some(e)) => {
            return finish_outcome(
                reg,
                e.nk,
                e.rmk,
                Authority::Emergency { index: e.slot },
                0,
                0,
            );
        }
        Ok(None) => {}
        Err(e @ (CryptoError::EmergencyCodesExhausted | CryptoError::EmergencyCodeRejected)) => {
            tracing::warn!(error = %e, "emergency unlock skipped");
        }
        Err(e) => return Err(e),
    }

    let mut reasons: Vec<String> = Vec::new();

    if let Some((u, authority)) = try_home_records(dir, &mut reg, policy, pins, time, &mut reasons)?
    {
        return finish_outcome(
            reg,
            u.nk,
            u.rmk,
            authority,
            u.grants_issued,
            u.grants_erased,
        );
    }

    for i in 0..reg.devices.len() {
        if reg.devices[i].kind != DeviceKind::Fido2 {
            continue;
        }
        let label = reg.devices[i].label.clone();
        let id = reg.devices[i].id.clone();
        let (has_wrap, grant_deadline) = (
            reg.devices[i].wrap.is_some(),
            reg.devices[i].grant.as_ref().map(|g| g.not_after_unix),
        );
        if !has_wrap && grant_deadline.is_none() {
            // Nothing to authenticate against: do not prompt for a touch that cannot succeed.
            reasons.push(format!(
                "{label}: {}",
                CryptoError::DeviceGrantAbsent {
                    label: label.clone()
                }
            ));
            continue;
        }
        let attempt =
            (|| -> Result<Unlock, CryptoError> {
                let params = reg.devices[i].fido2.clone().ok_or_else(|| {
                    CryptoError::DeviceRegistryCorrupt {
                        path: devices_path(dir).display().to_string(),
                        reason: format!("fido2 device {id} has no fido2 parameters"),
                    }
                })?;
                let (secret, sign_count) = fido2::hmac_secret(&params, &label, pins)?;
                let guard = secret.unlock()?;
                registry::unlock_with_away(dir, &mut reg, i, &guard, sign_count, time, policy)
            })();
        match attempt {
            Ok(u) => {
                return finish_outcome(
                    reg,
                    u.nk,
                    u.rmk,
                    Authority::Away {
                        id,
                        label,
                        not_after_unix: if has_wrap { None } else { grant_deadline },
                    },
                    0,
                    u.grants_erased,
                );
            }
            Err(e) if is_continue_class(&e) => reasons.push(format!("{label}: {e}")),
            Err(e) => return Err(e),
        }
    }

    Err(CryptoError::DeviceUnlockUnavailable(
        if reasons.is_empty() {
            "no devices registered".to_owned()
        } else {
            reasons.join("; ")
        },
    ))
}

#[cfg(all(test, target_os = "linux", feature = "devices"))]
mod tests;
