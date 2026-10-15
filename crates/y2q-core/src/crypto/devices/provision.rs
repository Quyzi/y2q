//! Shared core of "create a device registry": enroll the first device and
//! write `devices.json` plus the emergency code sheet.
//!
//! Used by `y2q admin device init` and by `y2qd setup`. Wording-bearing policy
//! (the Secure Boot refusal text, the Roughtime attestation refusal) stays with
//! each caller; this module owns only the steps that must be identical.

use std::io::Write;
use std::path::{Path, PathBuf};

use super::registry::{self, valid_label};
use super::types::{DeviceKind, MAX_AWAY_GRANT_SECONDS, MIN_AWAY_GRANT_SECONDS, PinProvider};
use super::{devices_path, emergency, fido2, tpm2};
use crate::crypto::CryptoError;

/// The first device of a new registry.
pub enum FirstDevice<'a> {
    /// A TPM 2.0 home device sealed to `pcrs` (default label `home-tpm`).
    Tpm {
        label: Option<String>,
        tcti: &'a str,
        pcrs: &'a [u8],
    },
    /// A FIDO2 away device (default label `away-fido2`). The registry is then
    /// created with zero home devices (`permanent_away`).
    Fido2 {
        label: Option<String>,
        uv_required: bool,
        hid_path: Option<&'a str>,
    },
}

impl FirstDevice<'_> {
    fn label(&self) -> Option<&str> {
        match self {
            FirstDevice::Tpm { label, .. } | FirstDevice::Fido2 { label, .. } => label.as_deref(),
        }
    }
}

/// Inputs to [`init`].
pub struct InitRequest<'a> {
    /// Keystore directory that will hold `devices.json`.
    pub dir: &'a Path,
    pub first: FirstDevice<'a>,
    pub away_grant_seconds: u32,
    /// Wrap this existing node key instead of generating one.
    pub adopt: Option<&'a [u8; 32]>,
}

/// Why [`preflight`] or [`init`] refused.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// `keystore.json` is present and no node key to adopt was supplied.
    #[error(
        "keystore.json already exists; a fresh registry would generate a new node key that cannot read existing data — adopt the node key this deployment already uses instead"
    )]
    KeystoreExists,
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// What [`init`] created.
pub struct InitReport {
    pub registry_path: PathBuf,
    pub device_label: String,
    pub device_kind: DeviceKind,
    pub device_id: String,
}

/// Cheap refusals, in the order they have always been applied: grant period
/// range, an existing registry, an invalid label, then `keystore.json`
/// without an adopted key. Touches no hardware and writes nothing.
pub fn preflight(
    dir: &Path,
    label: Option<&str>,
    adopt: bool,
    away_grant_seconds: u32,
) -> Result<(), InitError> {
    if !(MIN_AWAY_GRANT_SECONDS..=MAX_AWAY_GRANT_SECONDS).contains(&away_grant_seconds) {
        return Err(CryptoError::DeviceGrantPeriodInvalid {
            seconds: away_grant_seconds,
        }
        .into());
    }
    if registry::exists(dir) {
        return Err(
            CryptoError::DeviceRegistryExists(devices_path(dir).display().to_string()).into(),
        );
    }
    if let Some(label) = label {
        valid_label(label).map_err(CryptoError::DeviceLabelInvalid)?;
    }
    if !adopt && dir.join("keystore.json").exists() {
        return Err(InitError::KeystoreExists);
    }
    Ok(())
}

/// Enroll the first device and create the registry.
///
/// The caller MUST hold [`crate::crypto::keystore::acquire_lock`] and
/// [`registry::lock_registry`] for `req.dir` and have called
/// [`crate::secmem::harden_process`]. `codes_out` receives the emergency code
/// sheet, written and flushed before anything touches disk.
pub fn init(
    req: &InitRequest<'_>,
    pins: &dyn PinProvider,
    now: u64,
    codes_out: &mut impl Write,
) -> Result<InitReport, InitError> {
    preflight(
        req.dir,
        req.first.label(),
        req.adopt.is_some(),
        req.away_grant_seconds,
    )?;
    let permanent_away = matches!(req.first, FirstDevice::Fido2 { .. });
    let first = match &req.first {
        FirstDevice::Tpm { label, tcti, pcrs } => {
            let label = label.clone().unwrap_or_else(|| "home-tpm".to_owned());
            tpm2::enroll(label, tcti, pcrs)?
        }
        FirstDevice::Fido2 {
            label,
            uv_required,
            hid_path,
        } => {
            let label = label.clone().unwrap_or_else(|| "away-fido2".to_owned());
            fido2::enroll(label, *uv_required, pins, *hid_path)?
        }
    };
    let (device_label, device_kind) = (first.label.clone(), first.kind);
    let outcome = emergency::init_registry(
        req.dir,
        first,
        req.away_grant_seconds,
        permanent_away,
        now,
        req.adopt,
        codes_out,
    )?;
    let device_id = outcome
        .registry
        .devices
        .first()
        .map(|d| d.id.clone())
        .unwrap_or_default();
    Ok(InitReport {
        registry_path: devices_path(req.dir),
        device_label,
        device_kind,
        device_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tpm(label: Option<&str>) -> FirstDevice<'static> {
        FirstDevice::Tpm {
            label: label.map(str::to_owned),
            tcti: "device:/nonexistent-tpm",
            pcrs: &[7],
        }
    }

    #[test]
    fn preflight_refuses_keystore_without_adopt() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("keystore.json"), "{}").unwrap();
        let e = preflight(dir.path(), None, false, 3600).unwrap_err();
        assert!(matches!(e, InitError::KeystoreExists));
        assert!(preflight(dir.path(), None, true, 3600).is_ok());
    }

    #[test]
    fn preflight_refuses_bad_grant_period_label_and_existing_registry() {
        let dir = tempfile::tempdir().unwrap();
        for secs in [MIN_AWAY_GRANT_SECONDS - 1, MAX_AWAY_GRANT_SECONDS + 1] {
            assert!(matches!(
                preflight(dir.path(), None, false, secs),
                Err(InitError::Crypto(
                    CryptoError::DeviceGrantPeriodInvalid { .. }
                ))
            ));
        }
        assert!(matches!(
            preflight(dir.path(), Some("bad\nlabel"), false, 3600),
            Err(InitError::Crypto(CryptoError::DeviceLabelInvalid(_)))
        ));
        std::fs::write(devices_path(dir.path()), "{}").unwrap();
        assert!(matches!(
            preflight(dir.path(), None, false, 3600),
            Err(InitError::Crypto(CryptoError::DeviceRegistryExists(_)))
        ));
    }

    #[test]
    fn init_refuses_before_touching_hardware() {
        struct NoPins;
        impl PinProvider for NoPins {
            fn pin(&self, _label: &str) -> Result<zeroize::Zeroizing<String>, CryptoError> {
                unreachable!("refused before any prompt")
            }
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("keystore.json"), "{}").unwrap();
        let req = InitRequest {
            dir: dir.path(),
            first: tpm(None),
            away_grant_seconds: 3600,
            adopt: None,
        };
        let mut sink = Vec::new();
        let e = init(&req, &NoPins, 1, &mut sink).err().unwrap();
        assert!(matches!(e, InitError::KeystoreExists));
        assert!(sink.is_empty());
        assert!(!registry::exists(dir.path()));
    }
}
