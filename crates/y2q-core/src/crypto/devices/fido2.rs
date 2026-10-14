//! FIDO2 / CTAP2 `hmac-secret` away-device backend.
//!
//! Vendor-neutral: any authenticator that supports the `hmac-secret` extension can be
//! registered. The credential is non-discoverable; the device secret is the
//! `hmac-secret` output for a public per-device salt, so it exists only inside the
//! authenticator (its CredRandom) and is never stored on the medium.
//!
//! Post-quantum disclosure: the KEK derived from that secret is symmetric at rest, but
//! the CTAP2 `hmac-secret` wire exchange encrypts the salt and output under a P-256
//! ECDH shared secret negotiated with the token over the local USB bus. That transport
//! is classically asymmetric and is outside the at-rest post-quantum invariant; a
//! recorded USB session, not the drive, would be the exposure.
//!
//! The `ctap-hid-fido2` crate returns `anyhow::Result`; every call site converts the
//! error to a `CryptoError::DeviceBackend` string immediately, so no `anyhow` type is
//! named here.

use super::types::*;
use crate::crypto::CryptoError;
use crate::secmem::SecretBuf;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Extension as AssertExt;
use ctap_hid_fido2::fidokey::get_info::{InfoOption, InfoParam};
use ctap_hid_fido2::fidokey::{
    CredentialExtension, GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::{Cfg, FidoKeyHid, FidoKeyHidFactory, HidInfo, HidParam};
use zeroize::Zeroize;

/// Relying-party id every y2q credential is created under.
pub const RP_ID: &str = "y2q.local";
const USER_ID: &[u8] = b"y2q-node-key";
const USER_NAME: &str = "y2q";
const USER_DISPLAY_NAME: &str = "y2q node key";
const MAX_CREDENTIAL_ID_LEN: usize = 1024;

/// Outcome of the silent presence probe against one attached authenticator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeClass {
    /// The device holds the credential.
    Present,
    /// The device answered `CTAP2_ERR_NO_CREDENTIALS`.
    Absent,
    /// The device answered `CTAP2_ERR_PIN_REQUIRED` before looking the credential up.
    Indeterminate,
    /// Any other error.
    Failed,
}

fn backend(e: impl std::fmt::Display) -> CryptoError {
    CryptoError::DeviceBackend(format!("fido2: {e}"))
}

fn backend_msg(msg: impl Into<String>) -> CryptoError {
    CryptoError::DeviceBackend(msg.into())
}

/// Pure classification of a presence-probe answer (see the module plan, §5).
pub(crate) fn classify_probe(answer: &Result<(), String>) -> ProbeClass {
    match answer {
        Ok(()) => ProbeClass::Present,
        Err(text) if text.contains("CTAP2_ERR_NO_CREDENTIALS") => ProbeClass::Absent,
        Err(text) if text.contains("CTAP2_ERR_PIN_REQUIRED") => ProbeClass::Indeterminate,
        Err(_) => ProbeClass::Failed,
    }
}

/// Indices of the devices to try, in enumeration order: every `Present`; only when none
/// is `Present`, every `Indeterminate`; never `Absent` or `Failed`.
pub(crate) fn select_candidates(classes: &[ProbeClass]) -> Vec<usize> {
    let pick = |want: ProbeClass| -> Vec<usize> {
        classes
            .iter()
            .enumerate()
            .filter(|(_, c)| **c == want)
            .map(|(i, _)| i)
            .collect()
    };
    let present = pick(ProbeClass::Present);
    if present.is_empty() {
        pick(ProbeClass::Indeterminate)
    } else {
        present
    }
}

/// Everything known about one attached device after an unlock attempt.
struct Attached {
    path: String,
    class: ProbeClass,
    probe_err: Option<String>,
    selected: bool,
    assertion_err: Option<String>,
}

/// One `path: reason` entry per attached device, joined with `"; "`.
fn format_reasons(rows: &[Attached]) -> String {
    rows.iter()
        .map(|r| {
            let reason = match r.class {
                ProbeClass::Absent => "no matching credential".to_owned(),
                ProbeClass::Failed => r
                    .probe_err
                    .clone()
                    .unwrap_or_else(|| "probe failed".to_owned()),
                _ if r.selected => r
                    .assertion_err
                    .clone()
                    .unwrap_or_else(|| "assertion failed".to_owned()),
                _ => "not tried (another device holds the credential)".to_owned(),
            };
            format!("{}: {reason}", r.path)
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn path_of(info: &HidInfo) -> String {
    match &info.param {
        HidParam::Path(p) => p.clone(),
        HidParam::VidPid { vid, pid } => format!("{vid:04x}:{pid:04x}"),
    }
}

/// The single enumeration call site. The crate `expect`s hidapi initialisation, so a
/// panic is caught and mapped to an error.
fn enumerate() -> Result<Vec<HidInfo>, CryptoError> {
    std::panic::catch_unwind(ctap_hid_fido2::get_fidokey_devices)
        .map_err(|_| backend_msg("fido2: hidapi initialisation failed"))
}

fn cfg() -> Cfg {
    Cfg::init()
        .with_enable_log(false)
        .with_keep_alive_msg_to_stderr(true)
}

/// Open exactly the named device (never `FidoKeyHidFactory::create`, which errors
/// whenever more than one FIDO device is attached).
fn open(info: &HidInfo) -> Result<FidoKeyHid, String> {
    let param = info.param.clone();
    let c = cfg();
    let opened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        FidoKeyHidFactory::create_by_params(&[param], &c)
    }))
    .map_err(|_| "hidapi initialisation failed".to_owned())?;
    let mut key = opened.map_err(|e| e.to_string())?;
    let _ = key.set_pin_uv_auth_protocol_two();
    Ok(key)
}

fn announce_touch() {
    eprintln!("Touch your authenticator…");
    tracing::info!(target: "y2q::devices", "awaiting authenticator touch");
}

fn map_touch_timeout(e: impl std::fmt::Display) -> CryptoError {
    let text = e.to_string();
    if text.contains("CTAP2_ERR_USER_ACTION_TIMEOUT") || text.contains("CTAP2_ERR_ACTION_TIMEOUT") {
        backend_msg("fido2: authenticator timed out waiting for touch")
    } else {
        backend(text)
    }
}

/// Silent GetAssertion (`up = false`, no PIN, no extensions): requests neither a PIN nor
/// a touch. Returns the error's `Display` text, because the CTAP status reaches the
/// caller only as that text.
pub(crate) fn presence_probe(
    key: &FidoKeyHid,
    rp_id: &str,
    credential_id: &[u8],
) -> Result<(), String> {
    let challenge: [u8; 32] = rand::random();
    let args = GetAssertionArgsBuilder::new(rp_id, &challenge)
        .credential_id(credential_id)
        .without_up()
        .without_pin_and_uv()
        .build();
    key.get_assertion_with_args(&args)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// One full (touching) assertion; returns the hmac-secret output and signCount.
fn assert_hmac(
    key: &FidoKeyHid,
    rp_id: &str,
    credential_id: &[u8],
    salt: [u8; 32],
    pin: Option<&str>,
) -> Result<(SecretBuf, u32), CryptoError> {
    let challenge: [u8; 32] = rand::random();
    let mut b = GetAssertionArgsBuilder::new(rp_id, &challenge)
        .credential_id(credential_id)
        .extensions(&[AssertExt::HmacSecret(Some(salt))]);
    b = match pin {
        Some(p) => b.pin(p),
        None => b.without_pin_and_uv(),
    };
    let args = b.build();
    announce_touch();
    let mut assertions = key
        .get_assertion_with_args(&args)
        .map_err(map_touch_timeout)?;
    let Some(assertion) = assertions.first_mut() else {
        return Err(backend_msg("fido2: authenticator returned no assertion"));
    };
    let sign_count = assertion.sign_count;
    let mut found: Option<SecretBuf> = None;
    for ext in assertion.extensions.iter_mut() {
        if let AssertExt::HmacSecret(Some(out)) = ext {
            if found.is_none() {
                found = Some(SecretBuf::from_slice(&out[..])?);
            }
            out.zeroize();
        }
    }
    drop(assertions);
    let secret = found.ok_or_else(|| {
        backend_msg(
            "fido2: authenticator returned no hmac-secret output; the key must have a PIN set and the credential must have been created with hmac-secret enabled — re-register this device with `y2q admin device add-fido2`",
        )
    })?;
    Ok((secret, sign_count))
}

fn decode_fixed32(b64: &str, what: &str) -> Result<[u8; 32], CryptoError> {
    let v = STANDARD
        .decode(b64)
        .map_err(|e| backend(format!("{what} base64: {e}")))?;
    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| backend(format!("{what} must be 32 bytes")))
}

/// Register a new authenticator: creates a non-discoverable hmac-secret credential and
/// proves, with one full assertion, that its output is reproducible.
pub fn enroll(
    label: String,
    uv_required: bool,
    pins: &dyn PinProvider,
    hid_path: Option<&str>,
) -> Result<NewDevice, CryptoError> {
    let devices = enumerate()?;
    if devices.is_empty() {
        return Err(backend_msg(
            "fido2: no FIDO2 authenticator found on USB HID; insert the security key and retry",
        ));
    }
    let info = match hid_path {
        Some(path) => devices
            .iter()
            .find(|d| matches!(&d.param, HidParam::Path(p) if p == path))
            .ok_or_else(|| backend_msg(format!("fido2: no FIDO2 authenticator at {path}")))?,
        None if devices.len() == 1 => &devices[0],
        None => {
            let candidates = devices.iter().map(path_of).collect::<Vec<_>>().join(", ");
            return Err(backend_msg(format!(
                "fido2: multiple authenticators attached; re-run with --hid-path <path> (candidates: {candidates})"
            )));
        }
    };
    let key = open(info).map_err(backend)?;

    if !key
        .enable_info_param(&InfoParam::ExtensionsHmacSecret)
        .map_err(backend)?
    {
        return Err(backend_msg(
            "fido2: authenticator does not support the hmac-secret extension; it cannot be registered as an away device",
        ));
    }
    let pin_set = key
        .enable_info_option(&InfoOption::ClientPin)
        .map_err(backend)?
        == Some(true);
    if uv_required && !pin_set {
        return Err(backend_msg(
            "fido2: authenticator has no PIN set; set a PIN on the key or register it with --no-uv",
        ));
    }
    let pin = if uv_required {
        Some(pins.pin(&label)?)
    } else {
        None
    };
    let pin_str = pin.as_ref().map(|p| p.as_str());

    let challenge: [u8; 32] = rand::random();
    let user =
        PublicKeyCredentialUserEntity::new(Some(USER_ID), Some(USER_NAME), Some(USER_DISPLAY_NAME));
    let mut b = MakeCredentialArgsBuilder::new(RP_ID, &challenge)
        .user_entity(&user)
        .extensions(&[CredentialExtension::HmacSecret(Some(true))]);
    b = match pin_str {
        Some(p) => b.pin(p),
        None => b.without_pin_and_uv(),
    };
    let args = b.build();
    announce_touch();
    let att = key
        .make_credential_with_args(&args)
        .map_err(map_touch_timeout)?;
    let credential_id = att.credential_descriptor.id.clone();
    drop(att);
    if credential_id.is_empty() {
        return Err(backend_msg(
            "fido2: authenticator returned an empty credential id",
        ));
    }
    if credential_id.len() > MAX_CREDENTIAL_ID_LEN {
        return Err(backend_msg(format!(
            "fido2: authenticator returned an implausible credential id ({} bytes)",
            credential_id.len()
        )));
    }

    let salt: [u8; 32] = rand::random();
    let (secret, sign_count) = assert_hmac(&key, RP_ID, &credential_id, salt, pin_str).map_err(|e| match e {
        CryptoError::DeviceBackend(m) if m.contains("returned no hmac-secret output") => backend_msg(
            "fido2: authenticator produced no hmac-secret output during enrollment; this token requires a PIN for hmac-secret — set a PIN and register without --no-uv",
        ),
        other => other,
    })?;
    if sign_count == 0 {
        return Err(backend_msg(
            "fido2: authenticator reports signCount = 0 (counter disabled); clone detection is impossible without a monotonic signature counter — this key cannot be registered as an away device",
        ));
    }

    Ok(NewDevice {
        label,
        kind: DeviceKind::Fido2,
        tpm2: None,
        fido2: Some(Fido2Params {
            rp_id: RP_ID.to_owned(),
            credential_id_b64: STANDARD.encode(&credential_id),
            hmac_salt_b64: STANDARD.encode(salt),
            uv_required,
        }),
        secret,
        sign_count,
    })
}

/// Obtain the 32-byte hmac-secret output and the assertion's signCount from whichever
/// attached authenticator holds the record's credential.
pub fn hmac_secret(
    params: &Fido2Params,
    label: &str,
    pins: &dyn PinProvider,
) -> Result<(SecretBuf, u32), CryptoError> {
    let credential_id = STANDARD
        .decode(&params.credential_id_b64)
        .map_err(|e| backend(format!("credential id base64: {e}")))?;
    let salt = decode_fixed32(&params.hmac_salt_b64, "hmac salt")?;

    let devices = enumerate()?;
    if devices.is_empty() {
        return Err(backend_msg(
            "fido2: no FIDO2 authenticator found on USB HID; insert the security key and retry",
        ));
    }

    let mut keys: Vec<Option<FidoKeyHid>> = Vec::with_capacity(devices.len());
    let mut rows: Vec<Attached> = Vec::with_capacity(devices.len());
    for info in &devices {
        let (key, answer) = match open(info) {
            Ok(key) => {
                let answer = presence_probe(&key, &params.rp_id, &credential_id);
                (Some(key), answer)
            }
            Err(e) => (None, Err(format!("open: {e}"))),
        };
        rows.push(Attached {
            path: path_of(info),
            class: classify_probe(&answer),
            probe_err: answer.err(),
            selected: false,
            assertion_err: None,
        });
        keys.push(key);
    }

    let classes: Vec<ProbeClass> = rows.iter().map(|r| r.class).collect();
    let selected = select_candidates(&classes);
    for &i in &selected {
        rows[i].selected = true;
    }

    for &i in &selected {
        let Some(key) = keys[i].as_ref() else {
            continue;
        };
        // PIN: only for a selected candidate of a uv_required record, once per device.
        let pin = if params.uv_required {
            Some(pins.pin(label)?)
        } else {
            None
        };
        match assert_hmac(
            key,
            &params.rp_id,
            &credential_id,
            salt,
            pin.as_ref().map(|p| p.as_str()),
        ) {
            Ok(found) => return Ok(found),
            Err(e) => {
                rows[i].assertion_err = Some(match e {
                    CryptoError::DeviceBackend(m) => m,
                    other => other.to_string(),
                });
            }
        }
    }

    Err(backend_msg(format!(
        "fido2: no attached authenticator holds the credential for away device '{label}' ({}): {}",
        device_id_hint(params),
        format_reasons(&rows)
    )))
}

/// The record's device id is not part of `Fido2Params`; the label identifies it and the
/// credential id prefix disambiguates in messages.
fn device_id_hint(params: &Fido2Params) -> String {
    let id: String = params.credential_id_b64.chars().take(8).collect();
    format!("credential {id}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_CRED: &str =
        "response_status err = 0x2E CTAP2_ERR_NO_CREDENTIALS  No valid credentials provided.";
    const PIN_REQ: &str = "response_status err = 0x36 CTAP2_ERR_PIN_REQUIRED  PIN is required for the selected operation.";

    #[test]
    fn classify() {
        assert_eq!(classify_probe(&Ok(())), ProbeClass::Present);
        assert_eq!(classify_probe(&Err(NO_CRED.into())), ProbeClass::Absent);
        assert_eq!(
            classify_probe(&Err(PIN_REQ.into())),
            ProbeClass::Indeterminate
        );
        assert_eq!(
            classify_probe(&Err("read err = timeout".into())),
            ProbeClass::Failed
        );
    }

    #[test]
    fn select() {
        use ProbeClass::*;
        assert_eq!(
            select_candidates(&[Indeterminate, Present, Absent, Present, Failed]),
            vec![1, 3]
        );
        assert_eq!(
            select_candidates(&[Absent, Indeterminate, Failed, Indeterminate]),
            vec![1, 3]
        );
        assert_eq!(select_candidates(&[Absent, Failed]), Vec::<usize>::new());
        assert_eq!(select_candidates(&[]), Vec::<usize>::new());
    }

    #[test]
    fn reasons() {
        let rows = vec![
            Attached {
                path: "/a".into(),
                class: ProbeClass::Absent,
                probe_err: Some(NO_CRED.into()),
                selected: false,
                assertion_err: None,
            },
            Attached {
                path: "/b".into(),
                class: ProbeClass::Failed,
                probe_err: Some("read err".into()),
                selected: false,
                assertion_err: None,
            },
            Attached {
                path: "/c".into(),
                class: ProbeClass::Present,
                probe_err: None,
                selected: true,
                assertion_err: Some("fido2: boom".into()),
            },
            Attached {
                path: "/d".into(),
                class: ProbeClass::Indeterminate,
                probe_err: Some(PIN_REQ.into()),
                selected: false,
                assertion_err: None,
            },
        ];
        assert_eq!(
            format_reasons(&rows),
            "/a: no matching credential; /b: read err; /c: fido2: boom; /d: not tried (another device holds the credential)"
        );
    }
}
