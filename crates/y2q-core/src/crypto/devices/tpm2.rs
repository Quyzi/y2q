//! TPM 2.0 home-device backend: a 32-byte device secret sealed to a PCR policy
//! under an owner-hierarchy ECC storage primary.
//!
//! The primary is only a storage parent. The sealed child's `TPM2B_PRIVATE` is
//! protected by symmetric keys the TPM derives from the parent seed, so no
//! classically-asymmetric ciphertext of the secret exists on disk.
//!
//! Security boundary: sealing defeats offline theft of the drive (a stolen disk
//! cannot be unsealed on another machine and a changed boot chain refuses). With
//! the default `--pcrs 7` it does NOT bound theft of the whole host (any
//! Secure-Boot-trusted OS booted on it satisfies PCR 7), and it never defeats a
//! root-capable attacker on the live host, who can run the same unseal.

use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::SessionType;
use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
use tss_esapi::handles::{KeyHandle, ObjectHandle, SessionHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::{
    Digest, EccPoint, KeyedHashScheme, PcrSelectionList, PcrSlot, Private, Public, PublicBuilder,
    PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData, SymmetricDefinition,
    SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::{Context, Error as TssError};

use super::types::{DeviceKind, NewDevice, Tpm2Params};
use crate::crypto::CryptoError;
use crate::secmem::SecretBuf;

const SECRET_LEN: usize = 32;

fn tss_err(e: TssError) -> CryptoError {
    if let TssError::Tss2Error(rc) = e
        && rc.kind() == Some(Tss2ResponseCodeKind::PolicyFail)
    {
        return CryptoError::TpmPcrMismatch;
    }
    CryptoError::Tpm(e.to_string())
}

fn open(tcti: &str) -> Result<Context, CryptoError> {
    let conf = TctiNameConf::from_str(tcti)
        .map_err(|e| CryptoError::TpmUnavailable(format!("tcti {tcti:?}: {e}")))?;
    Context::new(conf).map_err(|e| CryptoError::TpmUnavailable(format!("tcti {tcti:?}: {e}")))
}

/// Verify the TPM is reachable; opens a context and drops it.
pub fn probe(tcti: &str) -> Result<(), CryptoError> {
    open(tcti).map(drop)
}

fn pcr_slot(n: u8) -> Result<PcrSlot, CryptoError> {
    Ok(match n {
        0 => PcrSlot::Slot0,
        1 => PcrSlot::Slot1,
        2 => PcrSlot::Slot2,
        3 => PcrSlot::Slot3,
        4 => PcrSlot::Slot4,
        5 => PcrSlot::Slot5,
        6 => PcrSlot::Slot6,
        7 => PcrSlot::Slot7,
        8 => PcrSlot::Slot8,
        9 => PcrSlot::Slot9,
        10 => PcrSlot::Slot10,
        11 => PcrSlot::Slot11,
        12 => PcrSlot::Slot12,
        13 => PcrSlot::Slot13,
        14 => PcrSlot::Slot14,
        15 => PcrSlot::Slot15,
        16 => PcrSlot::Slot16,
        17 => PcrSlot::Slot17,
        18 => PcrSlot::Slot18,
        19 => PcrSlot::Slot19,
        20 => PcrSlot::Slot20,
        21 => PcrSlot::Slot21,
        22 => PcrSlot::Slot22,
        23 => PcrSlot::Slot23,
        _ => return Err(CryptoError::Tpm(format!("unknown pcr slot {n}"))),
    })
}

fn pcr_selection(bank: &str, slots: &[u8]) -> Result<PcrSelectionList, CryptoError> {
    if bank != "sha256" {
        return Err(CryptoError::Tpm(
            "unsupported pcr bank (only \"sha256\" is supported)".to_owned(),
        ));
    }
    if slots.is_empty() {
        return Err(CryptoError::Tpm(
            "tpm device wrap has an empty pcr selection".to_owned(),
        ));
    }
    let parsed = slots
        .iter()
        .map(|&n| pcr_slot(n))
        .collect::<Result<Vec<_>, _>>()?;
    PcrSelectionList::builder()
        .with_selection(HashingAlgorithm::Sha256, &parsed)
        .build()
        .map_err(tss_err)
}

fn b64_err(e: base64::DecodeError) -> CryptoError {
    CryptoError::Tpm(format!("tpm wrap base64: {e}"))
}

fn primary_template() -> Result<Public, CryptoError> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .build()
        .map_err(tss_err)?;
    let ecc = PublicEccParametersBuilder::new_restricted_decryption_key(
        SymmetricDefinitionObject::AES_128_CFB,
        EccCurve::NistP256,
    )
    .build()
    .map_err(tss_err)?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(ecc)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(tss_err)
}

/// Create the primary storage key, run `f` with it, then flush it on every path.
fn with_primary<T>(
    ctx: &mut Context,
    f: impl FnOnce(&mut Context, KeyHandle) -> Result<T, CryptoError>,
) -> Result<T, CryptoError> {
    let template = primary_template()?;
    let primary = ctx
        .execute_with_nullauth_session(|c| {
            c.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })
        .map_err(tss_err)?
        .key_handle;
    let res = f(ctx, primary);
    let flushed = ctx
        .flush_context(ObjectHandle::from(primary))
        .map_err(tss_err);
    match res {
        Ok(v) => flushed.map(|()| v),
        Err(e) => Err(e),
    }
}

fn seal_with(
    ctx: &mut Context,
    secret: &[u8],
    slots: &[u8],
    bank: &str,
) -> Result<Tpm2Params, CryptoError> {
    if secret.len() != SECRET_LEN {
        return Err(CryptoError::Tpm(
            "tpm seal expects a 32-byte device secret".to_owned(),
        ));
    }
    let sel = pcr_selection(bank, slots)?;
    let policy = trial_policy_digest(ctx, &sel)?;
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(false)
        .with_user_with_auth(false)
        .with_admin_with_policy(true)
        .with_no_da(true)
        .build()
        .map_err(tss_err)?;
    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_auth_policy(policy)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(tss_err)?;
    let sensitive = SensitiveData::try_from(secret.to_vec()).map_err(tss_err)?;
    let created = with_primary(ctx, |c, parent| {
        c.execute_with_nullauth_session(|c| {
            c.create(parent, public, None, Some(sensitive), None, None)
        })
        .map_err(tss_err)
    })?;
    let public_bytes = created.out_public.marshall().map_err(tss_err)?;
    Ok(Tpm2Params {
        private_b64: STANDARD.encode(created.out_private.value()),
        public_b64: STANDARD.encode(public_bytes),
        pcr_slots: slots.to_vec(),
        pcr_bank: bank.to_owned(),
    })
}

fn trial_policy_digest(ctx: &mut Context, sel: &PcrSelectionList) -> Result<Digest, CryptoError> {
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Trial,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(tss_err)?
        .ok_or_else(|| CryptoError::Tpm("tpm returned no policy session handle".to_owned()))?;
    let res = (|| {
        let ps = PolicySession::try_from(session).map_err(tss_err)?;
        ctx.policy_pcr(ps, Digest::default(), sel.clone())
            .map_err(tss_err)?;
        ctx.policy_get_digest(ps).map_err(tss_err)
    })();
    flush_session(ctx, session, res)
}

fn flush_session<T>(
    ctx: &mut Context,
    session: AuthSession,
    res: Result<T, CryptoError>,
) -> Result<T, CryptoError> {
    let flushed = ctx
        .flush_context(SessionHandle::from(session).into())
        .map_err(tss_err);
    match res {
        Ok(v) => flushed.map(|()| v),
        Err(e) => Err(e),
    }
}

/// Seal a fresh device secret to the current values of `pcr_slots` (SHA-256 bank).
pub fn enroll(label: String, tcti: &str, pcr_slots: &[u8]) -> Result<NewDevice, CryptoError> {
    // Validate the selection before touching hardware.
    pcr_selection("sha256", pcr_slots)?;
    let mut ctx = open(tcti)?;
    let secret = SecretBuf::random(SECRET_LEN)?;
    let params = {
        let read = secret.unlock()?;
        seal_with(&mut ctx, &read[..], pcr_slots, "sha256")?
    };
    Ok(NewDevice {
        label,
        kind: DeviceKind::Tpm2,
        tpm2: Some(params),
        fido2: None,
        secret,
        sign_count: 0,
    })
}

/// Unseal the device secret under the PCR policy recorded in `params`.
pub fn unseal(params: &Tpm2Params, tcti: &str) -> Result<SecretBuf, CryptoError> {
    let sel = pcr_selection(&params.pcr_bank, &params.pcr_slots)?;
    let private_raw = STANDARD.decode(&params.private_b64).map_err(b64_err)?;
    let public_raw = STANDARD.decode(&params.public_b64).map_err(b64_err)?;
    let private = Private::try_from(private_raw).map_err(tss_err)?;
    let public = Public::unmarshall(&public_raw).map_err(tss_err)?;
    let mut ctx = open(tcti)?;
    with_primary(&mut ctx, |c, parent| {
        let loaded = c
            .execute_with_nullauth_session(|c| c.load(parent, private, public))
            .map_err(tss_err)?;
        let res = unseal_loaded(c, loaded, &sel);
        let flushed = c.flush_context(ObjectHandle::from(loaded)).map_err(tss_err);
        match res {
            Ok(v) => flushed.map(|()| v),
            Err(e) => Err(e),
        }
    })
}

fn unseal_loaded(
    c: &mut Context,
    loaded: KeyHandle,
    sel: &PcrSelectionList,
) -> Result<SecretBuf, CryptoError> {
    let session = c
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(tss_err)?
        .ok_or_else(|| CryptoError::Tpm("tpm returned no policy session handle".to_owned()))?;
    let res = (|| {
        let ps = PolicySession::try_from(session).map_err(tss_err)?;
        c.policy_pcr(ps, Digest::default(), sel.clone())
            .map_err(tss_err)?;
        c.execute_with_session(Some(session), |c| c.unseal(ObjectHandle::from(loaded)))
            .map_err(tss_err)
    })();
    let data = flush_session(c, session, res)?;
    let bytes = data.value();
    if bytes.len() != SECRET_LEN {
        return Err(CryptoError::Tpm(format!(
            "unsealed {} bytes, expected 32",
            bytes.len()
        )));
    }
    Ok(SecretBuf::from_slice(bytes)?)
}

/// Seal a fresh secret under the current PCR values of the recorded slots.
pub fn reseal(params: &Tpm2Params, tcti: &str) -> Result<(Tpm2Params, SecretBuf), CryptoError> {
    pcr_selection(&params.pcr_bank, &params.pcr_slots)?;
    let mut ctx = open(tcti)?;
    let secret = SecretBuf::random(SECRET_LEN)?;
    let new_params = {
        let read = secret.unlock()?;
        seal_with(&mut ctx, &read[..], &params.pcr_slots, &params.pcr_bank)?
    };
    Ok((new_params, secret))
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::process::{Child, Command, Stdio};
    use std::sync::Mutex;

    use tss_esapi::handles::PcrHandle;
    use tss_esapi::structures::DigestValues;

    use super::*;

    static TPM_LOCK: Mutex<()> = Mutex::new(());

    struct Swtpm {
        child: Child,
        _dir: tempfile::TempDir,
        tcti: String,
    }

    impl Drop for Swtpm {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn free_port_pair() -> u16 {
        loop {
            let a = TcpListener::bind("127.0.0.1:0").unwrap();
            let p = a.local_addr().unwrap().port();
            if p < u16::MAX && TcpListener::bind(("127.0.0.1", p + 1)).is_ok() {
                return p;
            }
        }
    }

    fn start_swtpm() -> Option<Swtpm> {
        if Command::new("swtpm").arg("--version").output().is_err() {
            eprintln!("skipping tpm2 test: swtpm not installed");
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        let spawn = |port: u16| {
            Command::new("swtpm")
                .args(["socket", "--tpm2", "--tpmstate"])
                .arg(format!("dir={}", dir.path().display()))
                .arg("--server")
                .arg(format!("type=tcp,port={port}"))
                .arg("--ctrl")
                .arg(format!("type=tcp,port={}", port + 1))
                .args(["--flags", "startup-clear"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        };
        let port = free_port_pair();
        let mut child = spawn(port);
        std::thread::sleep(std::time::Duration::from_millis(300));
        if child.try_wait().unwrap().is_some() {
            let ok = Command::new("swtpm_setup")
                .args(["--tpm2", "--createek", "--tpmstate"])
                .arg(dir.path())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            assert!(ok, "swtpm_setup failed");
            child = spawn(port);
        }
        let tcti = format!("swtpm:host=127.0.0.1,port={port}");
        let sw = Swtpm {
            child,
            _dir: dir,
            tcti,
        };
        for _ in 0..50 {
            if probe(&sw.tcti).is_ok() {
                return Some(sw);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("swtpm did not become reachable");
    }

    fn bytes(s: &SecretBuf) -> Vec<u8> {
        s.unlock().unwrap()[..].to_vec()
    }

    #[test]
    fn tpm2_roundtrip_reseal_and_pcr_policy() {
        let _g = TPM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(sw) = start_swtpm() else { return };

        let dev = enroll("t".into(), &sw.tcti, &[7]).unwrap();
        assert_eq!(dev.kind, DeviceKind::Tpm2);
        assert!(dev.fido2.is_none());
        assert_eq!(dev.sign_count, 0);
        let params = dev.tpm2.clone().unwrap();
        let s1 = bytes(&dev.secret);
        assert_eq!(s1.len(), 32);
        assert_eq!(bytes(&unseal(&params, &sw.tcti).unwrap()), s1);

        let (np, ns) = reseal(&params, &sw.tcti).unwrap();
        let s2 = bytes(&ns);
        assert_ne!(s1, s2);
        assert_eq!(np.pcr_slots, params.pcr_slots);
        assert_eq!(bytes(&unseal(&np, &sw.tcti).unwrap()), s2);

        // Move PCR 7: both old and new objects must now refuse.
        let mut ctx = open(&sw.tcti).unwrap();
        let mut dv = DigestValues::new();
        dv.set(
            HashingAlgorithm::Sha256,
            Digest::try_from(vec![0xAB; 32]).unwrap(),
        );
        ctx.execute_with_nullauth_session(|c| c.pcr_extend(PcrHandle::Pcr7, dv))
            .unwrap();
        drop(ctx);
        assert!(matches!(
            unseal(&params, &sw.tcti),
            Err(CryptoError::TpmPcrMismatch)
        ));
        assert!(matches!(
            unseal(&np, &sw.tcti),
            Err(CryptoError::TpmPcrMismatch)
        ));
    }

    #[test]
    fn tpm2_selection_validation() {
        let _g = TPM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let Some(sw) = start_swtpm() else { return };
        assert!(matches!(
            enroll("t".into(), &sw.tcti, &[]),
            Err(CryptoError::Tpm(_))
        ));
        assert!(matches!(
            enroll("t".into(), &sw.tcti, &[24]),
            Err(CryptoError::Tpm(m)) if m == "unknown pcr slot 24"
        ));
        let dev = enroll("t".into(), &sw.tcti, &[7]).unwrap();
        let mut p = dev.tpm2.unwrap();
        p.pcr_bank = "sha1".into();
        assert!(matches!(unseal(&p, &sw.tcti), Err(CryptoError::Tpm(_))));
        assert!(matches!(reseal(&p, &sw.tcti), Err(CryptoError::Tpm(_))));
        p.pcr_bank = "sha256".into();
        p.pcr_slots = vec![];
        assert!(matches!(unseal(&p, &sw.tcti), Err(CryptoError::Tpm(_))));
    }

    #[test]
    fn tpm2_unreachable_tcti() {
        let _g = TPM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let port = free_port_pair();
        let tcti = format!("swtpm:host=127.0.0.1,port={port}");
        assert!(matches!(probe(&tcti), Err(CryptoError::TpmUnavailable(_))));
        assert!(matches!(
            enroll("t".into(), &tcti, &[7]),
            Err(CryptoError::TpmUnavailable(_))
        ));
    }
}
