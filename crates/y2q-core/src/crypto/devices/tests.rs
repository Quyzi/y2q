//! Hardware-free tests for the registry, grants, authority and emergency paths.
//!
//! Time and authenticators are injected through `TimeSource` / secret bytes;
//! nothing here touches a TPM or an attached FIDO2 token. `devices::unlock` is
//! exercised only through its emergency-code success path, which returns before
//! any hardware is contacted.

use std::fs;
use std::path::Path;
use std::sync::Mutex;

use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::registry::*;
use super::types::*;
use super::{EMERGENCY_KEY_ENV_VAR, devices_path, emergency};
use crate::crypto::CryptoError;
use crate::secmem::SecretBuf;

static ENV_LOCK: Mutex<()> = Mutex::new(());

const T0: u64 = 1_000_000;
const HOME_SECRET: [u8; 32] = [0x11; 32];
const AWAY_SECRET: [u8; 32] = [0xA1; 32];

struct FixedTime(Option<u64>);
impl TimeSource for FixedTime {
    fn attested_now(&self) -> Result<u64, CryptoError> {
        self.0
            .ok_or_else(|| CryptoError::AttestedTimeUnavailable("test".to_owned()))
    }
}

struct PanicTime;
impl TimeSource for PanicTime {
    fn attested_now(&self) -> Result<u64, CryptoError> {
        panic!("attested time must not be requested");
    }
}

fn policy() -> DevicePolicy {
    DevicePolicy {
        tpm_tcti: "device:/nonexistent-tpm".to_owned(),
        roughtime: RoughtimeConfig::default(),
    }
}

fn tpm_dev(label: &str, secret: &[u8; 32]) -> NewDevice {
    NewDevice {
        label: label.to_owned(),
        kind: DeviceKind::Tpm2,
        tpm2: Some(Tpm2Params {
            private_b64: "AA==".to_owned(),
            public_b64: "AA==".to_owned(),
            pcr_slots: vec![7],
            pcr_bank: "sha256".to_owned(),
        }),
        fido2: None,
        secret: SecretBuf::from_slice(secret).unwrap(),
        sign_count: 0,
    }
}

fn fido_dev(label: &str, uv: bool, secret: &[u8; 32], sign_count: u32) -> NewDevice {
    NewDevice {
        label: label.to_owned(),
        kind: DeviceKind::Fido2,
        tpm2: None,
        fido2: Some(Fido2Params {
            rp_id: "y2q.local".to_owned(),
            credential_id_b64: STANDARD.encode([7u8; 16]),
            hmac_salt_b64: STANDARD.encode([8u8; 32]),
            uv_required: uv,
        }),
        secret: SecretBuf::from_slice(secret).unwrap(),
        sign_count,
    }
}

fn home() -> Authority {
    Authority::Home {
        id: "h".into(),
        label: "home".into(),
    }
}
fn away() -> Authority {
    Authority::Away {
        id: "a".into(),
        label: "away".into(),
        not_after_unix: None,
    }
}
fn emerg() -> Authority {
    Authority::Emergency { index: 0 }
}

fn parse_codes(sheet: &[u8]) -> Vec<String> {
    String::from_utf8(sheet.to_vec())
        .unwrap()
        .lines()
        .filter_map(|l| {
            let (n, code) = l.split_once(": ")?;
            n.trim().parse::<u8>().ok()?;
            Some(code.to_owned())
        })
        .collect()
}

fn rmk_of(reg: &DeviceRegistryFile, idx: usize, secret: &[u8; 32], dir: &Path) -> [u8; 32] {
    let d = &reg.devices[idx];
    let kek = derive_device_kek(secret, &d.id_bytes).unwrap();
    let uv = d.fido2.as_ref().is_some_and(|f| f.uv_required);
    *unwrap_secret(
        &kek,
        d.wrap.as_ref().unwrap(),
        &device_wrap_aad(&d.id_bytes, d.kind, uv, &reg.esc),
        &devices_path(dir),
    )
    .unwrap()
}

struct Fx {
    dir: tempfile::TempDir,
    reg: DeviceRegistryFile,
    rmk: [u8; 32],
    nk: [u8; 32],
    codes: Vec<String>,
}

impl Fx {
    fn path(&self) -> &Path {
        self.dir.path()
    }
    fn state_key(&self) -> [u8; 32] {
        *derive_state_key(&self.rmk).unwrap()
    }
    fn persist(&mut self) {
        let sk = self.state_key();
        persist(self.dir.path(), &mut self.reg, &sk).unwrap();
    }
    fn bytes(&self) -> Vec<u8> {
        fs::read(devices_path(self.path())).unwrap()
    }
    fn reload(&mut self) {
        self.reg = load(self.path()).unwrap();
    }
    /// Enroll an away device under home authority (mints nothing, row 8).
    fn add_fido(&mut self, label: &str, uv: bool, sign: u32) -> usize {
        let t = FixedTime(Some(T0));
        let p = policy();
        let ctx = Ctx {
            time: &t,
            now_host: 5,
            policy: &p,
        };
        enroll_device(
            self.dir.path(),
            &mut self.reg,
            fido_dev(label, uv, &AWAY_SECRET, sign),
            &self.rmk,
            &home(),
            &ctx,
        )
        .unwrap();
        self.persist();
        self.reg.devices.len() - 1
    }
}

fn fixture_with(first: NewDevice, secs: u32, permanent_away: bool, secret: &[u8; 32]) -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let mut sheet = Vec::new();
    let out = emergency::init_registry(
        dir.path(),
        first,
        secs,
        permanent_away,
        100,
        None,
        &mut sheet,
    )
    .unwrap();
    let rmk = rmk_of(&out.registry, 0, secret, dir.path());
    Fx {
        codes: parse_codes(&sheet),
        nk: *out.node_key,
        reg: out.registry,
        rmk,
        dir,
    }
}

fn home_fx() -> Fx {
    fixture_with(
        tpm_dev("home", &HOME_SECRET),
        DEFAULT_AWAY_GRANT_SECONDS,
        false,
        &HOME_SECRET,
    )
}

fn zero_home_fx() -> Fx {
    fixture_with(
        fido_dev("away", false, &AWAY_SECRET, 5),
        DEFAULT_AWAY_GRANT_SECONDS,
        true,
        &AWAY_SECRET,
    )
}

fn edit_json(dir: &Path, f: impl FnOnce(&mut serde_json::Value)) {
    let p = devices_path(dir);
    let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
    f(&mut v);
    fs::write(p, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
}

fn set_emergency_code(code: &str) {
    // SAFETY: serialised by ENV_LOCK in every test that touches this variable.
    unsafe { std::env::set_var(EMERGENCY_KEY_ENV_VAR, code) };
}

// ---------------------------------------------------------------------------
// AAD / wrap primitives
// ---------------------------------------------------------------------------

#[test]
fn aad_lengths_and_field_sensitivity() {
    let id = [1u8; 16];
    let esc = [2u8; 32];
    assert_eq!(
        device_wrap_aad(&id, DeviceKind::Tpm2, false, &esc).len(),
        69
    );
    assert_eq!(grant_aad(&id, true, 5, 60, &esc).len(), 79);
    assert_eq!(emergency_wrap_aad(3, &esc).len(), 55);
    assert_eq!(nk_wrap_aad(&esc, 60).len(), 51);
    assert_eq!(kek_cache_aad(&id, &esc).len(), 65);

    let base = device_wrap_aad(&id, DeviceKind::Fido2, true, &esc);
    assert_ne!(
        base,
        device_wrap_aad(&[9; 16], DeviceKind::Fido2, true, &esc)
    );
    assert_ne!(base, device_wrap_aad(&id, DeviceKind::Tpm2, true, &esc));
    assert_ne!(base, device_wrap_aad(&id, DeviceKind::Fido2, false, &esc));
    assert_ne!(
        base,
        device_wrap_aad(&id, DeviceKind::Fido2, true, &[3; 32])
    );

    let g = grant_aad(&id, true, 5, 60, &esc);
    assert_ne!(g, grant_aad(&[9; 16], true, 5, 60, &esc));
    assert_ne!(g, grant_aad(&id, false, 5, 60, &esc));
    assert_ne!(g, grant_aad(&id, true, 6, 60, &esc));
    assert_ne!(g, grant_aad(&id, true, 5, 61, &esc));
    assert_ne!(g, grant_aad(&id, true, 5, 60, &[3; 32]));
    assert_ne!(nk_wrap_aad(&esc, 60), nk_wrap_aad(&[3; 32], 60));
    assert_ne!(nk_wrap_aad(&esc, 60), nk_wrap_aad(&esc, 61));
}

#[test]
fn wrap_round_trips_and_fails_closed() {
    let kek = [5u8; 32];
    let secret = [6u8; 32];
    let p = Path::new("devices.json");
    let w = wrap_secret(&kek, &secret, b"aad").unwrap();
    assert_eq!(*unwrap_secret(&kek, &w, b"aad", p).unwrap(), secret);
    assert!(matches!(
        unwrap_secret(&kek, &w, b"aae", p),
        Err(CryptoError::DeviceUnwrapFailed)
    ));
    assert!(matches!(
        unwrap_secret(&[0u8; 32], &w, b"aad", p),
        Err(CryptoError::DeviceUnwrapFailed)
    ));
    let mut short = w.clone();
    short.ct_b64.truncate(short.ct_b64.len() - 8);
    assert!(matches!(
        unwrap_secret(&kek, &short, b"aad", p),
        Err(CryptoError::DeviceRegistryCorrupt { .. })
    ));
}

// ---------------------------------------------------------------------------
// init_registry
// ---------------------------------------------------------------------------

#[test]
fn init_prints_twelve_lines_and_commits_to_the_printed_set() {
    let dir = tempfile::tempdir().unwrap();
    let mut sheet = Vec::new();
    let out = emergency::init_registry(
        dir.path(),
        tpm_dev("home", &HOME_SECRET),
        DEFAULT_AWAY_GRANT_SECONDS,
        false,
        100,
        None,
        &mut sheet,
    )
    .unwrap();
    let text = String::from_utf8(sheet.clone()).unwrap();
    assert_eq!(text.lines().count(), 12);
    let codes = parse_codes(&sheet);
    assert_eq!(codes.len(), 10);
    for c in &codes {
        assert_eq!(c.len(), 44);
        assert_eq!(STANDARD.decode(c).unwrap().len(), 32);
    }
    assert_eq!(out.registry.emergency_slots.len(), 10);

    // ESC recomputed from the printed codes equals the stored commitment.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"y2q/v1/emergency-set");
    for c in &codes {
        h.update(Sha256::digest(STANDARD.decode(c).unwrap()));
    }
    let esc: [u8; 32] = h.finalize().into();
    assert_eq!(STANDARD.encode(esc), out.registry.esc_b64);

    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(devices_path(dir.path())).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert!(!dir.path().join("devices.json.tmp").exists());
}

#[test]
fn init_refuses_existing_registry_without_touching_it() {
    let fx = home_fx();
    let before = fx.bytes();
    let mut sink = Vec::new();
    let err = emergency::init_registry(
        fx.dir.path(),
        tpm_dev("again", &HOME_SECRET),
        DEFAULT_AWAY_GRANT_SECONDS,
        false,
        1,
        None,
        &mut sink,
    )
    .err()
    .unwrap();
    assert!(matches!(err, CryptoError::DeviceRegistryExists(_)));
    assert!(sink.is_empty(), "nothing may be printed for a refused init");
    assert_eq!(before, fx.bytes());
}

#[test]
fn init_requires_permanent_away_exactly_for_a_fido2_first_device() {
    let dir = tempfile::tempdir().unwrap();
    let mut sink = Vec::new();
    let e1 = emergency::init_registry(
        dir.path(),
        fido_dev("a", false, &AWAY_SECRET, 5),
        DEFAULT_AWAY_GRANT_SECONDS,
        false,
        1,
        None,
        &mut sink,
    )
    .err()
    .unwrap();
    assert!(matches!(
        e1,
        CryptoError::DevicePermanentAwayMismatch {
            kind: DeviceKind::Fido2
        }
    ));
    let e2 = emergency::init_registry(
        dir.path(),
        tpm_dev("h", &HOME_SECRET),
        DEFAULT_AWAY_GRANT_SECONDS,
        true,
        1,
        None,
        &mut sink,
    )
    .err()
    .unwrap();
    assert!(matches!(
        e2,
        CryptoError::DevicePermanentAwayMismatch {
            kind: DeviceKind::Tpm2
        }
    ));
    assert!(!devices_path(dir.path()).exists());
    assert!(sink.is_empty());
}

#[test]
fn grant_period_bounds_are_enforced_by_init_and_set_grant_period() {
    for bad in [59u32, 2_592_001] {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = Vec::new();
        let err = emergency::init_registry(
            dir.path(),
            tpm_dev("h", &HOME_SECRET),
            bad,
            false,
            1,
            None,
            &mut sink,
        )
        .err()
        .unwrap();
        assert!(matches!(err, CryptoError::DeviceGrantPeriodInvalid { seconds } if seconds == bad));
    }
    for ok in [60u32, 2_592_000] {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = Vec::new();
        emergency::init_registry(
            dir.path(),
            tpm_dev("h", &HOME_SECRET),
            ok,
            false,
            1,
            None,
            &mut sink,
        )
        .unwrap();
    }
    let mut fx = home_fx();
    let t = FixedTime(Some(T0));
    let p = policy();
    let ctx = Ctx {
        time: &t,
        now_host: 1,
        policy: &p,
    };
    for bad in [59u32, 2_592_001] {
        let err = set_grant_period(
            fx.dir.path(),
            &mut fx.reg,
            bad,
            &fx.nk,
            &fx.rmk,
            &home(),
            &ctx,
        )
        .unwrap_err();
        assert!(matches!(err, CryptoError::DeviceGrantPeriodInvalid { seconds } if seconds == bad));
    }
    for ok in [60u32, 2_592_000] {
        set_grant_period(
            fx.dir.path(),
            &mut fx.reg,
            ok,
            &fx.nk,
            &fx.rmk,
            &home(),
            &ctx,
        )
        .unwrap();
    }
}

struct FailingWriter;
impl std::io::Write for FailingWriter {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("sink closed"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::other("sink closed"))
    }
}

#[test]
fn init_is_atomic_and_prints_before_writing() {
    // Unprintable set → nothing on disk.
    let dir = tempfile::tempdir().unwrap();
    let err = emergency::init_registry(
        dir.path(),
        tpm_dev("h", &HOME_SECRET),
        DEFAULT_AWAY_GRANT_SECONDS,
        false,
        1,
        None,
        &mut FailingWriter,
    )
    .err()
    .unwrap();
    assert!(matches!(err, CryptoError::DeviceRegistryIo(_)));
    assert!(!devices_path(dir.path()).exists());

    // A crash-leftover tmp file is removed, and init succeeds.
    fs::write(dir.path().join("devices.json.tmp"), b"junk").unwrap();
    let mut sink = Vec::new();
    emergency::init_registry(
        dir.path(),
        tpm_dev("h", &HOME_SECRET),
        DEFAULT_AWAY_GRANT_SECONDS,
        false,
        1,
        None,
        &mut sink,
    )
    .unwrap();
    assert!(load(dir.path()).is_ok());
    assert!(!dir.path().join("devices.json.tmp").exists());

    // A failure before the rename leaves no registry.
    let dir2 = tempfile::tempdir().unwrap();
    fs::create_dir(dir2.path().join("devices.json.tmp")).unwrap();
    let mut sink = Vec::new();
    assert!(
        emergency::init_registry(
            dir2.path(),
            tpm_dev("h", &HOME_SECRET),
            DEFAULT_AWAY_GRANT_SECONDS,
            false,
            1,
            None,
            &mut sink,
        )
        .is_err()
    );
    assert!(!devices_path(dir2.path()).exists());
}

#[test]
fn separate_inits_yield_different_node_keys() {
    let a = home_fx();
    let b = home_fx();
    assert_ne!(a.nk, b.nk);
    assert_ne!(a.reg.esc_b64, b.reg.esc_b64);
}

#[test]
fn adopt_wraps_the_supplied_key_and_rewrite_changes_only_nk_wrap() {
    let dir = tempfile::tempdir().unwrap();
    let nk = [0x42u8; 32];
    let mut sink = Vec::new();
    let out = emergency::init_registry(
        dir.path(),
        tpm_dev("h", &HOME_SECRET),
        DEFAULT_AWAY_GRANT_SECONDS,
        false,
        1,
        Some(&nk),
        &mut sink,
    )
    .unwrap();
    assert_eq!(*out.node_key, nk);
    let mut reg = out.registry;
    let rmk = rmk_of(&reg, 0, &HOME_SECRET, dir.path());
    assert_eq!(*open_nk_pub(&reg, &rmk, dir.path()).unwrap(), nk);

    let before = reg.clone();
    let new_nk = [0x43u8; 32];
    emergency::rewrite_nk_wrap(dir.path(), &mut reg, &rmk, &new_nk).unwrap();
    let reg = load(dir.path()).unwrap();
    assert_eq!(*open_nk_pub(&reg, &rmk, dir.path()).unwrap(), new_nk);
    assert_eq!(
        serde_json::to_string(&before.devices).unwrap(),
        serde_json::to_string(&reg.devices).unwrap()
    );
    assert_eq!(
        serde_json::to_string(&before.emergency_slots).unwrap(),
        serde_json::to_string(&reg.emergency_slots).unwrap()
    );
    assert_ne!(before.nk_wrap.ct_b64, reg.nk_wrap.ct_b64);
}

#[test]
fn adopt_with_a_mismatched_keystore_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    crate::crypto::keystore::first_run(
        dir.path(),
        "root",
        crate::crypto::Argon2Params::with_random_salt(8 * 1024, 1, 1),
        &[1u8; 32],
    )
    .unwrap();
    let mut sink = Vec::new();
    let err = emergency::init_registry(
        dir.path(),
        tpm_dev("h", &HOME_SECRET),
        DEFAULT_AWAY_GRANT_SECONDS,
        false,
        1,
        Some(&[2u8; 32]),
        &mut sink,
    )
    .err()
    .unwrap();
    assert!(matches!(err, CryptoError::NodeKeyMismatch));
    assert!(!devices_path(dir.path()).exists());
    assert!(sink.is_empty());
}

// ---------------------------------------------------------------------------
// Emergency codes
// ---------------------------------------------------------------------------

#[test]
fn each_code_unlocks_once_then_is_rejected_then_exhaustion() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fx = home_fx();
    let dir = fx.dir.path().to_path_buf();
    for (i, code) in fx.codes.iter().enumerate() {
        let mut reg = load(&dir).unwrap();
        set_emergency_code(code);
        let u = emergency::emergency_unlock(&dir, &mut reg, 777)
            .unwrap()
            .unwrap();
        assert_eq!(*u.nk, fx.nk, "code {i} must yield the same NK");
        assert_eq!(*u.rmk, fx.rmk);
        assert_eq!(usize::from(u.slot), i);
        assert!(
            std::env::var_os(EMERGENCY_KEY_ENV_VAR).is_none(),
            "intake must scrub the variable"
        );
        // Burn survives a reload.
        let reloaded = load(&dir).unwrap();
        assert!(reloaded.emergency_slots[i].wrap.is_none());
        assert_eq!(reloaded.emergency_slots[i].burned_at_unix, Some(777));
        // Replay is rejected.
        set_emergency_code(code);
        let mut again = load(&dir).unwrap();
        let before = fs::read(devices_path(&dir)).unwrap();
        let err = emergency::emergency_unlock(&dir, &mut again, 1)
            .err()
            .unwrap();
        if i == 9 {
            assert!(matches!(err, CryptoError::EmergencyCodesExhausted));
        } else {
            assert!(matches!(err, CryptoError::EmergencyCodeRejected));
        }
        assert_eq!(before, fs::read(devices_path(&dir)).unwrap());
    }
}

#[test]
fn emergency_input_validation_and_foreign_codes() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fx = home_fx();
    let mut reg = load(fx.dir.path()).unwrap();
    let before = fx.bytes();

    // Absent variable → fall through.
    assert!(
        emergency::emergency_unlock(fx.dir.path(), &mut reg, 1)
            .unwrap()
            .is_none()
    );

    set_emergency_code(&STANDARD.encode([3u8; 31]));
    assert!(matches!(
        emergency::emergency_unlock(fx.dir.path(), &mut reg, 1),
        Err(CryptoError::EmergencyCodeMalformed(_))
    ));
    set_emergency_code("not base64 !!");
    assert!(matches!(
        emergency::emergency_unlock(fx.dir.path(), &mut reg, 1),
        Err(CryptoError::EmergencyCodeMalformed(_))
    ));
    // Well-formed but from nowhere.
    set_emergency_code(&STANDARD.encode([4u8; 32]));
    assert!(matches!(
        emergency::emergency_unlock(fx.dir.path(), &mut reg, 1),
        Err(CryptoError::EmergencyCodeRejected)
    ));
    assert_eq!(before, fx.bytes());
}

#[test]
fn emergency_unlock_through_orchestrator_needs_no_hardware() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fx = home_fx();
    set_emergency_code(&fx.codes[2]);
    let out = super::unlock(fx.dir.path(), &policy(), &NoPins, &PanicTime, 55).unwrap();
    assert_eq!(*out.node_key, fx.nk);
    assert!(matches!(out.authority, Authority::Emergency { index: 2 }));
    assert_eq!(out.emergency_slots_unused, 9);
    assert_eq!(*out.registry_master_key, fx.rmk);
}

struct NoPins;
impl PinProvider for NoPins {
    fn pin(&self, _: &str) -> Result<zeroize::Zeroizing<String>, CryptoError> {
        panic!("no PIN may be requested");
    }
}

// ---------------------------------------------------------------------------
// load()
// ---------------------------------------------------------------------------

#[test]
fn load_rejects_structurally_invalid_registries() {
    type Edit = Box<dyn Fn(&mut serde_json::Value)>;
    type Case = (&'static str, Edit, fn(&CryptoError) -> bool);
    let cases: Vec<Case> = vec![
        (
            "format version",
            Box::new(|v| v["format_version"] = 2.into()),
            |e| matches!(e, CryptoError::DeviceRegistryVersion { found: 2, .. }),
        ),
        (
            "nine slots",
            Box::new(|v| {
                v["emergency_slots"].as_array_mut().unwrap().pop();
            }),
            |e| matches!(e, CryptoError::DeviceRegistryCorrupt { .. }),
        ),
        (
            "duplicate slot index",
            Box::new(|v| v["emergency_slots"][1]["index"] = 0.into()),
            |e| matches!(e, CryptoError::DeviceRegistryCorrupt { .. }),
        ),
        (
            "slot with both wrap and burned",
            Box::new(|v| v["emergency_slots"][0]["burned_at_unix"] = 5.into()),
            |e| matches!(e, CryptoError::DeviceRegistryCorrupt { .. }),
        ),
        (
            "slot with neither",
            Box::new(|v| {
                v["emergency_slots"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("wrap");
            }),
            |e| matches!(e, CryptoError::DeviceRegistryCorrupt { .. }),
        ),
        (
            "uppercase id",
            Box::new(|v| {
                let id = v["devices"][0]["id"].as_str().unwrap().to_uppercase();
                v["devices"][0]["id"] = id.into();
            }),
            |e| matches!(e, CryptoError::DeviceRegistryCorrupt { .. }),
        ),
        (
            "short state mac",
            Box::new(|v| v["state_mac_b64"] = STANDARD.encode([1u8; 31]).into()),
            |e| matches!(e, CryptoError::DeviceRegistryCorrupt { .. }),
        ),
        (
            "grant period below minimum",
            Box::new(|v| v["away_grant_seconds"] = 59.into()),
            |e| matches!(e, CryptoError::DeviceGrantPeriodInvalid { seconds: 59 }),
        ),
        (
            "permanent_away with a home device",
            Box::new(|v| v["permanent_away"] = true.into()),
            |e| matches!(e, CryptoError::DeviceRegistryCorrupt { .. }),
        ),
        (
            "tpm record with a grant",
            Box::new(|v| {
                let w = v["devices"][0]["wrap"].clone();
                v["devices"][0]["grant"] =
                    serde_json::json!({"not_after_unix": 1, "issued_at_unix": 0, "wrap": w});
            }),
            |e| matches!(e, CryptoError::DeviceRegistryCorrupt { .. }),
        ),
    ];
    for (name, edit, expect) in cases {
        let fx = home_fx();
        edit_json(fx.dir.path(), |v| edit(v));
        let before = fx.bytes();
        let err = load(fx.dir.path()).unwrap_err();
        assert!(expect(&err), "case '{name}' produced {err:?}");
        assert_eq!(before, fx.bytes(), "load must never write ({name})");
    }
}

#[test]
fn load_rejects_away_record_inconsistencies() {
    type Edit = Box<dyn Fn(&mut serde_json::Value)>;
    let cases: Vec<(&str, Edit)> = vec![
        (
            "labels equal ignoring case",
            Box::new(|v| v["devices"][1]["label"] = "HOME".into()),
        ),
        (
            "fido2 wrap in non-permanent registry",
            Box::new(|v| v["devices"][1]["wrap"] = v["devices"][0]["wrap"].clone()),
        ),
        (
            "fido2 missing kek_wrap",
            Box::new(|v| {
                v["devices"][1].as_object_mut().unwrap().remove("kek_wrap");
            }),
        ),
        (
            "fido2 missing sign_count_last",
            Box::new(|v| {
                v["devices"][1]
                    .as_object_mut()
                    .unwrap()
                    .remove("sign_count_last");
            }),
        ),
    ];
    for (name, edit) in cases {
        let mut fx = home_fx();
        fx.add_fido("away", false, 5);
        edit_json(fx.dir.path(), |v| edit(v));
        let before = fx.bytes();
        let err = load(fx.dir.path()).unwrap_err();
        assert!(
            matches!(err, CryptoError::DeviceRegistryCorrupt { .. }),
            "case '{name}' produced {err:?}"
        );
        assert_eq!(before, fx.bytes());
    }
    // Zero-home: permanent_away false while no home device exists.
    let fx = zero_home_fx();
    edit_json(fx.dir.path(), |v| v["permanent_away"] = false.into());
    assert!(matches!(
        load(fx.dir.path()),
        Err(CryptoError::DeviceRegistryCorrupt { .. })
    ));
    // Missing / directory registry.
    let empty = tempfile::tempdir().unwrap();
    assert!(matches!(
        load(empty.path()),
        Err(CryptoError::DeviceRegistryMissing(_))
    ));
    fs::create_dir(devices_path(empty.path())).unwrap();
    assert!(matches!(
        load(empty.path()),
        Err(CryptoError::DeviceRegistryIo(_))
    ));
}

// ---------------------------------------------------------------------------
// State MAC and AAD-bound edits
// ---------------------------------------------------------------------------

fn home_unlock(fx: &mut Fx, now: Option<u64>) -> Result<Unlock, CryptoError> {
    unlock_with_home(
        fx.dir.path(),
        &mut fx.reg,
        0,
        &HOME_SECRET,
        &FixedTime(now),
        &policy(),
    )
}

fn away_unlock(
    fx: &mut Fx,
    idx: usize,
    sign: u32,
    now: Option<u64>,
) -> Result<Unlock, CryptoError> {
    unlock_with_away(
        fx.dir.path(),
        &mut fx.reg,
        idx,
        &AWAY_SECRET,
        sign,
        &FixedTime(now),
        &policy(),
    )
}

#[test]
fn mac_only_edits_are_detected_and_nothing_is_written() {
    type Edit = Box<dyn Fn(&mut serde_json::Value)>;
    let cases: Vec<(&str, Edit)> = vec![
        (
            "label",
            Box::new(|v| v["devices"][0]["label"] = "renamed".into()),
        ),
        (
            "added_at_unix",
            Box::new(|v| v["devices"][0]["added_at_unix"] = 9.into()),
        ),
        (
            "sign_count_last",
            Box::new(|v| v["devices"][1]["sign_count_last"] = 1.into()),
        ),
        (
            "burned slot flip",
            Box::new(|v| {
                let s = &mut v["emergency_slots"][4];
                s.as_object_mut().unwrap().remove("wrap");
                s["burned_at_unix"] = 3.into();
            }),
        ),
        (
            "tpm pcr_slots",
            Box::new(|v| v["devices"][0]["tpm2"]["pcr_slots"] = serde_json::json!([7, 4])),
        ),
        (
            "spliced nk_wrap",
            Box::new(|v| {
                let ct = v["nk_wrap"]["ct_b64"].as_str().unwrap().to_owned();
                let mut raw = STANDARD.decode(ct).unwrap();
                raw[0] ^= 1;
                v["nk_wrap"]["ct_b64"] = STANDARD.encode(raw).into();
            }),
        ),
    ];
    for (name, edit) in cases {
        let mut fx = home_fx();
        fx.add_fido("away", false, 5);
        fx.reg.devices[0].grant = None;
        edit_json(fx.dir.path(), |v| edit(v));
        fx.reload();
        let before = fx.bytes();
        let err = home_unlock(&mut fx, Some(T0)).err().unwrap_or_else(|| {
            panic!("case '{name}' must not unlock");
        });
        assert!(
            matches!(err, CryptoError::DeviceStateTampered),
            "case '{name}' produced {err:?}"
        );
        assert_eq!(before, fx.bytes(), "{name}: nothing may be written");
    }
}

#[test]
fn aad_bound_edits_fail_at_the_unwrap() {
    // Away side: uv flag, grant deadline, grant policy.
    let mut base = home_fx();
    base.add_fido("away", true, 5);
    home_unlock(&mut base, Some(T0)).unwrap();
    assert!(base.reg.devices[1].grant.is_some());

    type Edit = Box<dyn Fn(&mut serde_json::Value)>;
    let cases: Vec<(&str, Edit)> = vec![
        (
            "uv_required",
            Box::new(|v| v["devices"][1]["fido2"]["uv_required"] = false.into()),
        ),
        (
            "grant deadline",
            Box::new(|v| v["devices"][1]["grant"]["not_after_unix"] = 99.into()),
        ),
        (
            "away_grant_seconds",
            Box::new(|v| v["away_grant_seconds"] = 61.into()),
        ),
    ];
    for (name, edit) in cases {
        let mut fx = Fx {
            dir: tempfile::tempdir().unwrap(),
            reg: base.reg.clone(),
            rmk: base.rmk,
            nk: base.nk,
            codes: base.codes.clone(),
        };
        fx.persist();
        edit_json(fx.dir.path(), |v| edit(v));
        fx.reload();
        let before = fx.bytes();
        let err = away_unlock(&mut fx, 1, 9, Some(T0)).err().unwrap();
        assert!(
            matches!(err, CryptoError::DeviceUnwrapFailed),
            "case '{name}' produced {err:?}"
        );
        assert_eq!(before, fx.bytes());
    }

    // The policy edit is caught by the MAC where no AAD-bound wrap opens first (home path).
    let mut fx = Fx {
        dir: tempfile::tempdir().unwrap(),
        reg: base.reg.clone(),
        rmk: base.rmk,
        nk: base.nk,
        codes: base.codes.clone(),
    };
    fx.persist();
    edit_json(fx.dir.path(), |v| v["away_grant_seconds"] = 61.into());
    fx.reload();
    assert!(matches!(
        home_unlock(&mut fx, Some(T0)),
        Err(CryptoError::DeviceStateTampered)
    ));

    // Home side: swapped device id changes the KEK.
    let mut fx = home_fx();
    edit_json(fx.dir.path(), |v| {
        v["devices"][0]["id"] = "0".repeat(32).into()
    });
    fx.reload();
    assert!(matches!(
        home_unlock(&mut fx, Some(T0)),
        Err(CryptoError::DeviceUnwrapFailed)
    ));

    // ESC edit: no device wrap and no emergency code opens.
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut fx = home_fx();
    edit_json(fx.dir.path(), |v| {
        v["esc_b64"] = STANDARD.encode([9u8; 32]).into()
    });
    fx.reload();
    assert!(matches!(
        home_unlock(&mut fx, Some(T0)),
        Err(CryptoError::DeviceUnwrapFailed)
    ));
    set_emergency_code(&fx.codes[0].clone());
    assert!(matches!(
        emergency::emergency_unlock(fx.dir.path(), &mut fx.reg, 1),
        Err(CryptoError::EmergencyCodeRejected)
    ));
}

// ---------------------------------------------------------------------------
// Grant lifecycle
// ---------------------------------------------------------------------------

#[test]
fn grant_window_is_inclusive_then_erased_then_reminted_by_home() {
    let mut fx = home_fx();
    let away_idx = fx.add_fido("away", false, 5);
    assert!(fx.reg.devices[away_idx].grant.is_none());
    assert!(fx.reg.devices[away_idx].wrap.is_none());

    // Away device without a grant has nothing to authenticate against.
    assert!(matches!(
        away_unlock(&mut fx, away_idx, 6, Some(T0)),
        Err(CryptoError::DeviceGrantAbsent { .. })
    ));

    // Home unlock mints not_after = attested_now + period.
    let u = home_unlock(&mut fx, Some(T0)).unwrap();
    assert_eq!(u.grants_issued, 1);
    assert_eq!(*u.nk, fx.nk);
    let g = fx.reg.devices[away_idx].grant.clone().unwrap();
    assert_eq!(g.not_after_unix, T0 + u64::from(DEFAULT_AWAY_GRANT_SECONDS));
    assert_eq!(g.issued_at_unix, T0);
    let persisted = load(fx.dir.path()).unwrap();
    assert_eq!(
        persisted.devices[away_idx]
            .grant
            .as_ref()
            .unwrap()
            .not_after_unix,
        g.not_after_unix
    );

    // At the deadline the grant still opens.
    let u = away_unlock(&mut fx, away_idx, 6, Some(g.not_after_unix)).unwrap();
    assert_eq!(*u.nk, fx.nk);
    assert_eq!(fx.reg.devices[away_idx].sign_count_last, Some(6));
    assert_eq!(
        load(fx.dir.path()).unwrap().devices[away_idx].sign_count_last,
        Some(6)
    );

    // One second later it is expired, erased and persisted.
    let err = away_unlock(&mut fx, away_idx, 7, Some(g.not_after_unix + 1))
        .err()
        .unwrap();
    assert!(
        matches!(err, CryptoError::DeviceGrantExpired { not_after_unix, attested_now, .. }
        if not_after_unix == g.not_after_unix && attested_now == g.not_after_unix + 1)
    );
    assert!(
        load(fx.dir.path()).unwrap().devices[away_idx]
            .grant
            .is_none()
    );
    assert!(matches!(
        away_unlock(&mut fx, away_idx, 8, Some(g.not_after_unix + 1)),
        Err(CryptoError::DeviceGrantAbsent { .. })
    ));

    // A later home unlock re-mints via kek_wrap, without the token.
    let later = g.not_after_unix + 500;
    let u = home_unlock(&mut fx, Some(later)).unwrap();
    assert_eq!(u.grants_issued, 1);
    assert_eq!(
        fx.reg.devices[away_idx]
            .grant
            .as_ref()
            .unwrap()
            .not_after_unix,
        later + u64::from(DEFAULT_AWAY_GRANT_SECONDS)
    );
    away_unlock(&mut fx, away_idx, 9, Some(later)).unwrap();
}

#[test]
fn away_unlock_requires_attested_time_and_never_falls_back() {
    let mut fx = home_fx();
    let idx = fx.add_fido("away", false, 5);
    home_unlock(&mut fx, Some(T0)).unwrap();
    let before = fx.bytes();
    assert!(matches!(
        away_unlock(&mut fx, idx, 6, None),
        Err(CryptoError::AttestedTimeUnavailable(_))
    ));
    assert_eq!(before, fx.bytes());
}

#[test]
fn home_unlock_without_attestation_serves_but_mints_and_erases_nothing() {
    let mut fx = home_fx();
    let idx = fx.add_fido("away", false, 5);
    home_unlock(&mut fx, Some(T0)).unwrap();
    let before = fx.bytes();
    let u = home_unlock(&mut fx, None).unwrap();
    assert_eq!((u.grants_issued, u.grants_erased), (0, 0));
    assert_eq!(*u.nk, fx.nk);
    assert_eq!(before, fx.bytes(), "no persist without attested time");
    assert!(fx.reg.devices[idx].grant.is_some());
}

#[test]
fn load_and_emergency_unlock_never_sweep() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut fx = home_fx();
    let idx = fx.add_fido("away", false, 5);
    home_unlock(&mut fx, Some(T0)).unwrap();
    let not_after = fx.reg.devices[idx].grant.as_ref().unwrap().not_after_unix;

    // Loading an "expired" registry changes nothing.
    let before = fx.bytes();
    let reg = load(fx.dir.path()).unwrap();
    assert!(reg.devices[idx].grant.is_some());
    assert_eq!(before, fx.bytes());

    // Emergency unlock burns one slot and leaves the (long-expired) grant alone.
    let mut reg = load(fx.dir.path()).unwrap();
    set_emergency_code(&fx.codes[0]);
    emergency::emergency_unlock(fx.dir.path(), &mut reg, not_after + 10_000_000)
        .unwrap()
        .unwrap();
    let after = load(fx.dir.path()).unwrap();
    assert_eq!(
        after.devices[idx].grant.as_ref().unwrap().not_after_unix,
        not_after
    );
    assert!(after.emergency_slots[0].wrap.is_none());
    assert!(after.emergency_slots[1].wrap.is_some());
}

#[test]
fn sibling_expiry_is_erased_in_the_same_write_as_an_away_unlock() {
    let mut fx = home_fx();
    let a = fx.add_fido("away-a", false, 5);
    // Second away device with its own secret.
    let t = FixedTime(Some(T0));
    let p = policy();
    let ctx = Ctx {
        time: &t,
        now_host: 5,
        policy: &p,
    };
    enroll_device(
        fx.dir.path(),
        &mut fx.reg,
        fido_dev("away-b", false, &[0xB2; 32], 5),
        &fx.rmk,
        &home(),
        &ctx,
    )
    .unwrap();
    fx.persist();
    let b = fx.reg.devices.len() - 1;

    home_unlock(&mut fx, Some(T0)).unwrap();
    // Shorten b's life artificially is impossible (AAD-bound); instead let both lapse
    // differently: refresh only later so a's grant is newer than b's.
    let t_later = T0 + 100;
    // Re-mint a only by editing is impossible; use two home unlocks and compare deadlines.
    home_unlock(&mut fx, Some(t_later)).unwrap();
    let nb = fx.reg.devices[b].grant.as_ref().unwrap().not_after_unix;
    // Both now share the same deadline; at nb+1 a's own grant is expired and erased,
    // and so is b's: the sweep is global.
    let err = away_unlock(&mut fx, a, 6, Some(nb + 1)).err().unwrap();
    assert!(matches!(err, CryptoError::DeviceGrantExpired { .. }));
    let reloaded = load(fx.dir.path()).unwrap();
    assert!(reloaded.devices[a].grant.is_none());
    assert!(
        reloaded.devices[b].grant.is_none(),
        "sweep is global and persisted"
    );
}

#[test]
fn sign_count_must_strictly_increase() {
    let mut fx = home_fx();
    let idx = fx.add_fido("away", false, 500);
    home_unlock(&mut fx, Some(T0)).unwrap();
    for bad in [499u32, 500] {
        assert!(matches!(
            away_unlock(&mut fx, idx, bad, Some(T0)),
            Err(CryptoError::DeviceSignCountRollback { asserted, last: 500, .. }) if asserted == bad
        ));
    }
    away_unlock(&mut fx, idx, 501, Some(T0)).unwrap();
    assert_eq!(
        load(fx.dir.path()).unwrap().devices[idx].sign_count_last,
        Some(501)
    );
}

#[test]
fn wrong_secret_length_and_wrong_secret_are_distinguished() {
    let mut fx = home_fx();
    let idx = fx.add_fido("away", false, 5);
    home_unlock(&mut fx, Some(T0)).unwrap();
    let err = unlock_with_away(
        fx.dir.path(),
        &mut fx.reg.clone(),
        idx,
        &[0u8; 31],
        9,
        &FixedTime(Some(T0)),
        &policy(),
    )
    .err()
    .unwrap();
    assert!(matches!(
        err,
        CryptoError::DeviceSecretLength { len: 31, .. }
    ));
    let err = unlock_with_away(
        fx.dir.path(),
        &mut fx.reg.clone(),
        idx,
        &[0u8; 32],
        9,
        &FixedTime(Some(T0)),
        &policy(),
    )
    .err()
    .unwrap();
    assert!(matches!(err, CryptoError::DeviceUnwrapFailed));
}

#[test]
fn grant_deadline_saturates_instead_of_overflowing() {
    let mut fx = home_fx();
    let idx = fx.add_fido("away", false, 5);
    let u = home_unlock(&mut fx, Some(u64::MAX)).unwrap();
    assert_eq!(u.grants_issued, 1);
    assert_eq!(
        fx.reg.devices[idx].grant.as_ref().unwrap().not_after_unix,
        u64::MAX
    );
    let t = FixedTime(Some(u64::MAX));
    let p = policy();
    let ctx = Ctx {
        time: &t,
        now_host: 1,
        policy: &p,
    };
    let n = refresh_grants(fx.dir.path(), &mut fx.reg, &fx.rmk, &home(), &ctx).unwrap();
    assert_eq!(n, 1);
    assert_eq!(
        fx.reg.devices[idx].grant.as_ref().unwrap().not_after_unix,
        u64::MAX
    );
}

#[test]
fn unusable_kek_wrap_skips_only_that_record() {
    let mut fx = home_fx();
    let a = fx.add_fido("away-a", false, 5);
    let b = fx.add_fido("away-b", false, 5);
    // Corrupt a's kek_wrap ciphertext; the MAC covers its hash, so re-sign.
    {
        let w = fx.reg.devices[a].kek_wrap.as_mut().unwrap();
        let mut raw = STANDARD.decode(&w.ct_b64).unwrap();
        raw[0] ^= 1;
        w.ct_b64 = STANDARD.encode(raw);
    }
    fx.persist();
    let u = home_unlock(&mut fx, Some(T0)).unwrap();
    assert_eq!(u.grants_issued, 1);
    let reg = load(fx.dir.path()).unwrap();
    assert!(reg.devices[a].grant.is_none());
    assert!(reg.devices[b].grant.is_some());
}

// ---------------------------------------------------------------------------
// sweep_now
// ---------------------------------------------------------------------------

#[test]
fn sweep_now_cases() {
    // Zero-home registry never requests attested time.
    let fx = zero_home_fx();
    let before = fx.bytes();
    assert_eq!(
        sweep_now(fx.dir.path(), &fx.state_key(), None, &PanicTime).unwrap(),
        (0, 0)
    );
    assert_eq!(before, fx.bytes());

    // Only Tpm2 records + rmk: nothing to mint, no time request.
    let fx = home_fx();
    let before = fx.bytes();
    assert_eq!(
        sweep_now(fx.dir.path(), &fx.state_key(), Some(&fx.rmk), &PanicTime).unwrap(),
        (0, 0)
    );
    assert_eq!(before, fx.bytes());

    // Grantless away record under home authority: re-minted (daemon recovery after a
    // boot that could not attest). Without rmk it only sweeps.
    let mut fx = home_fx();
    let idx = fx.add_fido("away", false, 5);
    assert_eq!(
        sweep_now(fx.dir.path(), &fx.state_key(), None, &PanicTime).unwrap(),
        (0, 0)
    );
    let r = sweep_now(
        fx.dir.path(),
        &fx.state_key(),
        Some(&fx.rmk),
        &FixedTime(Some(T0)),
    )
    .unwrap();
    assert_eq!(r, (1, 0));
    assert!(load(fx.dir.path()).unwrap().devices[idx].grant.is_some());

    // Sweep without rmk erases an expired grant and mints nothing.
    let nb = load(fx.dir.path()).unwrap().devices[idx]
        .grant
        .as_ref()
        .unwrap()
        .not_after_unix;
    let r = sweep_now(
        fx.dir.path(),
        &fx.state_key(),
        None,
        &FixedTime(Some(nb + 1)),
    )
    .unwrap();
    assert_eq!(r, (0, 1));
    assert!(load(fx.dir.path()).unwrap().devices[idx].grant.is_none());

    // Attestation failure: does nothing, byte-identical.
    fx.reload();
    let before = fx.bytes();
    let r = sweep_now(
        fx.dir.path(),
        &fx.state_key(),
        Some(&fx.rmk),
        &FixedTime(None),
    )
    .unwrap();
    assert_eq!(r, (0, 0));
    assert_eq!(before, fx.bytes());

    // Tampered MAC: never re-signed.
    edit_json(fx.dir.path(), |v| v["devices"][0]["label"] = "x".into());
    let before = fx.bytes();
    let r = sweep_now(
        fx.dir.path(),
        &fx.state_key(),
        Some(&fx.rmk),
        &FixedTime(Some(T0)),
    )
    .unwrap();
    assert_eq!(r, (0, 0));
    assert_eq!(before, fx.bytes());
}

// ---------------------------------------------------------------------------
// Authority, enrolment, removal, grant period
// ---------------------------------------------------------------------------

fn ctx_parts() -> (FixedTime, DevicePolicy) {
    (FixedTime(Some(T0)), policy())
}

fn is_insufficient(r: Result<impl Sized, CryptoError>) -> bool {
    matches!(
        r.err(),
        Some(CryptoError::DeviceAuthorityInsufficient { .. })
    )
}

#[test]
fn authority_matrix_with_a_home_device() {
    let mut fx = home_fx();
    fx.add_fido("away", false, 5);
    let (t, p) = ctx_parts();
    let ctx = Ctx {
        time: &t,
        now_host: 1,
        policy: &p,
    };
    let (dir, rmk, nk) = (fx.dir.path().to_path_buf(), fx.rmk, fx.nk);

    // Away: nothing mutating.
    assert!(is_insufficient(enroll_device(
        &dir,
        &mut fx.reg,
        tpm_dev("t2", &[3; 32]),
        &rmk,
        &away(),
        &ctx
    )));
    assert!(is_insufficient(enroll_device(
        &dir,
        &mut fx.reg,
        fido_dev("f2", false, &[4; 32], 5),
        &rmk,
        &away(),
        &ctx
    )));
    assert!(is_insufficient(remove_device(
        &dir,
        &mut fx.reg,
        "away",
        &rmk,
        &away(),
        &ctx
    )));
    assert!(is_insufficient(remove_device(
        &dir,
        &mut fx.reg,
        "home",
        &rmk,
        &away(),
        &ctx
    )));
    assert!(is_insufficient(set_grant_period(
        &dir,
        &mut fx.reg,
        120,
        &nk,
        &rmk,
        &away(),
        &ctx
    )));
    assert!(is_insufficient(refresh_grants(
        &dir,
        &mut fx.reg,
        &rmk,
        &away(),
        &ctx
    )));
    assert!(is_insufficient(reseal_device(
        &dir,
        &mut fx.reg,
        "home",
        &rmk,
        &away(),
        &ctx
    )));

    // Emergency: cannot add anything or refresh, may remove an away record.
    assert!(is_insufficient(enroll_device(
        &dir,
        &mut fx.reg,
        tpm_dev("t2", &[3; 32]),
        &rmk,
        &emerg(),
        &ctx
    )));
    assert!(is_insufficient(enroll_device(
        &dir,
        &mut fx.reg,
        fido_dev("f2", false, &[4; 32], 5),
        &rmk,
        &emerg(),
        &ctx
    )));
    assert!(is_insufficient(refresh_grants(
        &dir,
        &mut fx.reg,
        &rmk,
        &emerg(),
        &ctx
    )));
    remove_device(&dir, &mut fx.reg, "away", &rmk, &emerg(), &ctx).unwrap();

    // Home: may add an away record (minting nothing) and a second home device.
    enroll_device(
        &dir,
        &mut fx.reg,
        fido_dev("f2", false, &[4; 32], 5),
        &rmk,
        &home(),
        &ctx,
    )
    .unwrap();
    let f2 = fx.reg.devices.iter().find(|d| d.label == "f2").unwrap();
    assert!(f2.wrap.is_none() && f2.grant.is_none());
    enroll_device(
        &dir,
        &mut fx.reg,
        tpm_dev("t2", &[3; 32]),
        &rmk,
        &home(),
        &ctx,
    )
    .unwrap();
    assert_eq!(home_count(&fx.reg), 2);
    // Unknown selector and bad labels.
    assert!(matches!(
        remove_device(&dir, &mut fx.reg, "nope", &rmk, &home(), &ctx),
        Err(CryptoError::DeviceNotFound(_))
    ));
    assert!(matches!(
        enroll_device(
            &dir,
            &mut fx.reg,
            tpm_dev(&"x".repeat(65), &[3; 32]),
            &rmk,
            &home(),
            &ctx
        ),
        Err(CryptoError::DeviceLabelInvalid(_))
    ));
    assert!(matches!(
        enroll_device(
            &dir,
            &mut fx.reg,
            tpm_dev("bad\x7f", &[3; 32]),
            &rmk,
            &home(),
            &ctx
        ),
        Err(CryptoError::DeviceLabelInvalid(_))
    ));
    assert!(matches!(
        enroll_device(
            &dir,
            &mut fx.reg,
            tpm_dev("HOME", &[3; 32]),
            &rmk,
            &home(),
            &ctx
        ),
        Err(CryptoError::DeviceLabelInUse(_))
    ));
}

#[test]
fn removal_rules_protect_the_last_home_and_last_device() {
    let mut fx = home_fx();
    fx.add_fido("away", false, 5);
    let (t, p) = ctx_parts();
    let ctx = Ctx {
        time: &t,
        now_host: 1,
        policy: &p,
    };
    let (dir, rmk) = (fx.dir.path().to_path_buf(), fx.rmk);
    for by in [home(), emerg()] {
        let before = fx.reg.devices.len();
        let err = remove_device(&dir, &mut fx.reg, "home", &rmk, &by, &ctx).unwrap_err();
        assert!(
            matches!(err, CryptoError::DeviceLastHomeRemovalRefused { ref label } if label == "home")
        );
        assert_eq!(fx.reg.devices.len(), before);
    }
    // Removing the away record first, then the lone home: last device.
    remove_device(&dir, &mut fx.reg, "away", &rmk, &home(), &ctx).unwrap();
    assert!(matches!(
        remove_device(&dir, &mut fx.reg, "home", &rmk, &home(), &ctx),
        Err(CryptoError::DeviceRegistryLastDevice)
    ));
}

#[test]
fn zero_home_registry_lifecycle() {
    let (t, p) = ctx_parts();
    let ctx = Ctx {
        time: &t,
        now_host: 1,
        policy: &p,
    };

    // Permanent wrap: away unlock needs neither network nor clock.
    let mut fx = zero_home_fx();
    assert!(fx.reg.permanent_away);
    assert!(fx.reg.devices[0].wrap.is_some() && fx.reg.devices[0].grant.is_none());
    let u = unlock_with_away(
        fx.dir.path(),
        &mut fx.reg,
        0,
        &AWAY_SECRET,
        6,
        &PanicTime,
        &policy(),
    )
    .unwrap();
    assert_eq!(*u.nk, fx.nk);

    // Authority on a zero-home registry.
    let (dir, rmk, nk) = (fx.dir.path().to_path_buf(), fx.rmk, fx.nk);
    assert!(is_insufficient(remove_device(
        &dir,
        &mut fx.reg,
        "away",
        &rmk,
        &away(),
        &ctx
    )));
    assert!(is_insufficient(set_grant_period(
        &dir,
        &mut fx.reg,
        120,
        &nk,
        &rmk,
        &away(),
        &ctx
    )));
    assert!(is_insufficient(refresh_grants(
        &dir,
        &mut fx.reg,
        &rmk,
        &away(),
        &ctx
    )));
    assert!(is_insufficient(enroll_device(
        &dir,
        &mut fx.reg,
        tpm_dev("t", &[3; 32]),
        &rmk,
        &emerg(),
        &ctx
    )));

    // add-fido2 under Away with zero homes: permanent wrap, no grant.
    enroll_device(
        &dir,
        &mut fx.reg,
        fido_dev("away2", false, &[0xC3; 32], 5),
        &rmk,
        &away(),
        &ctx,
    )
    .unwrap();
    let a2 = &fx.reg.devices[1];
    assert!(a2.wrap.is_some() && a2.grant.is_none());
    assert!(fx.reg.permanent_away);

    // Row 9: first Tpm2 under Away strips permanent wraps and mints grants.
    enroll_device(
        &dir,
        &mut fx.reg,
        tpm_dev("home", &HOME_SECRET),
        &rmk,
        &away(),
        &ctx,
    )
    .unwrap();
    assert!(!fx.reg.permanent_away);
    for d in fx
        .reg
        .devices
        .iter()
        .filter(|d| d.kind == DeviceKind::Fido2)
    {
        assert!(d.wrap.is_none());
        assert!(d.grant.is_some());
    }
    fx.persist();
    let u = away_unlock(&mut fx, 0, 7, Some(T0)).unwrap();
    assert_eq!(*u.nk, fx.nk);
}

#[test]
fn row9_without_attestation_strips_wraps_and_mints_nothing() {
    let mut fx = zero_home_fx();
    let t = FixedTime(None);
    let p = policy();
    let ctx = Ctx {
        time: &t,
        now_host: 1,
        policy: &p,
    };
    enroll_device(
        fx.dir.path(),
        &mut fx.reg,
        tpm_dev("home", &HOME_SECRET),
        &fx.rmk,
        &away(),
        &ctx,
    )
    .unwrap();
    fx.persist();
    let d = &fx.reg.devices[0];
    assert!(d.wrap.is_none() && d.grant.is_none());
    assert!(matches!(
        away_unlock(&mut fx, 0, 9, Some(T0)),
        Err(CryptoError::DeviceGrantAbsent { .. })
    ));
}

#[test]
fn set_grant_period_by_authority() {
    let mut fx = home_fx();
    let idx = fx.add_fido("away", false, 5);
    home_unlock(&mut fx, Some(T0)).unwrap();
    let (t, p) = ctx_parts();
    let ctx = Ctx {
        time: &t,
        now_host: 1,
        policy: &p,
    };
    let (dir, rmk, nk) = (fx.dir.path().to_path_buf(), fx.rmk, fx.nk);

    // Emergency: equal or larger refused; strictly smaller drops grants, mints none.
    assert!(is_insufficient(set_grant_period(
        &dir,
        &mut fx.reg,
        DEFAULT_AWAY_GRANT_SECONDS,
        &nk,
        &rmk,
        &emerg(),
        &ctx
    )));
    assert!(is_insufficient(set_grant_period(
        &dir,
        &mut fx.reg,
        DEFAULT_AWAY_GRANT_SECONDS + 1,
        &nk,
        &rmk,
        &emerg(),
        &ctx
    )));
    set_grant_period(&dir, &mut fx.reg, 120, &nk, &rmk, &emerg(), &ctx).unwrap();
    assert_eq!(fx.reg.away_grant_seconds, 120);
    assert!(fx.reg.devices[idx].grant.is_none());
    fx.persist();
    assert_eq!(
        *open_nk_pub(&load(fx.dir.path()).unwrap(), &rmk, fx.dir.path()).unwrap(),
        nk
    );

    // Home: any value, re-mints under the new period.
    set_grant_period(&dir, &mut fx.reg, 3600, &nk, &rmk, &home(), &ctx).unwrap();
    fx.persist();
    let g = fx.reg.devices[idx].grant.clone().unwrap();
    assert_eq!(g.not_after_unix, T0 + 3600);
    assert_eq!(
        *open_nk_pub(&load(fx.dir.path()).unwrap(), &rmk, fx.dir.path()).unwrap(),
        nk
    );
    away_unlock(&mut fx, idx, 6, Some(T0)).unwrap();

    // Away: refused.
    assert!(is_insufficient(set_grant_period(
        &dir,
        &mut fx.reg,
        60,
        &nk,
        &rmk,
        &away(),
        &ctx
    )));
}

// ---------------------------------------------------------------------------
// repair-state
// ---------------------------------------------------------------------------

#[test]
fn repair_state_via_emergency_code() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut fx = home_fx();
    let idx = fx.add_fido("away", false, 5);
    home_unlock(&mut fx, Some(T0)).unwrap();
    edit_json(fx.dir.path(), |v| {
        v["devices"][0]["label"] = "tampered".into()
    });

    // The normal path refuses.
    fx.reload();
    assert!(matches!(
        home_unlock(&mut fx, Some(T0)),
        Err(CryptoError::DeviceStateTampered)
    ));

    // No acknowledgement: nothing happens, nothing is written.
    let before = fx.bytes();
    set_emergency_code(&fx.codes[3].clone());
    assert!(matches!(
        repair_state_entry(fx.dir.path(), 9, &policy(), &NoPins, false, false),
        Err(CryptoError::DeviceRepairNotAccepted)
    ));
    assert_eq!(before, fx.bytes());
    // The acknowledgement gate precedes env intake: the code is still usable.
    assert!(std::env::var_os(EMERGENCY_KEY_ENV_VAR).is_some());

    // With acknowledgement: grants dropped, MAC re-signed, one slot burned in the same write.
    let auth = repair_state_entry(fx.dir.path(), 9, &policy(), &NoPins, false, true).unwrap();
    assert!(matches!(auth, Authority::Emergency { index: 3 }));
    let reg = load(fx.dir.path()).unwrap();
    assert!(reg.devices[idx].grant.is_none());
    assert!(reg.emergency_slots[3].wrap.is_none());
    assert_eq!(reg.emergency_slots[3].burned_at_unix, Some(9));
    assert_eq!(
        reg.devices[0].label, "tampered",
        "identity is re-signed as found"
    );
    verify_state_mac(&fx.state_key(), &reg, fx.dir.path()).unwrap();

    // A registry whose MAC already verifies is refused and nothing is written.
    set_emergency_code(&fx.codes[4].clone());
    let before = fx.bytes();
    let r = repair_state_entry(fx.dir.path(), 9, &policy(), &NoPins, false, true);
    assert!(
        matches!(r, Err(CryptoError::DeviceStateIntact)),
        "{:?}",
        r.err()
    );
    assert_eq!(before, fx.bytes());
    assert!(
        load(fx.dir.path()).unwrap().emergency_slots[4]
            .wrap
            .is_some()
    );
}

#[test]
fn repair_refuses_a_spliced_nk_wrap_and_grant_only_away_records() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut fx = home_fx();
    fx.add_fido("away", false, 5);
    home_unlock(&mut fx, Some(T0)).unwrap();

    // Grant-only away record with a home registered: refused before any touch.
    // (The unreachable TCTI makes the home attempt fail without hardware.)
    edit_json(fx.dir.path(), |v| {
        v["devices"][0]["label"] = "tampered".into()
    });
    let err = repair_state_entry(fx.dir.path(), 9, &policy(), &NoPins, true, true).unwrap_err();
    match err {
        CryptoError::DeviceAuthorityInsufficient { operation, by, .. } => {
            assert_eq!(operation, "repair-state");
            assert_eq!(by, "away device 'away'");
        }
        other => panic!("unexpected {other:?}"),
    }

    // Spliced nk_wrap: DeviceRegistryCorrupt, nothing written, the code is not burned.
    edit_json(fx.dir.path(), |v| {
        let ct = v["nk_wrap"]["ct_b64"].as_str().unwrap().to_owned();
        let mut raw = STANDARD.decode(ct).unwrap();
        raw[0] ^= 1;
        v["nk_wrap"]["ct_b64"] = STANDARD.encode(raw).into();
    });
    let before = fx.bytes();
    set_emergency_code(&fx.codes[0].clone());
    assert!(matches!(
        repair_state_entry(fx.dir.path(), 9, &policy(), &NoPins, false, true),
        Err(CryptoError::DeviceRegistryCorrupt { .. })
    ));
    assert_eq!(before, fx.bytes());
}

#[test]
fn repair_on_zero_home_registry_gates_away_repair_on_the_flag() {
    let fx = zero_home_fx();
    edit_json(fx.dir.path(), |v| {
        v["devices"][0]["label"] = "tampered".into()
    });
    let err = repair_state_entry(fx.dir.path(), 9, &policy(), &NoPins, false, true).unwrap_err();
    assert!(matches!(
        err,
        CryptoError::DeviceAuthorityInsufficient { .. }
    ));
}
