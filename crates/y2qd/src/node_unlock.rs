//! Node-key resolution at boot.
//!
//! Two modes, in this precedence order:
//!
//! 1. **Operator mode** — `Y2QD_NODE_KEY` or `[crypto] node_key_file`. Unchanged
//!    from before the device registry existed, and it wins at boot, so CI and
//!    the e2e suite are unaffected.
//! 2. **Device mode** — `<keystore_dir>/devices.json` exists. The node key is
//!    recovered from a registered TPM home device, a FIDO2 away device or a
//!    one-time emergency code (`y2q_core::crypto::devices`). Requires a Linux
//!    build with the `devices` feature; any other build refuses the registry.

use std::path::Path;

use y2q_core::crypto::{CryptoError, node_key};
use zeroize::Zeroizing;

#[cfg(all(target_os = "linux", feature = "devices"))]
use y2q_core::crypto::devices::{self, Authority, DeviceKind, DevicePolicy, PinProvider};
#[cfg(all(target_os = "linux", feature = "devices"))]
use y2q_core::secmem::SecretBuf;

/// Environment variable carrying the authenticator PIN for unattended boot.
/// Must come from a source outside `keystore_dir`.
#[cfg(all(target_os = "linux", feature = "devices"))]
pub const FIDO2_PIN_ENV_VAR: &str = "Y2QD_FIDO2_PIN";

/// Where the node key came from.
pub enum Source {
    /// `Y2QD_NODE_KEY` / `node_key_file`.
    Operator,
    /// A registered device opened the registry.
    #[cfg(all(target_os = "linux", feature = "devices"))]
    Device {
        label: String,
        kind: DeviceKind,
        device_id_hex: String,
        grants_issued: usize,
        grants_erased: usize,
    },
    /// An emergency code opened the registry and was burned.
    #[cfg(all(target_os = "linux", feature = "devices"))]
    Emergency { index: u8 },
}

/// Result of [`resolve`].
pub struct Resolved {
    pub node_key: Zeroizing<[u8; 32]>,
    /// `Some` only on the device path; the sweeper's MAC key.
    #[cfg_attr(not(all(target_os = "linux", feature = "devices")), allow(dead_code))]
    pub registry_state_key: Option<std::sync::Arc<y2q_core::secmem::SecretBuf>>,
    /// `Some` only when the boot authority was a home device; lets the timer
    /// re-mint grants. Both registry keys live in guarded memory (`SecretBuf`)
    /// for the daemon's lifetime, like `NodeKeySlot::install`: RMK opens
    /// `nk_wrap`, every wrap and the state key, so it must not sit in
    /// swappable heap pages.
    #[cfg_attr(not(all(target_os = "linux", feature = "devices")), allow(dead_code))]
    pub registry_master_key: Option<std::sync::Arc<y2q_core::secmem::SecretBuf>>,
    pub source: Source,
}

/// Supplies an authenticator PIN to the device unlock: `Y2QD_FIDO2_PIN` (taken
/// once at construction), else a `/dev/tty` prompt, else an error. Prompted
/// answers are not cached.
#[cfg(all(target_os = "linux", feature = "devices"))]
pub(crate) struct DaemonPinProvider {
    env_pin: Option<Zeroizing<String>>,
    tty_probe: fn() -> bool,
}

#[cfg(all(target_os = "linux", feature = "devices"))]
fn real_tty_probe() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_ok()
}

#[cfg(all(target_os = "linux", feature = "devices"))]
impl DaemonPinProvider {
    pub(crate) fn new() -> Result<Self, CryptoError> {
        Self::with_tty_probe(real_tty_probe)
    }

    pub(crate) fn with_tty_probe(tty_probe: fn() -> bool) -> Result<Self, CryptoError> {
        let env_pin = match node_key::take_env_secret(FIDO2_PIN_ENV_VAR) {
            Ok(v) => v,
            Err(CryptoError::NodeKeyMalformed(_)) => {
                return Err(CryptoError::DeviceBackend(
                    "fido2: Y2QD_FIDO2_PIN is not valid UTF-8".to_owned(),
                ));
            }
            Err(e) => return Err(e),
        };
        Ok(Self { env_pin, tty_probe })
    }
}

#[cfg(all(target_os = "linux", feature = "devices"))]
impl PinProvider for DaemonPinProvider {
    fn pin(&self, label: &str) -> Result<Zeroizing<String>, CryptoError> {
        if let Some(pin) = &self.env_pin {
            return Ok(pin.clone());
        }
        if (self.tty_probe)() {
            let entered = rpassword::prompt_password(format!("PIN for away device '{label}': "))
                .map_err(|e| CryptoError::DeviceBackend(format!("pin prompt: {e}")))?;
            return Ok(Zeroizing::new(entered));
        }
        Err(CryptoError::DeviceBackend(format!(
            "fido2: away device '{label}' requires a PIN but no PIN source is available: set \
             Y2QD_FIDO2_PIN (from a source outside keystore_dir) or start y2qd attached to a \
             terminal"
        )))
    }
}

/// Copy a guarded 32-byte secret out for one call. The copy zeroizes on drop;
/// the guarded pages are readable only for the duration of this function.
#[cfg(all(target_os = "linux", feature = "devices"))]
pub(crate) fn unlock_key(buf: &SecretBuf) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let r = buf.unlock()?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&r[..]);
    Ok(out)
}

/// Resolve the node key. MUST be called inside the keystore flock: the device
/// path rewrites `devices.json`.
pub fn resolve(
    cfg: &crate::config::Config,
    keystore_dir: &Path,
) -> Result<Resolved, std::io::Error> {
    // 1. Operator mode wins at boot.
    if !cfg.crypto.node_key_file.trim().is_empty()
        || std::env::var_os(node_key::NODE_KEY_ENV_VAR).is_some()
    {
        // Refuse a node_key_file that resolves inside storage.base_path or
        // keystore_dir, so a copy of the data can't carry the key that
        // protects it.
        node_key::check_node_key_location(
            &cfg.crypto.node_key_file,
            Path::new(&cfg.storage.base_path),
            keystore_dir,
        )
        .map_err(std::io::Error::other)?;
        let nk = node_key::load_node_key(&cfg.crypto.node_key_file)
            .map_err(|e| std::io::Error::other(format!("node key: {e}")))?;
        return Ok(Resolved {
            node_key: nk,
            registry_state_key: None,
            registry_master_key: None,
            source: Source::Operator,
        });
    }

    // 2. Device mode.
    if y2q_core::crypto::devices::devices_path(keystore_dir).exists() {
        return resolve_devices(cfg, keystore_dir);
    }

    // 3. An emergency code with nothing to open.
    if std::env::var_os(y2q_core::crypto::devices::EMERGENCY_KEY_ENV_VAR).is_some() {
        return Err(std::io::Error::other(format!(
            "Y2QD_EMERGENCY_KEY is set but no device registry exists at {}; emergency codes only \
             unlock a registry created by `y2q admin device init`",
            y2q_core::crypto::devices::devices_path(keystore_dir).display()
        )));
    }

    // 4. Nothing at all.
    Err(std::io::Error::other(format!(
        "node key: {}",
        CryptoError::NodeKeyMissing
    )))
}

#[cfg(all(target_os = "linux", feature = "devices"))]
fn resolve_devices(
    cfg: &crate::config::Config,
    keystore_dir: &Path,
) -> Result<Resolved, std::io::Error> {
    use y2q_core::crypto::devices::roughtime::RoughtimeTimeSource;

    let dev_err = |e: &dyn std::fmt::Display| std::io::Error::other(format!("device unlock: {e}"));

    let policy: DevicePolicy = (&cfg.crypto.devices).into();
    let pins = DaemonPinProvider::new().map_err(|e| dev_err(&e))?;
    let time = RoughtimeTimeSource::new(policy.roughtime.clone());
    let outcome = devices::unlock(keystore_dir, &policy, &pins, &time, devices::now_unix())
        .map_err(|e| dev_err(&e))?;

    let state_key = std::sync::Arc::new(
        SecretBuf::from_slice(&outcome.registry_state_key[..]).map_err(|e| dev_err(&e))?,
    );
    let master_key = if matches!(outcome.authority, Authority::Home { .. }) {
        Some(std::sync::Arc::new(
            SecretBuf::from_slice(&outcome.registry_master_key[..]).map_err(|e| dev_err(&e))?,
        ))
    } else {
        None
    };

    if outcome.emergency_slots_unused <= 3 {
        tracing::warn!(
            unused = outcome.emergency_slots_unused,
            "three or fewer emergency codes remain"
        );
    }

    let source = match &outcome.authority {
        Authority::Home { id, label } => Source::Device {
            label: label.clone(),
            kind: DeviceKind::Tpm2,
            device_id_hex: id.clone(),
            grants_issued: outcome.grants_issued,
            grants_erased: outcome.grants_erased,
        },
        Authority::Away { id, label, .. } => Source::Device {
            label: label.clone(),
            kind: DeviceKind::Fido2,
            device_id_hex: id.clone(),
            grants_issued: outcome.grants_issued,
            grants_erased: outcome.grants_erased,
        },
        Authority::Emergency { index } => Source::Emergency { index: *index },
    };

    // The `Zeroizing` originals and the loaded registry drop here.
    Ok(Resolved {
        node_key: outcome.node_key,
        registry_state_key: Some(state_key),
        registry_master_key: master_key,
        source,
    })
}

#[cfg(not(all(target_os = "linux", feature = "devices")))]
fn resolve_devices(
    _cfg: &crate::config::Config,
    keystore_dir: &Path,
) -> Result<Resolved, std::io::Error> {
    match y2q_core::crypto::devices::refuse_if_present(keystore_dir) {
        Err(e) => Err(std::io::Error::other(format!("device unlock: {e}"))),
        Ok(()) => Err(std::io::Error::other(
            "device unlock: device registry disappeared while booting",
        )),
    }
}

/// Emit exactly one line naming the node-key source. Carries no key material,
/// wrap bytes, code or `ESC`.
pub fn log_source(source: &Source) {
    match source {
        Source::Operator => tracing::info!(source = "operator", "node key source resolved"),
        #[cfg(all(target_os = "linux", feature = "devices"))]
        Source::Device {
            label,
            kind,
            device_id_hex,
            grants_issued,
            grants_erased,
        } => match kind {
            DeviceKind::Tpm2 => tracing::info!(
                source = "device",
                device = %label,
                device_id = %device_id_hex,
                kind = "tpm2",
                grants_issued = *grants_issued,
                grants_erased = *grants_erased,
                "node key unlocked by home device"
            ),
            DeviceKind::Fido2 => tracing::info!(
                source = "device",
                device = %label,
                device_id = %device_id_hex,
                kind = "fido2",
                grants_erased = *grants_erased,
                "node key unlocked by away device"
            ),
        },
        #[cfg(all(target_os = "linux", feature = "devices"))]
        Source::Emergency { index } => tracing::warn!(
            source = "emergency",
            slot = *index,
            "node key unlocked by emergency code; this code is now burned"
        ),
    }
}

/// Serializes every test that mutates process environment variables.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::TEST_ENV_LOCK as LOCK;
    use super::*;
    use clap::Parser as _;

    fn clear_env() {
        // SAFETY: serialized on LOCK; no other test thread touches the
        // environment concurrently within this module.
        unsafe {
            std::env::remove_var("Y2QD_NODE_KEY");
            std::env::remove_var("Y2QD_EMERGENCY_KEY");
            std::env::remove_var("Y2QD_FIDO2_PIN");
        }
    }

    fn set_env(k: &str, v: &str) {
        // SAFETY: see `clear_env`.
        unsafe { std::env::set_var(k, v) };
    }

    fn cfg_for(keystore: &Path, storage: &Path) -> crate::config::Config {
        let toml = format!(
            "[server]\nhost = \"127.0.0.1\"\nport = 0\n[storage]\nbase_path = \"{}\"\n\
             [crypto]\nkeystore_dir = \"{}\"\n[auth]\n",
            storage.display(),
            keystore.display()
        );
        use figment::providers::{Format, Toml};
        figment::Figment::new()
            .merge(Toml::string(&toml))
            .extract()
            .expect("test config parses")
    }

    fn operator_key_text() -> String {
        // 32 distinct, high-entropy-looking bytes in hex.
        (0u8..32)
            .map(|i| format!("{:02x}", i.wrapping_mul(37).wrapping_add(11)))
            .collect()
    }

    #[test]
    fn operator_key_wins_and_leaves_registry_untouched() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        let ks = tempfile::tempdir().unwrap();
        let st = tempfile::tempdir().unwrap();
        let reg = ks.path().join("devices.json");
        std::fs::write(&reg, b"{ not parsed by the operator path }").unwrap();
        let before = std::fs::metadata(&reg).unwrap().modified().unwrap();
        set_env("Y2QD_NODE_KEY", &operator_key_text());
        let cfg = cfg_for(ks.path(), st.path());
        let r = resolve(&cfg, ks.path()).expect("operator key resolves");
        assert!(matches!(r.source, Source::Operator));
        assert!(r.registry_state_key.is_none());
        assert!(r.registry_master_key.is_none());
        let after = std::fs::metadata(&reg).unwrap().modified().unwrap();
        assert_eq!(before, after);
        clear_env();
    }

    #[test]
    fn no_key_error_text_is_exact() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        let ks = tempfile::tempdir().unwrap();
        let st = tempfile::tempdir().unwrap();
        let cfg = cfg_for(ks.path(), st.path());
        let err = resolve(&cfg, ks.path()).err().expect("must fail");
        assert_eq!(
            err.to_string(),
            "node key: node key not supplied: set Y2QD_NODE_KEY or [crypto] node_key_file"
        );
    }

    #[test]
    fn emergency_key_without_registry_is_rejected() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        let ks = tempfile::tempdir().unwrap();
        let st = tempfile::tempdir().unwrap();
        let cfg = cfg_for(ks.path(), st.path());
        set_env("Y2QD_EMERGENCY_KEY", "whatever");
        let err = resolve(&cfg, ks.path()).err().expect("must fail");
        assert!(
            err.to_string().contains("but no device registry exists at"),
            "{err}"
        );
        clear_env();
    }

    #[test]
    fn config_load_accepts_registry_alone() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        let ks = tempfile::tempdir().unwrap();
        let st = tempfile::tempdir().unwrap();
        std::fs::write(ks.path().join("devices.json"), b"{}").unwrap();
        let cfg_path = st.path().join("config.toml");
        std::fs::write(
            &cfg_path,
            format!(
                "[server]\nhost = \"127.0.0.1\"\nport = 0\n[storage]\nbase_path = \"{}\"\n\
                 [crypto]\nkeystore_dir = \"{}\"\n[auth]\n",
                st.path().display(),
                ks.path().display()
            ),
        )
        .unwrap();
        let cli = crate::cli::Cli::parse_from(["y2qd", "--config", cfg_path.to_str().unwrap()]);
        crate::config::Config::load(&cli).expect("registry alone satisfies the node-key rule");

        std::fs::remove_file(ks.path().join("devices.json")).unwrap();
        let err = crate::config::Config::load(&cli).err().unwrap();
        assert!(err.to_string().contains("devices.json"), "{err}");
    }

    #[cfg(not(all(target_os = "linux", feature = "devices")))]
    #[test]
    fn default_build_refuses_registry() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        let ks = tempfile::tempdir().unwrap();
        let st = tempfile::tempdir().unwrap();
        std::fs::write(ks.path().join("devices.json"), b"{}").unwrap();
        assert!(matches!(
            y2q_core::crypto::devices::refuse_if_present(ks.path()),
            Err(CryptoError::DeviceSupportNotCompiled(_))
        ));
        let cfg = cfg_for(ks.path(), st.path());
        let err = resolve(&cfg, ks.path()).err().expect("must fail");
        assert!(err.to_string().contains("devices"), "{err}");
    }

    #[cfg(all(target_os = "linux", feature = "devices"))]
    #[test]
    fn pin_provider_takes_env_and_scrubs_it() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        set_env(FIDO2_PIN_ENV_VAR, "123456");
        let p = DaemonPinProvider::with_tty_probe(|| false).unwrap();
        assert!(std::env::var_os(FIDO2_PIN_ENV_VAR).is_none());
        assert_eq!(p.pin("k").unwrap().as_str(), "123456");
        // Held for later records too.
        assert_eq!(p.pin("k2").unwrap().as_str(), "123456");
    }

    #[cfg(all(target_os = "linux", feature = "devices"))]
    #[test]
    fn pin_provider_without_any_source_errors() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        let p = DaemonPinProvider::with_tty_probe(|| false).unwrap();
        let err = p.pin("away-1").err().unwrap();
        assert!(
            err.to_string().contains("no PIN source is available"),
            "{err}"
        );
    }

    #[cfg(all(target_os = "linux", feature = "devices"))]
    #[test]
    fn unlock_key_round_trips() {
        let buf = SecretBuf::from_slice(&[7u8; 32]).unwrap();
        assert_eq!(&unlock_key(&buf).unwrap()[..], &[7u8; 32][..]);
    }
}
