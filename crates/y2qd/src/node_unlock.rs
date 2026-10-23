//! Node-key resolution at boot.
//!
//! Three modes, in this precedence order:
//!
//! 1. **Operator mode** — `Y2QD_NODE_KEY` or `[crypto] node_key_file`. Unchanged
//!    from before the device registry existed, and it wins at boot, so CI and
//!    the e2e suite are unaffected.
//! 2. **Key helper** — `[crypto.devices] key_agent_socket` is set. The node key
//!    is fetched once from a socket-activated one-shot `y2qd --key-serve`,
//!    which owns the hardware and RMK for the length of one request; the
//!    daemon never touches either. The helper must have been armed
//!    (`y2qd --key-arm`) beforehand.
//! 3. **Device mode** — `<keystore_dir>/devices.json` exists. The node key is
//!    recovered in-process from a registered TPM home device, a FIDO2 away
//!    device or a one-time emergency code (`y2q_core::crypto::devices`).
//!    Requires a Linux build with the `devices` feature; any other build
//!    refuses the registry.

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
    /// The socket-activated key helper opened the registry and handed the key
    /// over.
    #[cfg(target_os = "linux")]
    Agent(y2q_core::crypto::devices::keyrpc::FetchMeta),
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

    /// Terminal-only: there is no environment variable for a passcode, so one
    /// never sits in a unit file.
    fn passcode(&self, label: &str) -> Result<Zeroizing<String>, CryptoError> {
        if (self.tty_probe)() {
            let entered =
                rpassword::prompt_password(format!("Passcode for home device '{label}': "))
                    .map_err(|e| CryptoError::DeviceBackend(format!("passcode prompt: {e}")))?;
            return Ok(Zeroizing::new(entered));
        }
        Err(CryptoError::DeviceBackend(format!(
            "home device '{label}' requires a passcode but no passcode source is available: \
             start y2qd attached to a terminal"
        )))
    }
}

/// How long the daemon keeps retrying while the key-helper socket is absent.
#[cfg(target_os = "linux")]
const AGENT_CONNECT_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);

/// Fetch the node key from the socket-activated key helper.
#[cfg(target_os = "linux")]
fn resolve_agent(cfg: &crate::config::Config) -> Result<Resolved, std::io::Error> {
    use y2q_core::crypto::devices::keyrpc;

    let dev = &cfg.crypto.devices;
    let fetched = keyrpc::fetch(
        Path::new(&dev.key_agent_socket),
        AGENT_CONNECT_WINDOW,
        std::time::Duration::from_secs(dev.key_agent_timeout_seconds),
    )
    .map_err(|e| {
        let text = e.to_string();
        let hint = if text.contains("not armed") {
            "; the key helper must be armed before the daemon starts: unattended hosts arm \
             with empty authorization from ExecStartPre=+ (`y2qd --key-arm`), attended hosts \
             arm interactively (`y2qd --key-arm --prompt-passcode`, `--prompt-pin` or \
             `--prompt-emergency-code`) first"
        } else {
            ""
        };
        std::io::Error::other(format!("node key: {text}{hint}"))
    })?;
    if fetched.meta.emergency_slots_unused <= 3 {
        tracing::warn!(
            unused = fetched.meta.emergency_slots_unused,
            "three or fewer emergency codes remain"
        );
    }
    Ok(Resolved {
        node_key: fetched.node_key,
        registry_state_key: None,
        registry_master_key: None,
        source: Source::Agent(fetched.meta),
    })
}

#[cfg(not(target_os = "linux"))]
fn resolve_agent(_cfg: &crate::config::Config) -> Result<Resolved, std::io::Error> {
    Err(std::io::Error::other(
        "[crypto.devices] key_agent_socket requires Linux",
    ))
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

    // 2. Key helper: the daemon never touches the hardware or devices.json.
    if !cfg.crypto.devices.key_agent_socket.is_empty() {
        return resolve_agent(cfg);
    }

    // 3. Device mode (in-process).
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
    unlock_devices(cfg, keystore_dir).map(|(resolved, unused)| {
        if unused <= 3 {
            tracing::warn!(unused, "three or fewer emergency codes remain");
        }
        resolved
    })
}

/// In-process device unlock (legacy mode, empty `key_agent_socket`). Returns
/// the resolved key plus the number of unburned emergency slots.
#[cfg(all(target_os = "linux", feature = "devices"))]
pub(crate) fn unlock_devices(
    cfg: &crate::config::Config,
    keystore_dir: &Path,
) -> Result<(Resolved, usize), std::io::Error> {
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
    Ok((
        Resolved {
            node_key: outcome.node_key,
            registry_state_key: Some(state_key),
            registry_master_key: master_key,
            source,
        },
        outcome.emergency_slots_unused,
    ))
}

/// One grant sweep / re-mint pass for the daemon's in-process timer (legacy
/// mode). Copies the guarded keys out for this call only; both copies
/// zeroize on drop.
#[cfg(all(target_os = "linux", feature = "devices"))]
pub(crate) fn grant_sweep_once(
    dir: &Path,
    policy: &DevicePolicy,
    state_key: &SecretBuf,
    master: Option<&SecretBuf>,
) -> Result<(usize, usize), CryptoError> {
    let state_key = unlock_key(state_key)?;
    let rmk = master.map(unlock_key).transpose()?;
    let time = devices::roughtime::RoughtimeTimeSource::new(policy.roughtime.clone());
    devices::sweep_now(dir, &state_key, rmk.as_deref(), &time)
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
        #[cfg(target_os = "linux")]
        Source::Agent(m) if m.kind == "emergency" => tracing::warn!(
            source = "agent",
            slot = m.slot.unwrap_or(0),
            "node key unlocked via key agent by emergency code; this code is now burned"
        ),
        #[cfg(target_os = "linux")]
        Source::Agent(m) => tracing::info!(
            source = "agent",
            kind = %m.kind,
            device = %m.label,
            device_id = %m.device_id,
            grants_issued = m.grants_issued,
            grants_erased = m.grants_erased,
            "node key unlocked via key agent"
        ),
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

    #[cfg(unix)]
    #[test]
    fn operator_key_file_mode_gates_boot() {
        use std::os::unix::fs::PermissionsExt as _;
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        let ks = tempfile::tempdir().unwrap();
        let st = tempfile::tempdir().unwrap();
        let kd = tempfile::tempdir().unwrap();
        let key = kd.path().join("node.key");
        std::fs::write(&key, operator_key_text()).unwrap();
        let mut cfg = cfg_for(ks.path(), st.path());
        cfg.crypto.node_key_file = key.to_string_lossy().into_owned();

        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = resolve(&cfg, ks.path())
            .err()
            .expect("loose mode must fail");
        assert!(err.to_string().contains("mode 0644"), "{err}");

        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o400)).unwrap();
        let r = resolve(&cfg, ks.path()).expect("0400 key resolves");
        assert!(matches!(r.source, Source::Operator));
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

    #[test]
    fn key_helper_flags_are_mutually_exclusive() {
        use crate::cli::Cli;
        let ok = |args: &[&str]| {
            Cli::try_parse_from(std::iter::once("y2qd").chain(args.iter().copied()))
        };
        assert!(ok(&["--key-serve"]).is_ok());
        assert!(ok(&["--key-sweep"]).is_ok());
        assert!(ok(&["--key-arm", "--prompt-pin", "--prompt-passcode"]).is_ok());
        assert!(ok(&["--key-serve", "--key-sweep"]).is_err());
        assert!(ok(&["--key-arm", "--key-serve"]).is_err());
        assert!(ok(&["--key-sweep", "--rotate-node-key"]).is_err());
        assert!(ok(&["--key-serve", "--upgrade-container-headers"]).is_err());
        assert!(ok(&["--prompt-pin"]).is_err());
        assert!(ok(&["--key-agent"]).is_err());
    }

    #[cfg(all(target_os = "linux", feature = "devices"))]
    #[test]
    fn passcode_without_a_terminal_errors_and_emergency_code_comes_from_env() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_env();
        let p = DaemonPinProvider::with_tty_probe(|| false).unwrap();
        let err = p.passcode("home-1").err().unwrap();
        assert!(
            err.to_string().contains("no passcode source is available"),
            "{err}"
        );
        assert!(p.emergency_code().unwrap().is_none());
        set_env("Y2QD_EMERGENCY_KEY", "code-from-env");
        assert_eq!(
            p.emergency_code().unwrap().unwrap().as_str(),
            "code-from-env"
        );
        clear_env();
    }

    #[cfg(all(target_os = "linux", feature = "devices"))]
    #[test]
    fn unlock_key_round_trips() {
        let buf = SecretBuf::from_slice(&[7u8; 32]).unwrap();
        assert_eq!(&unlock_key(&buf).unwrap()[..], &[7u8; 32][..]);
    }
}
