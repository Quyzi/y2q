//! Host compatibility scan: read-only probes that run before the first screen,
//! and the pure rules that turn them into the findings list.

use std::path::Path;

use super::existing::{ExistingInstall, Tri};
use super::sys;

/// Secure Boot state, mirrored from the device backend so rules and tests do
/// not depend on the `devices` feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// `Disabled` is constructed only by the device-backed Secure Boot probe.
#[cfg_attr(not(feature = "devices"), allow(dead_code))]
pub enum SecureBoot {
    Enabled,
    Disabled,
    Unknown,
}

pub const TPM_NODE: &str = "/dev/tpmrm0";
/// Soft `RLIMIT_MEMLOCK` below which the scan mentions guarded memory.
const MEMLOCK_NOTE_BYTES: u64 = 64 * 1024 * 1024;

/// Secret-bearing variables setup refuses to start with.
pub const REFUSED_ENV: [&str; 4] = [
    "Y2QD_NODE_KEY",
    "Y2QD_NEW_NODE_KEY",
    "Y2QD_EMERGENCY_KEY",
    "Y2QD_FIDO2_PIN",
];

#[derive(Debug, Clone)]
pub struct Facts {
    pub euid: u32,
    pub kernel: Option<(u32, u32)>,
    pub cpus: usize,
    pub mem_total_kib: Option<u64>,
    pub memlock_soft: Option<u64>,
    pub memfd_secret: Result<(), String>,
    pub io_uring: Result<(), String>,
    pub systemd: bool,
    pub tpm_node: bool,
    /// `Some` when the node exists: whether it opens read/write.
    pub tpm_access: Option<Result<(), String>>,
    pub built_with_devices: bool,
    /// `tpm2::probe` result; only when the node is present and opens.
    pub tpm_probe: Option<Result<(), String>>,
    pub fido2: Option<Result<Vec<String>, String>>,
    pub secure_boot: Option<SecureBoot>,
    /// Names of `Y2QD_*` variables set (excluding the refused secret ones).
    pub env_overrides: Vec<String>,
}

impl Facts {
    /// A TPM answered the probe.
    pub fn tpm_usable(&self) -> bool {
        matches!(self.tpm_probe, Some(Ok(())))
    }

    pub fn fido2_present(&self) -> bool {
        matches!(&self.fido2, Some(Ok(v)) if !v.is_empty())
    }

    pub fn fido2_count(&self) -> usize {
        match &self.fido2 {
            Some(Ok(v)) => v.len(),
            _ => 0,
        }
    }
}

/// Run every probe. `tpm_tcti` is the existing config's value, else the default.
pub fn collect(tpm_tcti: Option<&str>) -> Facts {
    let _ = tpm_tcti; // used only by the devices build
    let tpm_node = Path::new(TPM_NODE).exists();
    let tpm_access = tpm_node.then(|| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(TPM_NODE)
            .map(drop)
            .map_err(|e| e.to_string())
    });
    let mut env_overrides: Vec<String> = std::env::vars_os()
        .filter_map(|(k, _)| k.into_string().ok())
        .filter(|k| k.starts_with("Y2QD_") && !REFUSED_ENV.contains(&k.as_str()))
        .collect();
    env_overrides.sort();

    #[allow(unused_mut)]
    let mut facts = Facts {
        euid: sys::euid(),
        kernel: sys::kernel_release().and_then(|r| sys::parse_kernel(&r)),
        cpus: std::thread::available_parallelism().map_or(1, usize::from),
        mem_total_kib: sys::meminfo_total_kib(),
        memlock_soft: sys::rlimit_memlock(),
        memfd_secret: sys::probe_memfd_secret(),
        io_uring: sys::probe_io_uring(),
        systemd: Path::new("/run/systemd/system").exists(),
        tpm_node,
        tpm_access,
        built_with_devices: cfg!(feature = "devices"),
        tpm_probe: None,
        fido2: None,
        secure_boot: None,
        env_overrides,
    };
    #[cfg(feature = "devices")]
    {
        use y2q_core::crypto::devices::{DEFAULT_TPM_TCTI, fido2, tpm2};
        let _quiet = sys::silence_stderr();
        if matches!(facts.tpm_access, Some(Ok(()))) {
            facts.tpm_probe =
                Some(tpm2::probe(tpm_tcti.unwrap_or(DEFAULT_TPM_TCTI)).map_err(|e| e.to_string()));
        }
        facts.fido2 = Some(fido2::list_authenticators().map_err(|e| e.to_string()));
        facts.secure_boot = Some(match tpm2::secure_boot_state() {
            tpm2::SecureBootState::Enabled => SecureBoot::Enabled,
            tpm2::SecureBootState::Disabled => SecureBoot::Disabled,
            tpm2::SecureBootState::Unknown => SecureBoot::Unknown,
        });
    }
    facts
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Info,
    Warn,
    Fail,
}

impl Level {
    pub fn glyph(self) -> &'static str {
        match self {
            Level::Ok => "[ok]",
            Level::Info => "[i]",
            Level::Warn => "[!]",
            Level::Fail => "[x]",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Hardware,
    Software,
    Existing,
}

impl Group {
    pub fn title(self) -> &'static str {
        match self {
            Group::Hardware => "Hardware",
            Group::Software => "Software",
            Group::Existing => "Existing install",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: &'static str,
    pub group: Group,
    pub level: Level,
    pub title: String,
    pub detail: String,
}

fn f(
    id: &'static str,
    group: Group,
    level: Level,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> Finding {
    Finding {
        id,
        group,
        level,
        title: title.into(),
        detail: detail.into(),
    }
}

/// The scan rules. Pure: unit-tested on hand-built `Facts`.
pub fn findings(facts: &Facts, existing: &ExistingInstall) -> Vec<Finding> {
    use Group::{Existing, Hardware, Software};
    use Level::{Fail, Info, Ok, Warn};
    let mut out = Vec::new();

    // --- Hardware ---
    out.push(f(
        "cpus",
        Hardware,
        Ok,
        format!("{} CPU(s)", facts.cpus),
        "",
    ));
    match facts.mem_total_kib {
        Some(k) => out.push(f(
            "memory",
            Hardware,
            Ok,
            format!("{} MiB RAM", k / 1024),
            "",
        )),
        None => out.push(f("memory", Hardware, Info, "RAM size unknown", "")),
    }
    match &facts.memfd_secret {
        Result::Ok(()) => out.push(f(
            "memfd_secret",
            Hardware,
            Ok,
            "guarded memory (memfd_secret) works",
            "",
        )),
        Err(e) => out.push(f(
            "memfd_secret",
            Hardware,
            Warn,
            "guarded memory (memfd_secret) is unavailable",
            format!(
                "{e}. The daemon refuses to start unless [server] allow_unprotected_memory = true; the Security step offers that toggle."
            ),
        )),
    }
    if let Some(limit) = facts.memlock_soft
        && limit < MEMLOCK_NOTE_BYTES
    {
        out.push(f(
            "memlock",
            Hardware,
            Info,
            format!("RLIMIT_MEMLOCK is {} KiB for this shell", limit / 1024),
            "The shipped systemd units set LimitMEMLOCK=infinity; this only affects a foreground run.",
        ));
    }
    match (&facts.tpm_node, &facts.tpm_access) {
        (false, _) => out.push(f(
            "tpm_node",
            Hardware,
            Warn,
            format!("no TPM resource manager at {}", super::scan::TPM_NODE),
            "TPM home devices are unavailable on this host.",
        )),
        (true, Some(Err(e))) => out.push(f(
            "tpm_node",
            Hardware,
            Warn,
            format!("no permission on {}", super::scan::TPM_NODE),
            format!("{e}. Run as a user in the tss group (or root) to use the TPM."),
        )),
        (true, _) => out.push(f(
            "tpm_node",
            Hardware,
            Ok,
            format!("{} present", super::scan::TPM_NODE),
            "",
        )),
    }
    match &facts.tpm_probe {
        Some(Result::Ok(())) => out.push(f("tpm_probe", Hardware, Ok, "TPM answers", "")),
        Some(Err(e)) => out.push(f(
            "tpm_probe",
            Hardware,
            Warn,
            "TPM did not answer",
            e.clone(),
        )),
        None => {}
    }
    match &facts.secure_boot {
        Some(SecureBoot::Enabled) => {
            out.push(f("secure_boot", Hardware, Ok, "Secure Boot is enabled", ""))
        }
        Some(SecureBoot::Disabled) => out.push(f(
            "secure_boot",
            Hardware,
            Warn,
            "Secure Boot is disabled",
            "A PCR 7 TPM policy is then satisfiable by any bootable medium.",
        )),
        Some(SecureBoot::Unknown) => out.push(f(
            "secure_boot",
            Hardware,
            Warn,
            "Secure Boot state is unknown",
            "Non-UEFI boot, or efivarfs is unavailable.",
        )),
        None => {}
    }
    match &facts.fido2 {
        Some(Result::Ok(v)) if v.len() == 1 => out.push(f(
            "fido2",
            Hardware,
            Ok,
            "1 FIDO2 authenticator attached",
            "",
        )),
        Some(Result::Ok(v)) if v.is_empty() => out.push(f(
            "fido2",
            Hardware,
            Info,
            "no FIDO2 authenticator attached",
            "",
        )),
        Some(Result::Ok(v)) => out.push(f(
            "fido2",
            Hardware,
            Info,
            format!("{} FIDO2 authenticators attached", v.len()),
            "Enrolling one needs its HID path to be chosen explicitly.",
        )),
        Some(Err(e)) => out.push(f(
            "fido2",
            Hardware,
            Info,
            "FIDO2 enumeration failed",
            e.clone(),
        )),
        None => {}
    }

    // --- Software ---
    match facts.kernel {
        Some((maj, min)) => out.push(f("kernel", Software, Ok, format!("Linux {maj}.{min}"), "")),
        None => out.push(f("kernel", Software, Info, "kernel version unknown", "")),
    }
    match &facts.io_uring {
        Result::Ok(()) => out.push(f("io_uring", Software, Ok, "io_uring is available", "")),
        Err(e) => out.push(f(
            "io_uring",
            Software,
            Warn,
            "io_uring is unavailable",
            format!("{e}. The Storage step keeps the filesystem backend."),
        )),
    }
    out.push(if facts.systemd {
        f("systemd", Software, Ok, "systemd is running", "")
    } else {
        f(
            "systemd",
            Software,
            Info,
            "systemd is not running",
            "Unit installation still writes files, but nothing here can start them.",
        )
    });
    if !facts.built_with_devices {
        out.push(f(
            "devices_build",
            Software,
            Info,
            "TPM/FIDO2 authority unavailable; rebuild with `--features devices`",
            "The device-registry authority is disabled in this build.",
        ));
    }
    if facts.euid == 0 {
        out.push(f("root", Software, Info, "running as root", ""));
    } else {
        out.push(f(
            "root",
            Software,
            Info,
            "not root: ownership fixes and system-wide unit install are limited",
            format!("Files are owned by uid {}.", facts.euid),
        ));
    }
    if !facts.env_overrides.is_empty() {
        out.push(f(
            "env",
            Software,
            Warn,
            format!(
                "Y2QD_* variables are set: {}",
                facts.env_overrides.join(", ")
            ),
            "They override the config file at runtime; setup edits the file only.",
        ));
    }

    // --- Existing install ---
    if existing.config_exists {
        match &existing.config_parse {
            Result::Ok(_) => out.push(f("config", Existing, Info, "a config file exists", "")),
            Err(e) => out.push(f(
                "config",
                Existing,
                Fail,
                "the existing config file does not parse",
                e.clone(),
            )),
        }
    }
    if existing.keystore_json {
        out.push(f(
            "keystore_json",
            Existing,
            Info,
            "keystore.json exists",
            "A node key is already in use; a new node key would orphan existing data.",
        ));
    }
    if existing.devices_json {
        if facts.built_with_devices {
            out.push(f("devices_json", Existing, Info, "devices.json exists", ""));
        } else {
            out.push(f(
                "devices_json",
                Existing,
                Fail,
                "devices.json exists but this build has no device support",
                "The daemon refuses a device registry it cannot read; rebuild with `--features devices`.",
            ));
        }
    }
    if existing.users_redb {
        out.push(f("users_redb", Existing, Info, "users.redb exists", ""));
    }
    if existing.storage_nonempty {
        out.push(f(
            "storage",
            Existing,
            Info,
            "the data directory is not empty",
            "",
        ));
    }
    match existing.daemon_running {
        Tri::Yes => out.push(f(
            "daemon",
            Existing,
            Warn,
            "y2qd is running against this keystore",
            "Stop it before applying.",
        )),
        Tri::Unknown => out.push(f(
            "daemon",
            Existing,
            Info,
            "cannot tell whether y2qd is running",
            "The keystore lock file is not readable by this user.",
        )),
        Tri::No => {}
    }
    out
}

#[cfg(test)]
pub fn test_facts() -> Facts {
    Facts {
        euid: 1000,
        kernel: Some((6, 8)),
        cpus: 8,
        mem_total_kib: Some(16 * 1024 * 1024),
        memlock_soft: Some(u64::MAX),
        memfd_secret: Result::Ok(()),
        io_uring: Result::Ok(()),
        systemd: true,
        tpm_node: false,
        tpm_access: None,
        built_with_devices: true,
        tpm_probe: None,
        fido2: None,
        secure_boot: None,
        env_overrides: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has(v: &[Finding], id: &str, level: Level) -> bool {
        v.iter().any(|x| x.id == id && x.level == level)
    }

    #[test]
    fn clean_host_has_no_warnings_or_failures() {
        let mut facts = test_facts();
        facts.tpm_node = true;
        facts.tpm_access = Some(Result::Ok(()));
        facts.tpm_probe = Some(Result::Ok(()));
        facts.secure_boot = Some(SecureBoot::Enabled);
        facts.fido2 = Some(Result::Ok(vec!["/dev/hidraw3".into()]));
        let v = findings(&facts, &ExistingInstall::empty());
        assert!(v.iter().all(|x| x.level <= Level::Info), "{v:?}");
        assert!(has(&v, "tpm_probe", Level::Ok));
    }

    #[test]
    fn missing_capabilities_warn() {
        let mut facts = test_facts();
        facts.memfd_secret = Err("ENOSYS".into());
        facts.io_uring = Err("EPERM".into());
        facts.secure_boot = Some(SecureBoot::Disabled);
        let v = findings(&facts, &ExistingInstall::empty());
        assert!(has(&v, "memfd_secret", Level::Warn));
        assert!(has(&v, "io_uring", Level::Warn));
        assert!(has(&v, "secure_boot", Level::Warn));
        assert!(has(&v, "tpm_node", Level::Warn));
    }

    #[test]
    fn tpm_node_without_permission_is_distinguished() {
        let mut facts = test_facts();
        facts.tpm_node = true;
        facts.tpm_access = Some(Err("Permission denied".into()));
        let v = findings(&facts, &ExistingInstall::empty());
        let row = v.iter().find(|x| x.id == "tpm_node").unwrap();
        assert_eq!(row.level, Level::Warn);
        assert!(row.title.contains("no permission"));
    }

    #[test]
    fn low_memlock_is_info_only() {
        let mut facts = test_facts();
        facts.memlock_soft = Some(8 * 1024 * 1024);
        let v = findings(&facts, &ExistingInstall::empty());
        assert!(has(&v, "memlock", Level::Info));
    }

    #[test]
    fn fido2_counts() {
        let mut facts = test_facts();
        facts.fido2 = Some(Result::Ok(vec![]));
        assert!(has(
            &findings(&facts, &ExistingInstall::empty()),
            "fido2",
            Level::Info
        ));
        facts.fido2 = Some(Result::Ok(vec!["a".into(), "b".into()]));
        assert!(has(
            &findings(&facts, &ExistingInstall::empty()),
            "fido2",
            Level::Info
        ));
        facts.fido2 = Some(Result::Ok(vec!["a".into()]));
        assert!(has(
            &findings(&facts, &ExistingInstall::empty()),
            "fido2",
            Level::Ok
        ));
    }

    #[test]
    fn devices_json_without_device_support_fails() {
        let mut facts = test_facts();
        facts.built_with_devices = false;
        let mut ex = ExistingInstall::empty();
        ex.devices_json = true;
        let v = findings(&facts, &ex);
        assert!(has(&v, "devices_json", Level::Fail));
        assert!(has(&v, "devices_build", Level::Info));
        facts.built_with_devices = true;
        assert!(has(&findings(&facts, &ex), "devices_json", Level::Info));
    }

    #[test]
    fn root_and_env_and_daemon_rows() {
        let mut facts = test_facts();
        facts.euid = 0;
        facts.env_overrides = vec!["Y2QD_SERVER__PORT".into()];
        let mut ex = ExistingInstall::empty();
        ex.daemon_running = Tri::Yes;
        let v = findings(&facts, &ex);
        let root = v.iter().find(|x| x.id == "root").unwrap();
        assert_eq!(root.title, "running as root");
        assert!(has(&v, "env", Level::Warn));
        assert!(
            v.iter()
                .any(|x| x.id == "env" && x.title.contains("Y2QD_SERVER__PORT"))
        );
        assert!(has(&v, "daemon", Level::Warn));
    }

    #[test]
    fn unparsable_config_is_a_failure() {
        let mut ex = ExistingInstall::empty();
        ex.config_exists = true;
        ex.config_parse = Err("line 3".into());
        assert!(has(&findings(&test_facts(), &ex), "config", Level::Fail));
    }
}
