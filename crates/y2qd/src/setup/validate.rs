//! Per-step validators and the `Probes` seam.
//!
//! An **error** blocks `Tab` only for what the daemon or core would reject; a
//! stricter policy is a **warning**. All I/O the validators need goes through
//! [`Probes`], so every rule is unit-tested with [`FakeProbes`].

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::answers::{
    Answers, Authority, AuthorityContext, FirstKind, KeepKind, KeySource, NewRegistryAnswers,
    RoughtimeServerAnswer, TlsAnswers, is_within, normalize,
};
use super::existing::Tri;
use super::scan::{Facts, SecureBoot};
use super::sys::User;
use super::units::clean_param;

/// Wizard steps in order; also names the step an [`Issue`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Step {
    Scan,
    ExistingWarning,
    Paths,
    Network,
    S3,
    StorageLogging,
    Security,
    Authority,
    System,
    Review,
}

impl Step {
    pub fn title(self) -> &'static str {
        match self {
            Step::Scan => "Scan",
            Step::ExistingWarning => "Existing installation",
            Step::Paths => "Paths",
            Step::Network => "Network",
            Step::S3 => "S3 gateway",
            Step::StorageLogging => "Storage and logging",
            Step::Security => "Security",
            Step::Authority => "Node-key authority",
            Step::System => "System",
            Step::Review => "Review",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sev {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub step: Step,
    pub field: &'static str,
    pub sev: Sev,
    pub msg: String,
}

impl Issue {
    pub fn is_error(&self) -> bool {
        self.sev == Sev::Error
    }
}

pub fn has_errors(issues: &[Issue]) -> bool {
    issues.iter().any(Issue::is_error)
}

// --- probes ------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
pub struct DirInfo {
    pub exists: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub uid: u32,
    pub mode: u32,
    pub writable: bool,
    pub tmpfs: bool,
    pub device: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrySummary {
    pub permanent_away: bool,
    pub has_home: bool,
    pub home_has_second_factor: bool,
}

/// Every probe the validators (and apply preflight) use.
pub trait Probes {
    fn bind(&self, host: &str, port: u16) -> Result<(), String>;
    fn lookup_user(&self, name: &str) -> Option<User>;
    fn lookup_uid(&self, uid: u32) -> Option<User>;
    fn lookup_group(&self, name: &str) -> Option<u32>;
    fn group_name(&self, gid: u32) -> Option<String>;
    fn user_in_group(&self, user: &str, group: &str) -> bool;
    fn tls_check(
        &self,
        cert: &Path,
        key: &Path,
        client_ca: Option<&Path>,
        pq: bool,
    ) -> Result<(), String>;
    fn readable_by(&self, path: &Path, uid: u32, gid: u32) -> bool;
    fn dir_info(&self, path: &Path) -> DirInfo;
    fn path_exists(&self, path: &Path) -> bool;
    fn dir_nonempty(&self, path: &Path) -> bool;
    fn file_owner(&self, path: &Path) -> Option<u32>;
    fn free_bytes(&self, path: &Path) -> Option<u64>;
    fn daemon_running(&self, keystore_dir: &Path) -> Tri;
    fn registry_summary(&self, keystore_dir: &Path) -> Option<RegistrySummary>;
    /// `load_node_key_file` Ok, plus `verify_node_key` against `keystore_dir`
    /// when it holds a `keystore.json`.
    fn node_key_ok(&self, file: &str, keystore_dir: &Path) -> Result<(), String>;
    fn tpm_probe(&self, tcti: &str) -> Result<(), String>;
    fn attest(
        &self,
        servers: &[RoughtimeServerAnswer],
        timeout_ms: u64,
        min_responses: u8,
    ) -> Result<(u64, usize, usize), String>;
    fn fido2_list(&self) -> Result<Vec<String>, String>;
    fn secure_boot(&self) -> SecureBoot;
}

pub struct RealProbes;

impl Probes for RealProbes {
    fn bind(&self, host: &str, port: u16) -> Result<(), String> {
        std::net::TcpListener::bind((host, port))
            .map(drop)
            .map_err(|e| e.to_string())
    }

    fn lookup_user(&self, name: &str) -> Option<User> {
        super::sys::lookup_user(name)
    }

    fn lookup_uid(&self, uid: u32) -> Option<User> {
        super::sys::lookup_uid(uid)
    }

    fn lookup_group(&self, name: &str) -> Option<u32> {
        super::sys::lookup_group(name)
    }

    fn group_name(&self, gid: u32) -> Option<String> {
        super::sys::group_name(gid)
    }

    fn user_in_group(&self, user: &str, group: &str) -> bool {
        super::sys::user_in_group(user, group)
    }

    fn tls_check(
        &self,
        cert: &Path,
        key: &Path,
        client_ca: Option<&Path>,
        pq: bool,
    ) -> Result<(), String> {
        crate::tls::build_server_config(cert, key, client_ca, pq)
            .map(drop)
            .map_err(|e| e.to_string())
    }

    fn readable_by(&self, path: &Path, uid: u32, gid: u32) -> bool {
        let Ok(st) = super::sys::stat(path) else {
            return false;
        };
        let perm = st.perm();
        if st.uid == uid {
            perm & 0o400 != 0
        } else if st.gid == gid
            || super::sys::lookup_uid(uid).is_some_and(|u| {
                super::sys::group_name(st.gid)
                    .is_some_and(|g| super::sys::user_in_group(&u.name, &g))
            })
        {
            perm & 0o040 != 0
        } else {
            perm & 0o004 != 0
        }
    }

    fn dir_info(&self, path: &Path) -> DirInfo {
        let Ok(l) = super::sys::lstat(path) else {
            return DirInfo::default();
        };
        let followed = super::sys::stat(path).ok();
        let st = followed.unwrap_or(l);
        let writable = {
            use std::os::unix::ffi::OsStrExt;
            std::ffi::CString::new(path.as_os_str().as_bytes()).is_ok_and(|c| {
                // SAFETY: `c` is a valid NUL-terminated path for the call's duration.
                unsafe { libc::access(c.as_ptr(), libc::W_OK | libc::X_OK) == 0 }
            })
        };
        DirInfo {
            exists: true,
            is_dir: st.is_dir(),
            is_symlink: l.is_symlink(),
            uid: st.uid,
            mode: st.perm(),
            writable,
            tmpfs: super::sys::is_tmpfs(path),
            device: st.dev,
        }
    }

    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn dir_nonempty(&self, path: &Path) -> bool {
        std::fs::read_dir(path).is_ok_and(|mut d| d.next().is_some())
    }

    fn file_owner(&self, path: &Path) -> Option<u32> {
        super::sys::stat(path).ok().map(|s| s.uid)
    }

    fn free_bytes(&self, path: &Path) -> Option<u64> {
        super::sys::free_bytes(&super::sys::nearest_existing_ancestor(path)).ok()
    }

    fn daemon_running(&self, keystore_dir: &Path) -> Tri {
        super::existing::daemon_running_probe(keystore_dir)
    }

    fn registry_summary(&self, keystore_dir: &Path) -> Option<RegistrySummary> {
        registry_summary_impl(keystore_dir)
    }

    fn node_key_ok(&self, file: &str, keystore_dir: &Path) -> Result<(), String> {
        let nk = y2q_core::crypto::node_key::load_node_key_file(file).map_err(|e| e.to_string())?;
        if keystore_dir.join("keystore.json").exists() {
            y2q_core::crypto::keystore::verify_node_key(keystore_dir, &nk)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn tpm_probe(&self, tcti: &str) -> Result<(), String> {
        #[cfg(feature = "devices")]
        {
            let _quiet = super::sys::silence_stderr();
            y2q_core::crypto::devices::tpm2::probe(tcti).map_err(|e| e.to_string())
        }
        #[cfg(not(feature = "devices"))]
        {
            let _ = tcti;
            Err(NO_DEVICES.to_owned())
        }
    }

    fn attest(
        &self,
        servers: &[RoughtimeServerAnswer],
        timeout_ms: u64,
        min_responses: u8,
    ) -> Result<(u64, usize, usize), String> {
        #[cfg(feature = "devices")]
        {
            use y2q_core::crypto::devices::{RoughtimeConfig, RoughtimeServer, roughtime};
            let cfg = RoughtimeConfig {
                servers: servers
                    .iter()
                    .map(|s| RoughtimeServer {
                        name: s.name.clone(),
                        addr: s.addr.clone(),
                        public_key_b64: s.public_key_b64.clone(),
                    })
                    .collect(),
                timeout_ms,
                min_responses,
            };
            let _quiet = super::sys::silence_stderr();
            roughtime::attest_with(&cfg, &mut |_| {}).map_err(|e| e.to_string())
        }
        #[cfg(not(feature = "devices"))]
        {
            let _ = (servers, timeout_ms, min_responses);
            Err(NO_DEVICES.to_owned())
        }
    }

    fn fido2_list(&self) -> Result<Vec<String>, String> {
        #[cfg(feature = "devices")]
        {
            let _quiet = super::sys::silence_stderr();
            y2q_core::crypto::devices::fido2::list_authenticators().map_err(|e| e.to_string())
        }
        #[cfg(not(feature = "devices"))]
        {
            Err(NO_DEVICES.to_owned())
        }
    }

    fn secure_boot(&self) -> SecureBoot {
        #[cfg(feature = "devices")]
        {
            use y2q_core::crypto::devices::tpm2::{SecureBootState, secure_boot_state};
            match secure_boot_state() {
                SecureBootState::Enabled => SecureBoot::Enabled,
                SecureBootState::Disabled => SecureBoot::Disabled,
                SecureBootState::Unknown => SecureBoot::Unknown,
            }
        }
        #[cfg(not(feature = "devices"))]
        {
            SecureBoot::Unknown
        }
    }
}

#[cfg(not(feature = "devices"))]
const NO_DEVICES: &str = "this build has no device support";

#[cfg(feature = "devices")]
fn registry_summary_impl(dir: &Path) -> Option<RegistrySummary> {
    use y2q_core::crypto::devices::{DeviceKind, registry};
    let reg = registry::load(dir).ok()?;
    let homes: Vec<_> = reg
        .devices
        .iter()
        .filter(|d| d.kind == DeviceKind::Tpm2)
        .collect();
    Some(RegistrySummary {
        permanent_away: reg.permanent_away,
        has_home: !homes.is_empty(),
        home_has_second_factor: homes.iter().any(|d| d.home_factor.is_some()),
    })
}

#[cfg(not(feature = "devices"))]
fn registry_summary_impl(_dir: &Path) -> Option<RegistrySummary> {
    None
}

/// `secure_boot_problem` wording lives with the caller.
fn secure_boot_problem(state: SecureBoot, pcrs: &[u8], allow_off: bool) -> Option<&'static str> {
    #[cfg(feature = "devices")]
    {
        use y2q_core::crypto::devices::tpm2::{self, SecureBootState};
        let s = match state {
            SecureBoot::Enabled => SecureBootState::Enabled,
            SecureBoot::Disabled => SecureBootState::Disabled,
            SecureBoot::Unknown => SecureBootState::Unknown,
        };
        tpm2::secure_boot_problem(s, pcrs, allow_off)
    }
    #[cfg(not(feature = "devices"))]
    {
        let _ = (state, pcrs, allow_off);
        None
    }
}

/// Registry label rule (printable ASCII, 1..=64 bytes); no-op without device support.
pub fn fido_label_problem(label: &str) -> Result<(), String> {
    #[cfg(feature = "devices")]
    {
        y2q_core::crypto::devices::registry::valid_label(label)
    }
    #[cfg(not(feature = "devices"))]
    {
        let _ = label;
        Ok(())
    }
}

// --- probe cache -------------------------------------------------------------

const CACHE_TTL: Duration = Duration::from_secs(120);

/// Results of the slow device probes, keyed on their inputs. `c` ("check now")
/// refreshes entries; `Tab` and preflight reuse a fresh one.
type Cached<T> = RefCell<HashMap<String, (Instant, Result<T, String>)>>;

#[derive(Default)]
pub struct ProbeCache {
    tpm: Cached<()>,
    attest: Cached<(u64, usize, usize)>,
}

impl ProbeCache {
    pub fn tpm(&self, probes: &dyn Probes, tcti: &str, force: bool) -> Result<(), String> {
        if !force
            && let Some((at, r)) = self.tpm.borrow().get(tcti)
            && at.elapsed() < CACHE_TTL
        {
            return r.clone();
        }
        let r = probes.tpm_probe(tcti);
        self.tpm
            .borrow_mut()
            .insert(tcti.to_owned(), (Instant::now(), r.clone()));
        r
    }

    pub fn attest(
        &self,
        probes: &dyn Probes,
        servers: &[RoughtimeServerAnswer],
        timeout_ms: u64,
        min_responses: u8,
        force: bool,
    ) -> Result<(u64, usize, usize), String> {
        let key = format!(
            "{timeout_ms}/{min_responses}/{}",
            servers
                .iter()
                .map(|s| format!("{}|{}|{}", s.name, s.addr, s.public_key_b64))
                .collect::<Vec<_>>()
                .join(",")
        );
        if !force
            && let Some((at, r)) = self.attest.borrow().get(&key)
            && at.elapsed() < CACHE_TTL
        {
            return r.clone();
        }
        let r = probes.attest(servers, timeout_ms, min_responses);
        self.attest
            .borrow_mut()
            .insert(key, (Instant::now(), r.clone()));
        r
    }
}

/// Everything validators read besides the answers.
pub struct Ctx<'a> {
    pub facts: &'a Facts,
    pub probes: &'a dyn Probes,
    pub cache: &'a ProbeCache,
    /// Force fresh device probes (the `c` key).
    pub force_probe: bool,
}

// --- helpers -----------------------------------------------------------------

/// Directories that must never be a data/keystore/state/unit leaf. A UX guard;
/// the root-walk at preflight is the real check.
pub const PROTECTED_ROOTS: [&str; 19] = [
    "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc", "/root",
    "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var", "/var/lib",
];

fn is_protected(p: &Path) -> bool {
    let n = normalize(p);
    PROTECTED_ROOTS.iter().any(|r| n == Path::new(r)) || n == Path::new("/var/tmp")
}

fn err(step: Step, field: &'static str, msg: impl Into<String>) -> Issue {
    Issue {
        step,
        field,
        sev: Sev::Error,
        msg: msg.into(),
    }
}

fn warn(step: Step, field: &'static str, msg: impl Into<String>) -> Issue {
    Issue {
        step,
        field,
        sev: Sev::Warning,
        msg: msg.into(),
    }
}

/// The unconditional character rule for a rendered path or identity.
fn chars(v: &mut Vec<Issue>, step: Step, field: &'static str, what: &str, value: &str) {
    if let Err(e) = clean_param(what, value) {
        v.push(err(step, field, e));
    }
}

fn abs_path(v: &mut Vec<Issue>, step: Step, field: &'static str, what: &str, value: &str) -> bool {
    if value.is_empty() {
        v.push(err(step, field, format!("{what} must not be empty")));
        return false;
    }
    let before = v.len();
    chars(v, step, field, what, value);
    if !Path::new(value).is_absolute() {
        v.push(err(step, field, format!("{what} must be an absolute path")));
    }
    v.len() == before
}

fn is_wildcard(host: &str) -> bool {
    host == "0.0.0.0" || host == "::" || host == "[::]"
}

fn valid_name(name: &str) -> bool {
    let mut it = name.chars();
    matches!(it.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && it.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn keystore_path(a: &Answers) -> PathBuf {
    PathBuf::from(&a.keystore_dir)
}

/// Facts about the *current* keystore directory.
pub fn authority_context(a: &Answers, cx: &Ctx) -> AuthorityContext {
    let ks = keystore_path(a);
    AuthorityContext {
        keystore_json: cx.probes.path_exists(&ks.join("keystore.json")),
        devices_json: cx.probes.path_exists(&ks.join("devices.json")),
        built_with_devices: cx.facts.built_with_devices,
    }
}

/// Setup would leave existing data unreadable: the keystore directory changed
/// (or is empty) while data exists. Needs an explicit acknowledgement.
pub fn orphan_risk(a: &Answers, cx: &Ctx) -> bool {
    let ks = keystore_path(a);
    if cx.probes.path_exists(&ks.join("keystore.json")) {
        return false;
    }
    let base_nonempty = cx.probes.dir_nonempty(Path::new(&a.base_path));
    let loaded_moved = a.loaded.keystore_dir.as_ref().is_some_and(|l| {
        normalize(Path::new(l)) != normalize(&ks)
            && cx.probes.path_exists(&Path::new(l).join("keystore.json"))
    });
    base_nonempty || loaded_moved
}

fn daemon_uid_gid(a: &Answers, cx: &Ctx) -> Option<(u32, u32)> {
    cx.probes
        .lookup_user(&a.daemon_user)
        .map(|u| (u.uid, u.gid))
}

// --- steps -------------------------------------------------------------------

pub fn all(a: &Answers, cx: &Ctx) -> Vec<Issue> {
    let mut v = Vec::new();
    for step in [
        Step::Paths,
        Step::Network,
        Step::S3,
        Step::StorageLogging,
        Step::Security,
        Step::Authority,
        Step::System,
    ] {
        v.extend(for_step(step, a, cx));
    }
    v
}

pub fn for_step(step: Step, a: &Answers, cx: &Ctx) -> Vec<Issue> {
    match step {
        Step::Paths => paths(a, cx),
        Step::Network => network(a, cx),
        Step::S3 => s3(a, cx),
        Step::StorageLogging => storage_logging(a, cx),
        Step::Security => security(a),
        Step::Authority => authority(a, cx),
        Step::System => system(a, cx),
        Step::Scan | Step::ExistingWarning | Step::Review => Vec::new(),
    }
}

pub fn paths(a: &Answers, cx: &Ctx) -> Vec<Issue> {
    const S: Step = Step::Paths;
    let mut v = Vec::new();
    chars(
        &mut v,
        S,
        "config_file",
        "config file path",
        &a.config_path.to_string_lossy(),
    );
    if let Some(idx) = &a.index_path {
        chars(&mut v, S, "base_path", "storage.index_path", idx);
    }
    let mut ok = [false; 2];
    for (i, (field, what, value)) in [
        ("base_path", "data directory", &a.base_path),
        ("keystore_dir", "keystore directory", &a.keystore_dir),
    ]
    .into_iter()
    .enumerate()
    {
        ok[i] = abs_path(&mut v, S, field, what, value);
        if !ok[i] {
            continue;
        }
        let p = Path::new(value);
        if is_protected(p) {
            v.push(err(
                S,
                field,
                format!("{what} must not be the system directory {value}; use a subdirectory"),
            ));
            continue;
        }
        let info = cx.probes.dir_info(p);
        if info.is_symlink {
            v.push(err(S, field, format!("{what} {value} is a symlink")));
        } else if info.exists && !info.is_dir {
            v.push(err(
                S,
                field,
                format!("{what} {value} exists and is not a directory"),
            ));
        }
        let anc = super::sys::nearest_existing_ancestor(p);
        let ai = cx.probes.dir_info(&anc);
        if !ai.is_dir {
            v.push(err(
                S,
                field,
                format!(
                    "{} is not a directory, so {value} cannot be created",
                    anc.display()
                ),
            ));
        } else if cx.facts.euid != 0 && !ai.writable && !info.exists {
            v.push(err(
                S,
                field,
                format!(
                    "cannot create {value}: {} is not writable by this user",
                    anc.display()
                ),
            ));
        }
        if info.tmpfs || (!info.exists && ai.tmpfs) {
            v.push(warn(
                S,
                field,
                format!("{value} is on tmpfs: data is lost at reboot"),
            ));
        }
    }
    if ok[0] && ok[1] {
        let (b, k) = (Path::new(&a.base_path), Path::new(&a.keystore_dir));
        if is_within(b, k) || is_within(k, b) {
            v.push(err(
                S,
                "keystore_dir",
                "the data and keystore directories must not be inside one another",
            ));
        }
        if orphan_risk(a, cx) && !a.ack_data_risk {
            v.push(err(
                S,
                "ack_data_risk",
                "setup does not move data: existing data would become unreadable under this keystore; tick the box to continue",
            ));
        }
        if let Some(free) = cx.probes.free_bytes(b)
            && free < 1024 * 1024 * 1024
        {
            v.push(warn(
                S,
                "base_path",
                format!("only {} MiB free on the data volume", free / (1024 * 1024)),
            ));
        }
    }
    v
}

fn tls_issues(
    v: &mut Vec<Issue>,
    step: Step,
    ids: [&'static str; 3],
    tls: &TlsAnswers,
    a: &Answers,
    cx: &Ctx,
) {
    if !tls.enabled {
        return;
    }
    let [cert_f, key_f, ca_f] = ids;
    let mut ok = true;
    for (f, what, val) in [
        (cert_f, "TLS certificate", &tls.cert_path),
        (key_f, "TLS private key", &tls.key_path),
    ] {
        if val.is_empty() {
            v.push(err(
                step,
                f,
                format!("{what} path is required when TLS is enabled"),
            ));
            ok = false;
        } else {
            chars(v, step, f, what, val);
        }
    }
    if !tls.client_ca_path.is_empty() {
        chars(v, step, ca_f, "client CA bundle", &tls.client_ca_path);
    }
    if !ok {
        return;
    }
    let ca = (!tls.client_ca_path.is_empty()).then(|| Path::new(&tls.client_ca_path));
    if let Err(e) = cx.probes.tls_check(
        Path::new(&tls.cert_path),
        Path::new(&tls.key_path),
        ca,
        tls.require_pq_kex,
    ) {
        v.push(err(step, cert_f, format!("TLS material is unusable: {e}")));
        return;
    }
    if cx.facts.euid == 0
        && let Some((uid, gid)) = daemon_uid_gid(a, cx)
        && !cx.probes.readable_by(Path::new(&tls.key_path), uid, gid)
    {
        v.push(warn(
            step,
            key_f,
            format!(
                "the daemon user '{}' cannot read the private key",
                a.daemon_user
            ),
        ));
    }
}

fn host_issues(
    v: &mut Vec<Issue>,
    step: Step,
    host_f: &'static str,
    port_f: &'static str,
    host: &str,
    port: u16,
    cx: &Ctx,
) {
    if host.is_empty() || host.chars().any(char::is_whitespace) {
        v.push(err(
            step,
            host_f,
            "listen address must be non-empty and contain no whitespace",
        ));
        return;
    }
    if port == 0 {
        v.push(warn(step, port_f, "port 0 binds a random port each start"));
    } else if let Err(e) = cx.probes.bind(host, port) {
        v.push(warn(
            step,
            port_f,
            format!("cannot bind {host}:{port} now: {e}"),
        ));
    }
}

pub fn network(a: &Answers, cx: &Ctx) -> Vec<Issue> {
    const S: Step = Step::Network;
    let mut v = Vec::new();
    host_issues(&mut v, S, "host", "port", &a.host, a.port, cx);
    tls_issues(
        &mut v,
        S,
        ["tls_cert", "tls_key", "tls_client_ca"],
        &a.tls,
        a,
        cx,
    );
    if !a.tls.enabled && !crate::config::host_is_loopback(&a.host) && !a.allow_insecure_bind {
        v.push(err(
            S,
            "allow_insecure_bind",
            "the daemon refuses to bind a non-loopback address without TLS; enable TLS, use a loopback address, or allow the insecure bind",
        ));
    }
    v
}

pub fn s3(a: &Answers, cx: &Ctx) -> Vec<Issue> {
    const S: Step = Step::S3;
    let mut v = Vec::new();
    if !a.s3_enabled {
        return v;
    }
    host_issues(&mut v, S, "s3_host", "s3_port", &a.s3_host, a.s3_port, cx);
    if a.s3_port == a.port
        && (a.s3_host == a.host || is_wildcard(&a.host) || is_wildcard(&a.s3_host))
    {
        v.push(err(
            S,
            "s3_port",
            "the S3 gateway needs its own port: it clashes with the HTTP listener",
        ));
    }
    if a.s3_region.trim().is_empty() {
        v.push(err(S, "s3_region", "region must not be empty"));
    }
    if a.s3_virtual_host_domain.starts_with('.') {
        v.push(err(
            S,
            "s3_vhost",
            "virtual-host domain must not start with a dot",
        ));
    }
    tls_issues(
        &mut v,
        S,
        ["s3_tls_cert", "s3_tls_key", "s3_tls_client_ca"],
        &a.s3_tls,
        a,
        cx,
    );
    if !a.s3_tls.enabled
        && !crate::config::host_is_loopback(&a.s3_host)
        && !a.s3_allow_insecure_bind
    {
        v.push(err(
            S,
            "s3_allow_insecure_bind",
            "the daemon refuses to bind the S3 gateway on a non-loopback address without TLS; enable TLS, use a loopback address, or allow the insecure bind",
        ));
    }
    v
}

pub fn storage_logging(a: &Answers, cx: &Ctx) -> Vec<Issue> {
    const S: Step = Step::StorageLogging;
    let mut v = Vec::new();
    if a.backend == "uring"
        && let Err(e) = &cx.facts.io_uring
    {
        v.push(err(
            S,
            "backend",
            format!("io_uring is unavailable here: {e}"),
        ));
    }
    if let Err(e) = tracing_subscriber::EnvFilter::try_new(&a.log_filter) {
        v.push(err(S, "log_filter", format!("not a valid log filter: {e}")));
    }
    v
}

pub fn security(a: &Answers) -> Vec<Issue> {
    const S: Step = Step::Security;
    let mut v = Vec::new();
    if a.default_ttl_seconds < 1 {
        v.push(err(S, "default_ttl", "must be at least 1 second"));
    }
    if a.default_ttl_seconds > a.max_ttl_seconds {
        v.push(err(
            S,
            "default_ttl",
            "the default TTL must not exceed the maximum TTL",
        ));
    }
    if a.max_failed_logins > 0 && a.lockout_seconds < 1 {
        v.push(err(
            S,
            "lockout",
            "lockout must be at least 1 second when logins can lock out",
        ));
    }
    if a.argon_t_cost < 1 {
        v.push(err(S, "argon_t", "iterations must be at least 1"));
    }
    if !(1..=255).contains(&a.argon_p_cost) {
        v.push(err(S, "argon_p", "lanes must be between 1 and 255"));
    }
    if a.argon_m_cost_kib < 8 * a.argon_p_cost.clamp(1, 255) {
        v.push(err(S, "argon_m", "memory must be at least 8 KiB per lane"));
    } else if a.argon_m_cost_kib < 19_456 {
        v.push(warn(
            S,
            "argon_m",
            "below 19456 KiB (19 MiB) weakens password hashing",
        ));
    }
    if !a.enforce_authorization {
        v.push(warn(
            S,
            "enforce_authz",
            "any authenticated user gets full access to every bucket and admin endpoint",
        ));
    }
    v
}

/// Key-file checks shared by every operator-key path (Generate, UseExisting,
/// adopt, Keep(Operator)).
fn operator_key_location(v: &mut Vec<Issue>, field: &'static str, file: &str, a: &Answers) {
    let p = Path::new(file);
    // A not-yet-existing file is located by its canonical parent.
    let located = if p.exists() {
        file.to_owned()
    } else {
        match (
            p.parent().and_then(|d| std::fs::canonicalize(d).ok()),
            p.file_name(),
        ) {
            (Some(parent), Some(name)) => parent.join(name).to_string_lossy().into_owned(),
            _ => file.to_owned(),
        }
    };
    if let Err(e) = y2q_core::crypto::node_key::check_node_key_location(
        &located,
        Path::new(&a.base_path),
        Path::new(&a.keystore_dir),
    ) {
        v.push(err(Step::Authority, field, e));
    }
}

fn existing_key_file_warnings(
    v: &mut Vec<Issue>,
    field: &'static str,
    file: &str,
    a: &Answers,
    cx: &Ctx,
) {
    const S: Step = Step::Authority;
    let info = cx.probes.dir_info(Path::new(file));
    if !info.exists {
        return;
    }
    let daemon_uid = daemon_uid_gid(a, cx).map(|(u, _)| u);
    if info.uid != 0 && Some(info.uid) != daemon_uid {
        v.push(warn(
            S,
            field,
            "key file is owned by neither the daemon user nor root",
        ));
    }
    let base = cx.probes.dir_info(Path::new(&a.base_path));
    if base.exists && info.device == base.device && info.device != 0 {
        v.push(warn(S, field, "the key file and the data share one volume"));
    }
}

pub fn authority(a: &Answers, cx: &Ctx) -> Vec<Issue> {
    const S: Step = Step::Authority;
    let mut v = Vec::new();
    let Some(auth) = &a.authority else {
        v.push(err(S, "authority", "choose a node-key authority"));
        return v;
    };
    let ctx = authority_context(a, cx);
    if let Some(k) = a
        .authority_kinds(&ctx)
        .iter()
        .find(|k| k.kind == auth.kind())
        && let Some(reason) = &k.reason
    {
        v.push(err(S, "authority", reason.clone()));
        return v;
    }
    let ks = keystore_path(a);
    let keystore_json = ctx.keystore_json;
    match auth {
        Authority::Keep(KeepKind::Operator) => {
            let file = &a.loaded.node_key_file;
            operator_key_location(&mut v, "authority", file, a);
            if let Err(e) = cx.probes.node_key_ok(file, &ks) {
                v.push(err(
                    S,
                    "authority",
                    format!("the configured node key file is unusable: {e}"),
                ));
            }
            existing_key_file_warnings(&mut v, "authority", file, a, cx);
        }
        Authority::Keep(KeepKind::Registry) => registry_group(&mut v, a, cx),
        Authority::FinishMigration { ack_adopted } => {
            if !ack_adopted {
                v.push(err(
                    S,
                    "ack_adopted",
                    "confirm that this registry was created by adopting this key file",
                ));
            }
            if let Err(e) = cx.probes.node_key_ok(&a.loaded.node_key_file, &ks) {
                v.push(err(
                    S,
                    "authority",
                    format!("the configured node key file is unusable: {e}"),
                ));
            }
            registry_group(&mut v, a, cx);
        }
        Authority::OperatorKey { mode, file } => {
            if abs_path(&mut v, S, "key_file", "key file", file) {
                operator_key_location(&mut v, "key_file", file, a);
                if a.install_units
                    && ["/home", "/root", "/run/user"]
                        .iter()
                        .any(|p| normalize(Path::new(file)).starts_with(p))
                {
                    v.push(err(
                        S,
                        "key_file",
                        "units run with ProtectHome=true: the key file must not be under /home, /root or /run/user",
                    ));
                }
                match mode {
                    KeySource::Generate => {
                        if keystore_json || ctx.devices_json {
                            v.push(err(
                                S,
                                "key_source",
                                "a keystore already exists here: a new key would orphan it; choose Use existing",
                            ));
                        }
                        if cx.probes.path_exists(Path::new(file)) {
                            v.push(err(
                                S,
                                "key_file",
                                "this file exists: choose Use existing (a previous attempt may have created it)",
                            ));
                        }
                        let parent = Path::new(file).parent().unwrap_or(Path::new("/"));
                        if cx.probes.dir_info(parent).device != 0
                            && cx.probes.dir_info(parent).device
                                == cx.probes.dir_info(Path::new(&a.base_path)).device
                            && cx.probes.dir_info(Path::new(&a.base_path)).exists
                        {
                            v.push(warn(
                                S,
                                "key_file",
                                "the key file and the data share one volume",
                            ));
                        }
                        if cx.facts.euid != 0
                            && let Some((uid, _)) = daemon_uid_gid(a, cx)
                            && uid != cx.facts.euid
                        {
                            v.push(warn(
                                S,
                                "key_file",
                                "the file will be owned by you, not the daemon user: the daemon cannot read it",
                            ));
                        }
                    }
                    KeySource::UseExisting => {
                        if let Err(e) = cx.probes.node_key_ok(file, &ks) {
                            v.push(err(S, "key_file", format!("the key file is unusable: {e}")));
                        }
                        existing_key_file_warnings(&mut v, "key_file", file, a, cx);
                        let owner = cx.probes.file_owner(Path::new(file));
                        if cx.facts.euid != 0
                            && let (Some(o), Some((uid, _))) = (owner, daemon_uid_gid(a, cx))
                            && o != uid
                        {
                            v.push(warn(
                                S,
                                "key_file",
                                "the daemon user does not own this file",
                            ));
                        }
                    }
                }
            }
        }
        Authority::NewRegistry(n) => {
            new_registry(&mut v, n, a, cx);
            registry_group(&mut v, a, cx);
        }
    }
    v
}

fn new_registry(v: &mut Vec<Issue>, n: &NewRegistryAnswers, a: &Answers, cx: &Ctx) {
    const S: Step = Step::Authority;
    let ks = keystore_path(a);
    let keystore_json = cx.probes.path_exists(&ks.join("keystore.json"));
    #[cfg(feature = "devices")]
    {
        use y2q_core::crypto::devices::provision;
        let label = n.label.as_deref().filter(|l| !l.is_empty());
        let field = if n.first == FirstKind::Tpm {
            "tpm_label"
        } else {
            "fido_label"
        };
        if let Err(e) = provision::preflight(&ks, label, true, n.away_grant_seconds) {
            v.push(err(
                S,
                if label.is_some() && e.to_string().contains("label") {
                    field
                } else {
                    "away_grant"
                },
                e.to_string(),
            ));
        }
    }
    if keystore_json {
        match n.adopt_key_file.as_deref().filter(|f| !f.is_empty()) {
            None => v.push(err(
                S,
                "adopt_file",
                "keystore.json exists: name the node-key file this deployment uses so the registry can adopt it",
            )),
            Some(file) => {
                if abs_path(v, S, "adopt_file", "node-key file", file) {
                    operator_key_location(v, "adopt_file", file, a);
                    if let Err(e) = cx.probes.node_key_ok(file, &ks) {
                        v.push(err(S, "adopt_file", format!("the node-key file is unusable: {e}")));
                    }
                }
            }
        }
    }
    match n.first {
        FirstKind::Tpm => {
            if n.pcrs.is_empty() || n.pcrs.iter().any(|p| *p > 23) {
                v.push(err(
                    S,
                    "tpm_pcrs",
                    "PCRs must be integers 0..=23, at least one",
                ));
            }
            if a.device.tcti.trim().is_empty() {
                v.push(err(S, "tpm_tcti", "TCTI must not be empty"));
            }
            if let Err(e) = cx.cache.tpm(cx.probes, &a.device.tcti, cx.force_probe) {
                v.push(err(S, "tpm_tcti", format!("the TPM is not reachable: {e}")));
            }
            let sb = cx
                .facts
                .secure_boot
                .unwrap_or_else(|| cx.probes.secure_boot());
            if let Some(what) = secure_boot_problem(sb, &n.pcrs, n.allow_secure_boot_off) {
                v.push(err(
                    S,
                    "allow_sb_off",
                    format!("refusing to bind to PCR 7: {what}; enable Secure Boot or tick 'Allow PCR 7 without Secure Boot' (test rigs only)"),
                ));
            }
            roughtime_required(v, a, cx, true);
        }
        FirstKind::Fido2 => {
            match cx.probes.fido2_list() {
                Ok(list) if list.is_empty() => {
                    v.push(err(S, "first_device", "no FIDO2 authenticator is attached"))
                }
                Ok(list) if list.len() >= 2 => match n.hid_path.as_deref() {
                    None | Some("") => v.push(err(
                        S,
                        "hid_path",
                        "several authenticators are attached: choose one",
                    )),
                    Some(p) if !list.iter().any(|l| l == p) => {
                        v.push(err(S, "hid_path", "that authenticator is not attached"));
                    }
                    Some(_) => {}
                },
                Ok(_) => {}
                Err(e) => v.push(err(
                    S,
                    "first_device",
                    format!("cannot enumerate authenticators: {e}"),
                )),
            }
            if let Some(l) = n.label.as_deref()
                && !l.is_empty()
                && let Err(e) = fido_label_problem(l)
            {
                v.push(err(S, "fido_label", e));
            }
        }
    }
}

/// Roughtime requirements: a home device implies away grants, which need
/// attested time.
fn roughtime_required(v: &mut Vec<Issue>, a: &Answers, cx: &Ctx, required: bool) {
    const S: Step = Step::Authority;
    let d = &a.device;
    if !(200..=30_000).contains(&d.roughtime_timeout_ms) {
        v.push(err(S, "rt_timeout", "timeout must be 200..=30000 ms"));
    }
    if !(2..=16).contains(&d.roughtime_min_responses) {
        v.push(err(S, "rt_min", "minimum responses must be 2..=16"));
    }
    if !required {
        return;
    }
    if d.roughtime_servers.len() < usize::from(d.roughtime_min_responses) {
        v.push(err(
            S,
            "roughtime",
            format!(
                "at least {} Roughtime servers are needed (have {})",
                d.roughtime_min_responses,
                d.roughtime_servers.len()
            ),
        ));
        return;
    }
    if let Err(e) = cx.cache.attest(
        cx.probes,
        &d.roughtime_servers,
        d.roughtime_timeout_ms,
        d.roughtime_min_responses,
        cx.force_probe,
    ) {
        v.push(err(
            S,
            "roughtime",
            format!("attested time unavailable: {e}"),
        ));
    }
}

/// The Device config group, for plans that end with a registry.
fn registry_group(v: &mut Vec<Issue>, a: &Answers, cx: &Ctx) {
    const S: Step = Step::Authority;
    let d = &a.device;
    match &a.authority {
        Some(Authority::Keep(KeepKind::Registry)) | Some(Authority::FinishMigration { .. }) => {
            match cx.probes.registry_summary(&keystore_path(a)) {
                Some(s) if s.has_home => roughtime_required(v, a, cx, true),
                Some(_) => roughtime_required(v, a, cx, false),
                None => {
                    roughtime_required(v, a, cx, false);
                    v.push(warn(
                        S,
                        "roughtime",
                        "cannot read the registry to tell whether Roughtime servers are required",
                    ));
                }
            }
        }
        _ => {}
    }
    if d.tcti.trim().is_empty() {
        v.push(err(S, "tpm_tcti", "TCTI must not be empty"));
    }
    if d.use_helper {
        abs_path(v, S, "socket_path", "helper socket path", &d.socket_path);
        abs_path(v, S, "state_dir", "helper state directory", &d.state_dir);
        if is_protected(Path::new(&d.state_dir)) {
            v.push(err(
                S,
                "state_dir",
                "the state directory must not be a system directory",
            ));
        }
        if !d.key_user.is_empty()
            && cx.facts.euid != 0
            && matches!(&a.authority, Some(Authority::NewRegistry(_)))
        {
            match cx.probes.lookup_user(&d.key_user) {
                Some(u) if u.uid != cx.facts.euid => v.push(err(
                    S,
                    "key_user",
                    format!(
                        "the registry must be created by the key user: run `sudo -u {} y2qd setup`",
                        d.key_user
                    ),
                )),
                _ => {}
            }
        }
    }
}

pub fn system(a: &Answers, cx: &Ctx) -> Vec<Issue> {
    const S: Step = Step::System;
    let mut v = Vec::new();
    let helper = a.device.use_helper && a.involves_registry();
    let root = cx.facts.euid == 0;
    let identities = a.install_units || root || helper;
    if identities {
        let mut names: Vec<(&'static str, &str, bool)> = vec![
            ("daemon_user", &a.daemon_user, true),
            ("group", &a.group, false),
        ];
        if a.install_units {
            names.push(("socket_group", &a.socket_group, false));
        }
        if helper {
            names.push(("key_user", &a.device.key_user, true));
            names.push(("key_user_group", &a.key_user_group, false));
        }
        for (field, name, is_user) in names {
            if !valid_name(name) {
                v.push(err(
                    S,
                    field,
                    format!("'{name}' is not a valid account name"),
                ));
                continue;
            }
            let found = if is_user {
                cx.probes.lookup_user(name).map(|u| (u.uid, u.gid))
            } else {
                cx.probes.lookup_group(name).map(|g| (g, g))
            };
            match found {
                None => v.push(err(
                    S,
                    field,
                    format!(
                        "{} '{name}' does not exist: create it ({}) first",
                        if is_user { "user" } else { "group" },
                        if is_user {
                            format!("useradd --system {name}")
                        } else {
                            format!("groupadd --system {name}")
                        }
                    ),
                )),
                Some((0, _)) if is_user => v.push(err(S, field, "must not be root")),
                Some((id, _)) if !is_user && id == 0 => {
                    v.push(err(S, field, "must not be the root group"))
                }
                Some(_) => {}
            }
        }
        if helper {
            let du = cx.probes.lookup_user(&a.daemon_user);
            let ku = cx.probes.lookup_user(&a.device.key_user);
            if let (Some(d), Some(k)) = (&du, &ku)
                && d.uid == k.uid
            {
                v.push(err(
                    S,
                    "key_user",
                    "the key helper must run as a different uid than the daemon",
                ));
            }
            if a.key_user_group == a.group {
                v.push(err(
                    S,
                    "key_user_group",
                    "the key user's group must differ from the shared group",
                ));
            }
            if cx.probes.user_in_group(&a.daemon_user, &a.key_user_group) {
                v.push(err(
                    S,
                    "key_user_group",
                    "the daemon user is a member of the key user's group, which would let it open the FIDO2 device",
                ));
            }
            if !cx.probes.user_in_group(&a.device.key_user, "tss") {
                v.push(warn(
                    S,
                    "key_user",
                    "the key user is not in the tss group (TPM access)",
                ));
            }
        }
    }
    if a.install_units {
        if !cx.facts.systemd {
            v.push(warn(
                S,
                "install_units",
                "systemd is not running on this host",
            ));
        }
        if abs_path(&mut v, S, "unit_root", "unit install root", &a.unit_root)
            && is_protected(Path::new(&a.unit_root))
            && Path::new(&a.unit_root) != Path::new("/etc")
        {
            v.push(err(
                S,
                "unit_root",
                "the unit install root must not be a system directory",
            ));
        }
        if abs_path(&mut v, S, "binary_path", "binary path", &a.binary_path) {
            let info = cx.probes.dir_info(Path::new(&a.binary_path));
            if !info.exists || info.mode & 0o111 == 0 {
                v.push(warn(
                    S,
                    "binary_path",
                    "the binary is missing or not executable",
                ));
            }
        }
        for (field, value) in [
            ("binary_path", &a.binary_path),
            ("base_path", &a.base_path),
            ("keystore_dir", &a.keystore_dir),
            ("unit_root", &a.unit_root),
        ] {
            if ["/home", "/root", "/run/user"]
                .iter()
                .any(|p| normalize(Path::new(value)).starts_with(p))
            {
                v.push(err(S, field, "units run with ProtectHome=true: this path must not be under /home, /root or /run/user"));
            }
        }
        if !a.config_path.starts_with("/etc")
            && ["/home", "/root", "/run/user"]
                .iter()
                .any(|p| a.config_path.starts_with(p))
        {
            v.push(err(
                S,
                "unit_root",
                "the config file is under a path the unit cannot read (ProtectHome=true)",
            ));
        }
        if !matches!(
            &a.authority,
            Some(Authority::OperatorKey { .. }) | Some(Authority::Keep(KeepKind::Operator))
        ) && !helper
        {
            v.push(err(
                S,
                "install_units",
                "unit templates cover helper mode and operator-key mode only; enable the key helper or use an operator key",
            ));
        }
        if a.install_udev_rule {
            if a.udev_vendor_id.len() != 4
                || !a.udev_vendor_id.chars().all(|c| c.is_ascii_hexdigit())
            {
                v.push(err(S, "udev_vendor", "vendor id must be 4 hex digits"));
            } else if a.udev_vendor_id != "1050" {
                v.push(warn(
                    S,
                    "udev_vendor",
                    "the shipped rule targets Yubico (1050) only",
                ));
            }
        }
    }
    if helper {
        for (field, value) in [
            ("state_dir", a.device.state_dir.as_str()),
            ("socket_path", a.device.socket_path.as_str()),
        ] {
            let p = Path::new(value);
            let under_run = p.starts_with("/run")
                || cx
                    .probes
                    .dir_info(&super::sys::nearest_existing_ancestor(p))
                    .tmpfs;
            if !under_run {
                v.push(err(
                    S,
                    field,
                    "must be under /run (or on tmpfs): it holds one-time authorization",
                ));
            }
            if is_within(p, Path::new(&a.base_path)) || is_within(p, Path::new(&a.keystore_dir)) {
                v.push(err(
                    S,
                    field,
                    "must not be inside the data or keystore directory",
                ));
            }
        }
        if !a.device.state_dir.is_empty()
            && !cx
                .probes
                .dir_info(&super::sys::nearest_existing_ancestor(Path::new(
                    &a.device.state_dir,
                )))
                .tmpfs
        {
            v.push(warn(S, "state_dir", "the state directory is not on tmpfs"));
        }
    }
    v
}

#[cfg(test)]
pub use fake::FakeProbes;

#[cfg(test)]
mod fake {
    use super::*;
    use std::cell::RefCell;

    /// Configurable stand-in for every probe. Defaults: everything exists and
    /// works; no users/groups are defined until added.
    pub struct FakeProbes {
        pub users: Vec<User>,
        pub groups: Vec<(String, u32)>,
        pub memberships: Vec<(String, String)>,
        pub bind_error: Option<String>,
        pub tls_error: Option<String>,
        pub dirs: RefCell<HashMap<PathBuf, DirInfo>>,
        pub default_dir: DirInfo,
        pub existing_paths: RefCell<Vec<PathBuf>>,
        pub nonempty_dirs: Vec<PathBuf>,
        pub owners: HashMap<PathBuf, u32>,
        pub free: Option<u64>,
        pub daemon: Tri,
        pub registry: Option<RegistrySummary>,
        pub node_key: Result<(), String>,
        pub tpm: Result<(), String>,
        pub attest: Result<(u64, usize, usize), String>,
        pub fido2: Result<Vec<String>, String>,
        pub secure_boot: SecureBoot,
        pub readable: bool,
    }

    impl Default for FakeProbes {
        fn default() -> Self {
            Self {
                users: Vec::new(),
                groups: Vec::new(),
                memberships: Vec::new(),
                bind_error: None,
                tls_error: None,
                dirs: RefCell::new(HashMap::new()),
                default_dir: DirInfo {
                    exists: true,
                    is_dir: true,
                    writable: true,
                    mode: 0o755,
                    ..DirInfo::default()
                },
                existing_paths: RefCell::new(Vec::new()),
                nonempty_dirs: Vec::new(),
                owners: HashMap::new(),
                free: Some(100 << 30),
                daemon: Tri::No,
                registry: None,
                node_key: Ok(()),
                tpm: Ok(()),
                attest: Ok((1, 2, 2)),
                fido2: Ok(Vec::new()),
                secure_boot: SecureBoot::Enabled,
                readable: true,
            }
        }
    }

    impl FakeProbes {
        pub fn with_user(mut self, name: &str, uid: u32, gid: u32) -> Self {
            self.users.push(User {
                uid,
                gid,
                name: name.to_owned(),
            });
            self.groups.push((name.to_owned(), gid));
            self
        }

        pub fn with_group(mut self, name: &str, gid: u32) -> Self {
            self.groups.push((name.to_owned(), gid));
            self
        }

        pub fn exists(self, p: &str) -> Self {
            self.existing_paths.borrow_mut().push(PathBuf::from(p));
            self
        }
    }

    impl Probes for FakeProbes {
        fn bind(&self, _: &str, _: u16) -> Result<(), String> {
            self.bind_error.clone().map_or(Ok(()), Err)
        }
        fn lookup_user(&self, name: &str) -> Option<User> {
            self.users.iter().find(|u| u.name == name).cloned()
        }
        fn lookup_uid(&self, uid: u32) -> Option<User> {
            self.users.iter().find(|u| u.uid == uid).cloned()
        }
        fn lookup_group(&self, name: &str) -> Option<u32> {
            self.groups.iter().find(|g| g.0 == name).map(|g| g.1)
        }
        fn group_name(&self, gid: u32) -> Option<String> {
            self.groups.iter().find(|g| g.1 == gid).map(|g| g.0.clone())
        }
        fn user_in_group(&self, user: &str, group: &str) -> bool {
            self.memberships
                .iter()
                .any(|(u, g)| u == user && g == group)
        }
        fn tls_check(&self, _: &Path, _: &Path, _: Option<&Path>, _: bool) -> Result<(), String> {
            self.tls_error.clone().map_or(Ok(()), Err)
        }
        fn readable_by(&self, _: &Path, _: u32, _: u32) -> bool {
            self.readable
        }
        fn dir_info(&self, path: &Path) -> DirInfo {
            if let Some(d) = self.dirs.borrow().get(path) {
                return *d;
            }
            if self.existing_paths.borrow().iter().any(|p| p == path) {
                return self.default_dir;
            }
            self.default_dir
        }
        fn path_exists(&self, path: &Path) -> bool {
            self.existing_paths.borrow().iter().any(|p| p == path)
        }
        fn dir_nonempty(&self, path: &Path) -> bool {
            self.nonempty_dirs.iter().any(|p| p == path)
        }
        fn file_owner(&self, path: &Path) -> Option<u32> {
            self.owners.get(path).copied()
        }
        fn free_bytes(&self, _: &Path) -> Option<u64> {
            self.free
        }
        fn daemon_running(&self, _: &Path) -> Tri {
            self.daemon
        }
        fn registry_summary(&self, _: &Path) -> Option<RegistrySummary> {
            self.registry
        }
        fn node_key_ok(&self, _: &str, _: &Path) -> Result<(), String> {
            self.node_key.clone()
        }
        fn tpm_probe(&self, _: &str) -> Result<(), String> {
            self.tpm.clone()
        }
        fn attest(
            &self,
            _: &[RoughtimeServerAnswer],
            _: u64,
            _: u8,
        ) -> Result<(u64, usize, usize), String> {
            self.attest.clone()
        }
        fn fido2_list(&self) -> Result<Vec<String>, String> {
            self.fido2.clone()
        }
        fn secure_boot(&self) -> SecureBoot {
            self.secure_boot
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::answers::AuthorityKind;
    use crate::setup::scan::test_facts;

    struct Env {
        facts: Facts,
        probes: FakeProbes,
        cache: ProbeCache,
    }

    impl Env {
        fn new() -> Self {
            Self {
                facts: test_facts(),
                probes: FakeProbes::default(),
                cache: ProbeCache::default(),
            }
        }

        fn answers(&self) -> Answers {
            let mut a =
                Answers::defaults(&self.facts, &self.probes, Path::new("/srv/y2q/config.toml"));
            a.base_path = "/srv/y2q/data".into();
            a.keystore_dir = "/srv/y2q/keys".into();
            a.authority = Some(Authority::OperatorKey {
                mode: KeySource::Generate,
                file: "/etc/y2q/node.key".into(),
            });
            a
        }

        fn run(&self, step: Step, a: &Answers) -> Vec<Issue> {
            let cx = Ctx {
                facts: &self.facts,
                probes: &self.probes,
                cache: &self.cache,
                force_probe: false,
            };
            for_step(step, a, &cx)
        }
    }

    fn errors(v: &[Issue]) -> Vec<&str> {
        v.iter().filter(|i| i.is_error()).map(|i| i.field).collect()
    }

    #[test]
    fn defaults_validate_clean() {
        let env = Env::new();
        let a = env.answers();
        for step in [
            Step::Paths,
            Step::Network,
            Step::S3,
            Step::StorageLogging,
            Step::Security,
            Step::System,
        ] {
            assert!(
                errors(&env.run(step, &a)).is_empty(),
                "{step:?}: {:?}",
                env.run(step, &a)
            );
        }
    }

    #[test]
    fn nested_protected_and_symlinked_paths_are_errors() {
        let env = Env::new();
        let mut a = env.answers();
        a.keystore_dir = "/srv/y2q/data/keys".into();
        assert_eq!(errors(&env.run(Step::Paths, &a)), ["keystore_dir"]);
        a.keystore_dir = "/srv/y2q/keys".into();
        a.base_path = "/var/lib".into();
        assert_eq!(errors(&env.run(Step::Paths, &a)), ["base_path"]);
        a.base_path = "/srv/y2q/data".into();
        env.probes.dirs.borrow_mut().insert(
            PathBuf::from("/srv/y2q/data"),
            DirInfo {
                exists: true,
                is_dir: true,
                is_symlink: true,
                ..DirInfo::default()
            },
        );
        assert_eq!(errors(&env.run(Step::Paths, &a)), ["base_path"]);
    }

    #[test]
    fn orphan_risk_needs_acknowledgement() {
        let mut env = Env::new();
        env.probes
            .nonempty_dirs
            .push(PathBuf::from("/srv/y2q/data"));
        let mut a = env.answers();
        assert_eq!(errors(&env.run(Step::Paths, &a)), ["ack_data_risk"]);
        a.ack_data_risk = true;
        assert!(errors(&env.run(Step::Paths, &a)).is_empty());
        // A keystore already at the target is not an orphan.
        a.ack_data_risk = false;
        let env = Env {
            probes: FakeProbes::default().exists("/srv/y2q/keys/keystore.json"),
            ..Env::new()
        };
        assert!(errors(&env.run(Step::Paths, &a)).is_empty());
    }

    #[test]
    fn injection_characters_are_rejected_without_units() {
        let env = Env::new();
        let mut a = env.answers();
        for bad in [
            "/srv/a b",
            "/srv/a\"b",
            "/srv/a;b",
            "/srv/a%b",
            "/srv/a$b",
            "/srv/a\nb",
            "/srv/a'b",
            "/srv/a\\b",
        ] {
            a.base_path = bad.into();
            assert!(!errors(&env.run(Step::Paths, &a)).is_empty(), "{bad:?}");
        }
        a.base_path = "/srv/y2q/data".into();
        a.tls.enabled = true;
        a.tls.cert_path = "/etc/a b.pem".into();
        a.tls.key_path = "/etc/k.pem".into();
        assert!(errors(&env.run(Step::Network, &a)).contains(&"tls_cert"));
    }

    #[test]
    fn network_rules() {
        let mut env = Env::new();
        let mut a = env.answers();
        a.host = "0.0.0.0".into();
        assert_eq!(errors(&env.run(Step::Network, &a)), ["allow_insecure_bind"]);
        a.allow_insecure_bind = true;
        assert!(errors(&env.run(Step::Network, &a)).is_empty());
        a.tls.enabled = true;
        assert!(errors(&env.run(Step::Network, &a)).contains(&"tls_cert"));
        a.tls.cert_path = "/etc/c.pem".into();
        a.tls.key_path = "/etc/k.pem".into();
        assert!(errors(&env.run(Step::Network, &a)).is_empty());
        env.probes.tls_error = Some("bad pem".into());
        assert!(errors(&env.run(Step::Network, &a)).contains(&"tls_cert"));
        env.probes.tls_error = None;
        a.port = 0;
        let v = env.run(Step::Network, &a);
        assert!(v.iter().any(|i| i.field == "port" && i.sev == Sev::Warning));
        a.port = 8080;
        env.probes.bind_error = Some("address in use".into());
        let v = env.run(Step::Network, &a);
        assert!(errors(&v).is_empty() && v.iter().any(|i| i.field == "port"));
    }

    #[test]
    fn s3_rules() {
        let env = Env::new();
        let mut a = env.answers();
        assert!(env.run(Step::S3, &a).is_empty());
        a.s3_enabled = true;
        a.s3_port = a.port;
        assert!(errors(&env.run(Step::S3, &a)).contains(&"s3_port"));
        a.s3_host = "127.0.0.2".into();
        a.s3_port = a.port;
        assert!(!errors(&env.run(Step::S3, &a)).contains(&"s3_port"));
        a.s3_host = "0.0.0.0".into();
        assert!(errors(&env.run(Step::S3, &a)).contains(&"s3_port"));
        a.s3_port = 9000;
        assert_eq!(errors(&env.run(Step::S3, &a)), ["s3_allow_insecure_bind"]);
    }

    #[test]
    fn security_bounds() {
        let env = Env::new();
        let mut a = env.answers();
        a.default_ttl_seconds = 90_000;
        assert_eq!(errors(&env.run(Step::Security, &a)), ["default_ttl"]);
        a.default_ttl_seconds = 3600;
        a.lockout_seconds = 0;
        assert_eq!(errors(&env.run(Step::Security, &a)), ["lockout"]);
        a.max_failed_logins = 0;
        assert!(errors(&env.run(Step::Security, &a)).is_empty());
        a.argon_p_cost = 256;
        assert!(errors(&env.run(Step::Security, &a)).contains(&"argon_p"));
        a.argon_p_cost = 4;
        a.argon_m_cost_kib = 16;
        assert_eq!(errors(&env.run(Step::Security, &a)), ["argon_m"]);
        a.argon_m_cost_kib = 8192;
        let v = env.run(Step::Security, &a);
        assert!(errors(&v).is_empty() && v.iter().any(|i| i.field == "argon_m"));
        a.argon_t_cost = 0;
        assert!(errors(&env.run(Step::Security, &a)).contains(&"argon_t"));
    }

    #[test]
    fn uring_requires_the_probe_to_pass() {
        let mut env = Env::new();
        let mut a = env.answers();
        a.backend = "uring".into();
        assert!(errors(&env.run(Step::StorageLogging, &a)).is_empty());
        env.facts.io_uring = Err("EPERM".into());
        assert_eq!(errors(&env.run(Step::StorageLogging, &a)), ["backend"]);
        a.backend = "filesystem".into();
        a.log_filter = "info,[".into();
        assert_eq!(errors(&env.run(Step::StorageLogging, &a)), ["log_filter"]);
    }

    #[test]
    fn operator_key_rules() {
        let mut env = Env::new();
        let mut a = env.answers();
        // Generate: file must not exist, key must be outside data and keystore.
        assert!(errors(&env.run(Step::Authority, &a)).is_empty());
        env.probes = FakeProbes::default().exists("/etc/y2q/node.key");
        assert_eq!(errors(&env.run(Step::Authority, &a)), ["key_file"]);
        a.authority = Some(Authority::OperatorKey {
            mode: KeySource::Generate,
            file: "/srv/y2q/keys/node.key".into(),
        });
        assert!(errors(&env.run(Step::Authority, &a)).contains(&"key_file"));
        // A keystore at the target removes Generate.
        env.probes = FakeProbes::default().exists("/srv/y2q/keys/keystore.json");
        a.authority = Some(Authority::OperatorKey {
            mode: KeySource::Generate,
            file: "/etc/y2q/node.key".into(),
        });
        assert_eq!(errors(&env.run(Step::Authority, &a)), ["key_source"]);
        // UseExisting with a bad key fails; with a good one passes.
        a.authority = Some(Authority::OperatorKey {
            mode: KeySource::UseExisting,
            file: "/etc/y2q/node.key".into(),
        });
        assert!(errors(&env.run(Step::Authority, &a)).is_empty());
        env.probes.node_key = Err("wrong key".into());
        assert_eq!(errors(&env.run(Step::Authority, &a)), ["key_file"]);
    }

    #[test]
    fn keep_and_finish_migration_availability() {
        let mut env = Env::new();
        let mut a = env.answers();
        a.authority = Some(Authority::Keep(KeepKind::Operator));
        assert_eq!(errors(&env.run(Step::Authority, &a)), ["authority"]);
        a.loaded.node_key_file = "/etc/y2q/node.key".into();
        assert!(errors(&env.run(Step::Authority, &a)).is_empty());
        // Both a key file and a registry: Keep(Operator) and FinishMigration offered.
        env.probes = FakeProbes::default().exists("/srv/y2q/keys/devices.json");
        let cx = Ctx {
            facts: &env.facts,
            probes: &env.probes,
            cache: &env.cache,
            force_probe: false,
        };
        let kinds = a.authority_kinds(&authority_context(&a, &cx));
        let avail = |k: AuthorityKind| kinds.iter().find(|x| x.kind == k).unwrap().available();
        assert!(avail(AuthorityKind::Keep) && avail(AuthorityKind::FinishMigration));
        assert!(!avail(AuthorityKind::NewRegistry));
        a.authority = Some(Authority::FinishMigration { ack_adopted: false });
        assert!(errors(&env.run(Step::Authority, &a)).contains(&"ack_adopted"));
        a.authority = Some(Authority::FinishMigration { ack_adopted: true });
        a.device.roughtime_servers.clear();
        let v = env.run(Step::Authority, &a);
        let e = errors(&v);
        assert!(!e.contains(&"ack_adopted"));
    }

    #[test]
    fn identities_must_exist_and_be_distinct_when_it_matters() {
        let mut env = Env::new();
        env.facts.euid = 0;
        let mut a = env.answers();
        assert!(errors(&env.run(Step::System, &a)).contains(&"daemon_user"));
        env.probes = FakeProbes::default()
            .with_user("y2qd", 954, 954)
            .with_group("y2q", 960)
            .with_user("y2q-keyd", 955, 955)
            .with_group("y2q-keyd", 955);
        a.authority = Some(Authority::NewRegistry(NewRegistryAnswers::default()));
        a.device.use_helper = true;
        assert!(
            errors(&env.run(Step::System, &a)).is_empty(),
            "{:?}",
            env.run(Step::System, &a)
        );
        a.device.key_user = "y2qd".into();
        assert!(errors(&env.run(Step::System, &a)).contains(&"key_user"));
        a.device.key_user = "y2q-keyd".into();
        a.key_user_group = "y2q".into();
        assert!(errors(&env.run(Step::System, &a)).contains(&"key_user_group"));
        a.key_user_group = "y2q-keyd".into();
        env.probes
            .memberships
            .push(("y2qd".into(), "y2q-keyd".into()));
        assert!(errors(&env.run(Step::System, &a)).contains(&"key_user_group"));
        // Root account is refused.
        env.probes.memberships.clear();
        env.probes.users.push(User {
            uid: 0,
            gid: 0,
            name: "root".into(),
        });
        a.daemon_user = "root".into();
        assert!(errors(&env.run(Step::System, &a)).contains(&"daemon_user"));
    }

    #[test]
    fn unit_rules() {
        let mut env = Env::new();
        env.probes = FakeProbes::default()
            .with_user("y2qd", 954, 954)
            .with_group("y2q", 960);
        let mut a = env.answers();
        a.install_units = true;
        a.socket_group = "y2q".into();
        a.binary_path = "/usr/local/bin/y2qd".into();
        a.authority = Some(Authority::OperatorKey {
            mode: KeySource::Generate,
            file: "/etc/y2q/node.key".into(),
        });
        let v = env.run(Step::System, &a);
        assert!(errors(&v).is_empty(), "{v:?}");
        // ProtectHome: nothing under /home.
        a.base_path = "/home/me/data".into();
        assert!(errors(&env.run(Step::System, &a)).contains(&"base_path"));
        a.base_path = "/srv/y2q/data".into();
        // Legacy in-process device mode is refused.
        a.authority = Some(Authority::NewRegistry(NewRegistryAnswers::default()));
        a.device.use_helper = false;
        assert!(errors(&env.run(Step::System, &a)).contains(&"install_units"));
        // Helper state must live under /run.
        a.device.use_helper = true;
        env.probes = FakeProbes::default()
            .with_user("y2qd", 954, 954)
            .with_user("y2q-keyd", 955, 955)
            .with_group("y2q", 960)
            .with_group("y2q-keyd", 955);
        a.device.state_dir = "/srv/y2q/keys/state".into();
        let v = env.run(Step::System, &a);
        let e = errors(&v);
        assert!(e.contains(&"state_dir"));
    }

    #[cfg(feature = "devices")]
    #[test]
    fn new_registry_tpm_rules() {
        let mut env = Env::new();
        let mut a = env.answers();
        a.authority = Some(Authority::NewRegistry(NewRegistryAnswers::default()));
        a.device.roughtime_servers = vec![
            RoughtimeServerAnswer {
                name: "a".into(),
                addr: "127.0.0.1:1".into(),
                public_key_b64: "x".into(),
            },
            RoughtimeServerAnswer {
                name: "b".into(),
                addr: "127.0.0.1:2".into(),
                public_key_b64: "y".into(),
            },
        ];
        assert!(
            errors(&env.run(Step::Authority, &a)).is_empty(),
            "{:?}",
            env.run(Step::Authority, &a)
        );
        env.probes.secure_boot = SecureBoot::Disabled;
        env.facts.secure_boot = Some(SecureBoot::Disabled);
        assert!(errors(&env.run(Step::Authority, &a)).contains(&"allow_sb_off"));
        if let Some(Authority::NewRegistry(n)) = &mut a.authority {
            n.allow_secure_boot_off = true;
        }
        assert!(errors(&env.run(Step::Authority, &a)).is_empty());
        a.device.roughtime_servers.pop();
        assert!(errors(&env.run(Step::Authority, &a)).contains(&"roughtime"));
    }

    #[cfg(feature = "devices")]
    #[test]
    fn new_registry_requires_adopt_file_when_keystore_exists() {
        let env = Env {
            probes: FakeProbes::default().exists("/srv/y2q/keys/keystore.json"),
            ..Env::new()
        };
        let mut a = env.answers();
        let mut n = NewRegistryAnswers {
            first: FirstKind::Fido2,
            ..NewRegistryAnswers::default()
        };
        a.authority = Some(Authority::NewRegistry(n.clone()));
        let v = env.run(Step::Authority, &a);
        let e = errors(&v);
        assert!(e.contains(&"adopt_file"));
        n.adopt_key_file = Some("/etc/y2q/node.key".into());
        a.authority = Some(Authority::NewRegistry(n));
        // Fido2 still needs an authenticator.
        let v = env.run(Step::Authority, &a);
        let e = errors(&v);
        assert!(!e.contains(&"adopt_file") && e.contains(&"first_device"));
    }
}
