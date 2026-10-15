//! The operator's answers: every value the wizard edits, with fresh-install
//! defaults and loading from an existing config file.
//!
//! `Answers` holds *typed* values; the wizard's form fields are strings that are
//! parsed into it. Hidden fields keep their loaded/default values.

use std::path::{Component, Path, PathBuf};

use toml_edit::{DocumentMut, Item, TableLike};

use super::scan::Facts;
use super::validate::Probes;

// --- compiled defaults (mirrors `config.default.toml` / `config.rs`) --------

pub const DEFAULT_HOST: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 8080;
pub const DEFAULT_S3_PORT: u16 = 9000;
pub const DEFAULT_S3_REGION: &str = "y2q";
pub const DEFAULT_LOG_FILTER: &str = "info";
pub const DEFAULT_ROUGHTIME_TIMEOUT_MS: u64 = 3000;
pub const DEFAULT_ROUGHTIME_MIN_RESPONSES: u8 = 2;
pub const DEFAULT_KEY_USER: &str = "y2q-keyd";
pub const DEFAULT_SOCKET_PATH: &str = "/run/y2q-keyd.sock";
pub const DEFAULT_STATE_DIR: &str = "/run/y2q-keyd";
pub const DEFAULT_GROUP: &str = "y2q";
pub const DEFAULT_UDEV_VENDOR_ID: &str = "1050";

/// Lexical normalisation: make absolute against the cwd, drop `.`, resolve
/// `..` without touching the filesystem. Used for every path comparison.
pub fn normalize(path: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        out.push("/");
    }
    out
}

/// `true` when `inner` equals or lies below `outer` (both normalised).
pub fn is_within(inner: &Path, outer: &Path) -> bool {
    normalize(inner).starts_with(normalize(outer))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsAnswers {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
    pub client_ca_path: String,
    pub require_pq_kex: bool,
}

impl Default for TlsAnswers {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_path: String::new(),
            key_path: String::new(),
            client_ca_path: String::new(),
            require_pq_kex: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoughtimeServerAnswer {
    pub name: String,
    pub addr: String,
    pub public_key_b64: String,
}

/// `[crypto.devices]` values; used only when the authority involves a registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceConfig {
    pub use_helper: bool,
    pub key_user: String,
    pub socket_path: String,
    pub state_dir: String,
    pub tcti: String,
    pub roughtime_servers: Vec<RoughtimeServerAnswer>,
    pub roughtime_timeout_ms: u64,
    pub roughtime_min_responses: u8,
    pub arm_on_start: bool,
    /// Uid written to `key_agent_peer_uid`: the daemon user's uid, resolved by
    /// [`Answers::resolve_ids`]. `None` leaves the key untouched.
    pub peer_uid: Option<u32>,
    pub arm_uid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepKind {
    Operator,
    Registry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    Generate,
    UseExisting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstKind {
    Tpm,
    Fido2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRegistryAnswers {
    pub first: FirstKind,
    pub label: Option<String>,
    pub pcrs: Vec<u8>,
    pub allow_secure_boot_off: bool,
    pub away_grant_seconds: u32,
    pub uv_required: bool,
    pub hid_path: Option<String>,
    pub adopt_key_file: Option<String>,
}

impl Default for NewRegistryAnswers {
    fn default() -> Self {
        Self {
            first: FirstKind::Tpm,
            label: None,
            pcrs: vec![7],
            allow_secure_boot_off: false,
            away_grant_seconds: y2q_core::crypto::devices::DEFAULT_AWAY_GRANT_SECONDS,
            uv_required: true,
            hid_path: None,
            adopt_key_file: None,
        }
    }
}

/// Where the node key comes from after setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authority {
    /// Leave the existing arrangement as configured.
    Keep(KeepKind),
    /// A registry adopted this config's key file earlier: drop `node_key_file`.
    FinishMigration {
        ack_adopted: bool,
    },
    OperatorKey {
        mode: KeySource,
        file: String,
    },
    NewRegistry(NewRegistryAnswers),
}

/// The selectable authority kinds in the form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityKind {
    Keep,
    FinishMigration,
    OperatorKey,
    NewRegistry,
}

impl AuthorityKind {
    pub const ALL: [AuthorityKind; 4] = [
        AuthorityKind::Keep,
        AuthorityKind::FinishMigration,
        AuthorityKind::OperatorKey,
        AuthorityKind::NewRegistry,
    ];

    pub fn label(self) -> &'static str {
        match self {
            AuthorityKind::Keep => "Keep current",
            AuthorityKind::FinishMigration => "Finish registry migration",
            AuthorityKind::OperatorKey => "Operator key file",
            AuthorityKind::NewRegistry => "Device registry (TPM/FIDO2)",
        }
    }
}

impl Authority {
    pub fn kind(&self) -> AuthorityKind {
        match self {
            Authority::Keep(_) => AuthorityKind::Keep,
            Authority::FinishMigration { .. } => AuthorityKind::FinishMigration,
            Authority::OperatorKey { .. } => AuthorityKind::OperatorKey,
            Authority::NewRegistry(_) => AuthorityKind::NewRegistry,
        }
    }

    /// The plan ends with a registry (existing or new) holding the node key.
    pub fn involves_registry(&self) -> bool {
        matches!(
            self,
            Authority::Keep(KeepKind::Registry)
                | Authority::FinishMigration { .. }
                | Authority::NewRegistry(_)
        )
    }
}

/// What the loaded config said, for deciding which authority kinds are offered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Loaded {
    pub config_exists: bool,
    pub node_key_file: String,
    pub key_agent_socket: String,
    pub keystore_dir: Option<String>,
    pub base_path: Option<String>,
}

/// Facts about the *current* keystore directory that decide availability.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuthorityContext {
    pub keystore_json: bool,
    pub devices_json: bool,
    pub built_with_devices: bool,
}

#[derive(Debug, Clone)]
pub struct KindAvailability {
    pub kind: AuthorityKind,
    pub reason: Option<String>,
}

impl KindAvailability {
    pub fn available(&self) -> bool {
        self.reason.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answers {
    pub config_path: PathBuf,
    // Paths
    pub base_path: String,
    pub keystore_dir: String,
    pub ack_data_risk: bool,
    pub index_path: Option<String>,
    // Network
    pub host: String,
    pub port: u16,
    pub tls: TlsAnswers,
    pub allow_insecure_bind: bool,
    // S3
    pub s3_enabled: bool,
    pub s3_host: String,
    pub s3_port: u16,
    pub s3_region: String,
    pub s3_virtual_host_domain: String,
    pub s3_tls: TlsAnswers,
    pub s3_allow_insecure_bind: bool,
    // Storage / logging
    pub backend: String,
    pub default_sync: String,
    pub log_filter: String,
    pub log_format: String,
    // Security
    pub default_ttl_seconds: u64,
    pub max_ttl_seconds: u64,
    pub max_failed_logins: u32,
    pub lockout_seconds: u64,
    pub enforce_authorization: bool,
    pub max_refreshes: u32,
    pub argon_m_cost_kib: u32,
    pub argon_t_cost: u32,
    pub argon_p_cost: u32,
    pub allow_unprotected_memory: bool,
    // Authority
    pub authority: Option<Authority>,
    pub device: DeviceConfig,
    // System
    pub daemon_user: String,
    pub group: String,
    pub install_units: bool,
    pub unit_root: String,
    pub binary_path: String,
    pub socket_group: String,
    pub key_user_group: String,
    pub install_udev_rule: bool,
    pub udev_vendor_id: String,
    // Bookkeeping
    pub loaded: Loaded,
    /// Keys present in the user's config with the wrong TOML type.
    pub unreadable: Vec<String>,
}

fn config_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn path_string(p: PathBuf) -> String {
    p.to_string_lossy().into_owned()
}

/// Binaries run out of a build tree or a home directory are not what a unit
/// should point at.
fn default_binary_path() -> String {
    const SHIPPED: &str = "/usr/local/bin/y2qd";
    match std::env::current_exe() {
        Ok(p) => {
            let s = p.to_string_lossy().into_owned();
            if s.starts_with("/home")
                || s.starts_with("/tmp")
                || s.starts_with("/root")
                || s.contains("/target/")
            {
                SHIPPED.to_owned()
            } else {
                s
            }
        }
        Err(_) => SHIPPED.to_owned(),
    }
}

impl Answers {
    /// Fresh-install values.
    pub fn defaults(facts: &Facts, probes: &dyn Probes, config_path: &Path) -> Self {
        let config_path = normalize(config_path);
        let cdir = config_dir(&config_path);
        let root = facts.euid == 0;
        let (base_path, keystore_dir, key_file) = if root {
            (
                "/var/lib/y2q/data".to_owned(),
                "/var/lib/y2q/keystore".to_owned(),
                "/etc/y2q/node.key".to_owned(),
            )
        } else {
            (
                path_string(cdir.join("y2q-data")),
                path_string(cdir.join("y2q-keys")),
                path_string(cdir.join("node.key")),
            )
        };
        let daemon_user = if !root {
            probes
                .lookup_uid(facts.euid)
                .map(|u| u.name)
                .unwrap_or_else(|| "y2qd".to_owned())
        } else {
            "y2qd".to_owned()
        };
        let socket_group = probes
            .lookup_user(&daemon_user)
            .and_then(|u| probes.group_name(u.gid))
            .unwrap_or_else(|| daemon_user.clone());
        let key_user_group = probes
            .lookup_user(DEFAULT_KEY_USER)
            .and_then(|u| probes.group_name(u.gid))
            .unwrap_or_else(|| DEFAULT_KEY_USER.to_owned());
        Self {
            config_path,
            base_path,
            keystore_dir,
            ack_data_risk: false,
            index_path: None,
            host: DEFAULT_HOST.to_owned(),
            port: DEFAULT_PORT,
            tls: TlsAnswers::default(),
            allow_insecure_bind: false,
            s3_enabled: false,
            s3_host: DEFAULT_HOST.to_owned(),
            s3_port: DEFAULT_S3_PORT,
            s3_region: DEFAULT_S3_REGION.to_owned(),
            s3_virtual_host_domain: String::new(),
            s3_tls: TlsAnswers::default(),
            s3_allow_insecure_bind: false,
            backend: "filesystem".to_owned(),
            default_sync: "durable".to_owned(),
            log_filter: DEFAULT_LOG_FILTER.to_owned(),
            log_format: "text".to_owned(),
            default_ttl_seconds: 3600,
            max_ttl_seconds: 86_400,
            max_failed_logins: 10,
            lockout_seconds: 900,
            enforce_authorization: true,
            max_refreshes: 0,
            argon_m_cost_kib: 65_536,
            argon_t_cost: 3,
            argon_p_cost: 4,
            allow_unprotected_memory: false,
            authority: Some(Authority::OperatorKey {
                mode: KeySource::Generate,
                file: key_file,
            }),
            device: DeviceConfig {
                use_helper: root,
                key_user: DEFAULT_KEY_USER.to_owned(),
                socket_path: DEFAULT_SOCKET_PATH.to_owned(),
                state_dir: DEFAULT_STATE_DIR.to_owned(),
                tcti: y2q_core::crypto::devices::DEFAULT_TPM_TCTI.to_owned(),
                roughtime_servers: Vec::new(),
                roughtime_timeout_ms: DEFAULT_ROUGHTIME_TIMEOUT_MS,
                roughtime_min_responses: DEFAULT_ROUGHTIME_MIN_RESPONSES,
                arm_on_start: false,
                peer_uid: None,
                arm_uid: 0,
            },
            daemon_user,
            group: DEFAULT_GROUP.to_owned(),
            install_units: false,
            unit_root: "/etc".to_owned(),
            binary_path: default_binary_path(),
            socket_group,
            key_user_group,
            install_udev_rule: false,
            udev_vendor_id: DEFAULT_UDEV_VENDOR_ID.to_owned(),
            loaded: Loaded::default(),
            unreadable: Vec::new(),
        }
    }

    /// Overlay the keys present in the user's parsed config (correct TOML type
    /// only) onto `defaults`. Never applied to the embedded default text.
    pub fn from_doc(doc: &DocumentMut, defaults: Self, facts: &Facts, probes: &dyn Probes) -> Self {
        let mut a = defaults;
        let mut r = Reader {
            doc,
            unreadable: Vec::new(),
        };
        a.loaded.config_exists = true;

        r.string(&["storage", "base_path"], &mut a.base_path);
        r.string(&["crypto", "keystore_dir"], &mut a.keystore_dir);
        let mut idx = String::new();
        if r.string(&["storage", "index_path"], &mut idx) && !idx.is_empty() {
            a.index_path = Some(idx);
        }

        r.string(&["server", "host"], &mut a.host);
        r.num(&["server", "port"], &mut a.port);
        r.tls(&["server", "tls"], &mut a.tls);
        r.boolean(
            &["server", "allow_insecure_bind"],
            &mut a.allow_insecure_bind,
        );
        r.boolean(
            &["server", "allow_unprotected_memory"],
            &mut a.allow_unprotected_memory,
        );

        r.boolean(&["s3", "enabled"], &mut a.s3_enabled);
        r.string(&["s3", "host"], &mut a.s3_host);
        r.num(&["s3", "port"], &mut a.s3_port);
        r.string(&["s3", "region"], &mut a.s3_region);
        r.string(
            &["s3", "virtual_host_domain"],
            &mut a.s3_virtual_host_domain,
        );
        r.tls(&["s3", "tls"], &mut a.s3_tls);
        r.boolean(
            &["s3", "allow_insecure_bind"],
            &mut a.s3_allow_insecure_bind,
        );

        r.choice(
            &["storage", "backend"],
            &mut a.backend,
            &["filesystem", "uring"],
        );
        r.choice(
            &["storage", "default_sync"],
            &mut a.default_sync,
            &["durable", "best-effort"],
        );
        r.string(&["observability", "log_filter"], &mut a.log_filter);
        r.choice(
            &["observability", "log_format"],
            &mut a.log_format,
            &["text", "json"],
        );

        r.num(&["auth", "default_ttl_seconds"], &mut a.default_ttl_seconds);
        r.num(&["auth", "max_ttl_seconds"], &mut a.max_ttl_seconds);
        r.num(&["auth", "max_failed_logins"], &mut a.max_failed_logins);
        r.num(&["auth", "lockout_seconds"], &mut a.lockout_seconds);
        r.boolean(
            &["auth", "enforce_authorization"],
            &mut a.enforce_authorization,
        );
        r.num(&["auth", "max_refreshes"], &mut a.max_refreshes);
        r.num(&["crypto", "argon2", "m_cost_kib"], &mut a.argon_m_cost_kib);
        r.num(&["crypto", "argon2", "t_cost"], &mut a.argon_t_cost);
        r.num(&["crypto", "argon2", "p_cost"], &mut a.argon_p_cost);

        // Device config.
        let mut socket = String::new();
        let socket_set = r.string(&["crypto", "devices", "key_agent_socket"], &mut socket);
        r.string(&["crypto", "devices", "tpm_tcti"], &mut a.device.tcti);
        r.string(
            &["crypto", "devices", "key_agent_state_dir"],
            &mut a.device.state_dir,
        );
        let mut peer = 0u32;
        if r.num(&["crypto", "devices", "key_agent_peer_uid"], &mut peer) {
            a.device.peer_uid = Some(peer);
        }
        r.num(
            &["crypto", "devices", "key_agent_arm_uid"],
            &mut a.device.arm_uid,
        );
        r.num(
            &["crypto", "devices", "roughtime", "timeout_ms"],
            &mut a.device.roughtime_timeout_ms,
        );
        r.num(
            &["crypto", "devices", "roughtime", "min_responses"],
            &mut a.device.roughtime_min_responses,
        );
        if let Some(servers) = r.servers(&["crypto", "devices", "roughtime", "servers"]) {
            a.device.roughtime_servers = servers;
        }
        a.loaded.key_agent_socket = socket.clone();
        if socket_set {
            a.device.use_helper = !socket.is_empty();
            if !socket.is_empty() {
                a.device.socket_path = socket;
            }
        } else {
            a.device.use_helper = false;
        }

        let mut nk = String::new();
        r.string(&["crypto", "node_key_file"], &mut nk);
        a.loaded.node_key_file = nk.clone();
        a.loaded.keystore_dir = Some(a.keystore_dir.clone());
        a.loaded.base_path = Some(a.base_path.clone());
        a.unreadable = r.unreadable;

        // Daemon user: reverse-lookup of the loaded peer uid, else the owner of
        // existing state, else the process user, else the default.
        let owner = |p: &str| probes.file_owner(Path::new(p));
        let from_state = a
            .device
            .peer_uid
            .or_else(|| owner(&format!("{}/keystore.json", a.keystore_dir)))
            .or_else(|| owner(&format!("{}/users.redb", a.keystore_dir)))
            .or_else(|| owner(&a.base_path))
            .and_then(|uid| probes.lookup_uid(uid))
            .filter(|u| u.uid != 0)
            .map(|u| u.name);
        if let Some(name) = from_state {
            a.daemon_user = name;
            a.socket_group = probes
                .lookup_user(&a.daemon_user)
                .and_then(|u| probes.group_name(u.gid))
                .unwrap_or_else(|| a.daemon_user.clone());
        }

        a.authority = if !nk_is_empty(&a.loaded.node_key_file) {
            Some(Authority::Keep(KeepKind::Operator))
        } else if Path::new(&a.keystore_dir).join("devices.json").exists() {
            Some(Authority::Keep(KeepKind::Registry))
        } else {
            // No `Keep` offered and (when keystore.json exists) no `Generate`.
            default_new_authority(&a, facts)
        };
        a
    }

    /// Which authority kinds are offered right now and why the others are not.
    pub fn authority_kinds(&self, ctx: &AuthorityContext) -> Vec<KindAvailability> {
        let has_nk = !nk_is_empty(&self.loaded.node_key_file);
        let keep_operator = has_nk;
        let keep_registry = ctx.devices_json && !has_nk;
        let finish = ctx.devices_json && has_nk;
        let registry_ok = ctx.built_with_devices && !ctx.devices_json;
        AuthorityKind::ALL
            .iter()
            .map(|&kind| {
                let reason = match kind {
                    AuthorityKind::Keep if keep_operator || keep_registry => None,
                    AuthorityKind::Keep => Some("nothing configured to keep".to_owned()),
                    AuthorityKind::FinishMigration if finish => None,
                    AuthorityKind::FinishMigration => {
                        Some("no half-finished registry adoption found".to_owned())
                    }
                    AuthorityKind::OperatorKey => None,
                    AuthorityKind::NewRegistry if registry_ok => None,
                    AuthorityKind::NewRegistry if !ctx.built_with_devices => Some(
                        "this build has no device support (rebuild with --features devices)"
                            .to_owned(),
                    ),
                    AuthorityKind::NewRegistry => Some(
                        "devices.json already exists; manage it with `y2q admin device ...`"
                            .to_owned(),
                    ),
                };
                KindAvailability { kind, reason }
            })
            .collect()
    }

    /// `Keep` resolved against the loaded config.
    pub fn keep_kind(&self) -> KeepKind {
        if nk_is_empty(&self.loaded.node_key_file) {
            KeepKind::Registry
        } else {
            KeepKind::Operator
        }
    }

    /// Switch the authority to `kind`, seeding the sub-answers.
    pub fn select_authority(&mut self, kind: AuthorityKind, facts: &Facts) {
        let key_file = self.default_key_file();
        self.authority = Some(match kind {
            AuthorityKind::Keep => Authority::Keep(self.keep_kind()),
            AuthorityKind::FinishMigration => Authority::FinishMigration { ack_adopted: false },
            AuthorityKind::OperatorKey => Authority::OperatorKey {
                mode: KeySource::Generate,
                file: key_file,
            },
            AuthorityKind::NewRegistry => {
                let mut n = NewRegistryAnswers::default();
                if facts.tpm_usable() || !facts.fido2_present() {
                    n.first = FirstKind::Tpm;
                } else {
                    n.first = FirstKind::Fido2;
                }
                if !nk_is_empty(&self.loaded.node_key_file) {
                    n.adopt_key_file = Some(self.loaded.node_key_file.clone());
                }
                if n.adopt_key_file.is_none()
                    && Path::new(&self.keystore_dir).join("keystore.json").exists()
                {
                    n.adopt_key_file = Some(String::new());
                }
                Authority::NewRegistry(n)
            }
        });
        self.install_udev_rule = matches!(
            &self.authority,
            Some(Authority::NewRegistry(n)) if n.first == FirstKind::Fido2
        );
    }

    /// Default location of a generated key file.
    pub fn default_key_file(&self) -> String {
        if self.loaded.config_exists && !nk_is_empty(&self.loaded.node_key_file) {
            return self.loaded.node_key_file.clone();
        }
        let cdir = config_dir(&self.config_path);
        if self.device.use_helper || cdir.starts_with("/etc") {
            "/etc/y2q/node.key".to_owned()
        } else {
            path_string(cdir.join("node.key"))
        }
    }

    /// Resolve `daemon_user`'s uid into `device.peer_uid` (helper mode only).
    pub fn resolve_ids(&mut self, probes: &dyn Probes) {
        if self.device.use_helper
            && let Some(u) = probes.lookup_user(&self.daemon_user)
        {
            self.device.peer_uid = Some(u.uid);
        }
    }

    /// The plan wants the Device config group.
    pub fn involves_registry(&self) -> bool {
        self.authority
            .as_ref()
            .is_some_and(Authority::involves_registry)
    }
}

fn nk_is_empty(s: &str) -> bool {
    s.trim().is_empty()
}

/// Default when no `Keep` is offered: `Generate` unless a keystore already
/// exists (it would orphan the data), in which case there is no default.
fn default_new_authority(a: &Answers, _facts: &Facts) -> Option<Authority> {
    let keystore_exists = Path::new(&a.keystore_dir).join("keystore.json").exists()
        || Path::new(&a.keystore_dir).join("devices.json").exists();
    if keystore_exists {
        None
    } else {
        Some(Authority::OperatorKey {
            mode: KeySource::Generate,
            file: a.default_key_file(),
        })
    }
}

/// Typed reads from the user's parsed config.
struct Reader<'a> {
    doc: &'a DocumentMut,
    unreadable: Vec<String>,
}

fn lookup<'a>(doc: &'a DocumentMut, path: &[&str]) -> Option<&'a Item> {
    let mut cur: &dyn TableLike = doc.as_table();
    for (i, k) in path.iter().enumerate() {
        let it = cur.get(k)?;
        if i + 1 == path.len() {
            return Some(it);
        }
        cur = it.as_table_like()?;
    }
    None
}

impl Reader<'_> {
    fn flag(&mut self, path: &[&str]) {
        self.unreadable.push(path.join("."));
    }

    /// `true` when the key exists with the right type (and `out` was set).
    fn string(&mut self, path: &[&str], out: &mut String) -> bool {
        match lookup(self.doc, path) {
            None => false,
            Some(it) => match it.as_str() {
                Some(s) => {
                    *out = s.to_owned();
                    true
                }
                None => {
                    self.flag(path);
                    false
                }
            },
        }
    }

    fn boolean(&mut self, path: &[&str], out: &mut bool) -> bool {
        match lookup(self.doc, path) {
            None => false,
            Some(it) => match it.as_bool() {
                Some(b) => {
                    *out = b;
                    true
                }
                None => {
                    self.flag(path);
                    false
                }
            },
        }
    }

    fn num<T: TryFrom<i64>>(&mut self, path: &[&str], out: &mut T) -> bool {
        match lookup(self.doc, path) {
            None => false,
            Some(it) => match it.as_integer().and_then(|n| T::try_from(n).ok()) {
                Some(n) => {
                    *out = n;
                    true
                }
                None => {
                    self.flag(path);
                    false
                }
            },
        }
    }

    fn choice(&mut self, path: &[&str], out: &mut String, allowed: &[&str]) {
        let mut s = String::new();
        if self.string(path, &mut s) {
            if allowed.contains(&s.as_str()) {
                *out = s;
            } else {
                self.flag(path);
            }
        }
    }

    fn tls(&mut self, base: &[&str], out: &mut TlsAnswers) {
        let k = |leaf: &'static str| -> Vec<&str> {
            let mut v = base.to_vec();
            v.push(leaf);
            v
        };
        self.boolean(&k("enabled"), &mut out.enabled);
        self.string(&k("cert_path"), &mut out.cert_path);
        self.string(&k("key_path"), &mut out.key_path);
        self.string(&k("client_ca_path"), &mut out.client_ca_path);
        self.boolean(&k("require_pq_kex"), &mut out.require_pq_kex);
    }

    fn servers(&mut self, path: &[&str]) -> Option<Vec<RoughtimeServerAnswer>> {
        let it = lookup(self.doc, path)?;
        let tables: Vec<&dyn TableLike> = if let Some(aot) = it.as_array_of_tables() {
            aot.iter().map(|t| t as &dyn TableLike).collect()
        } else if let Some(arr) = it.as_array() {
            let v: Vec<_> = arr
                .iter()
                .filter_map(|v| v.as_inline_table().map(|t| t as &dyn TableLike))
                .collect();
            if v.len() != arr.len() {
                self.flag(path);
                return None;
            }
            v
        } else {
            self.flag(path);
            return None;
        };
        let mut out = Vec::new();
        for t in tables {
            let get = |k: &str| t.get(k).and_then(|i| i.as_str()).map(str::to_owned);
            match (get("name"), get("addr"), get("public_key_b64")) {
                (Some(name), Some(addr), Some(public_key_b64)) => out.push(RoughtimeServerAnswer {
                    name,
                    addr,
                    public_key_b64,
                }),
                _ => {
                    self.flag(path);
                    return None;
                }
            }
        }
        Some(out)
    }
}

/// One flattened config key whose value differs between two renderings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyChange {
    pub path: String,
    pub old: Option<String>,
    pub new: Option<String>,
}
