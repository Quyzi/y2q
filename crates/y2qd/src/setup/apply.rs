//! Planning, preflight and the ordered apply.
//!
//! `build_plan` is pure with respect to the filesystem (it only reads);
//! `preflight` re-checks everything without side effects; `run` performs the
//! changes, stopping at the first error and printing what is done and what is
//! not. No `umask` call anywhere: every created file and directory gets its
//! mode at creation and again through an fd.

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use super::answers::{Answers, Authority, FirstKind, KeepKind, KeyChange, KeySource, is_within};
use super::authority;
use super::config_doc;
use super::existing::{ExistingInstall, PathPair, Tri};
use super::sanitize;
use super::sys;
use super::units::{self, UnitParams};
use super::validate::{self, Ctx, Issue, Probes, Sev, Step};
use crate::config::Config;

// --- plan ----------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DirPlan {
    pub path: PathBuf,
    pub mode: u32,
    pub owner: Option<(u32, u32)>,
    pub exists: bool,
}

#[derive(Debug, Clone)]
pub struct OwnershipPlan {
    pub path: PathBuf,
    pub mode: u32,
    pub owner: Option<(u32, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityAction {
    /// Nothing to create (Keep, UseExisting).
    Nothing,
    GenerateKey {
        file: String,
    },
    CreateRegistry {
        description: String,
        adopts: Option<String>,
    },
    /// Config-only: drop `node_key_file` for an already-adopted registry.
    FinishMigration,
}

impl AuthorityAction {
    /// Cannot be undone by restoring the config backup.
    pub fn irreversible(&self) -> bool {
        matches!(
            self,
            AuthorityAction::GenerateKey { .. } | AuthorityAction::CreateRegistry { .. }
        )
    }

    pub fn describe(&self) -> Option<String> {
        match self {
            AuthorityAction::Nothing => None,
            AuthorityAction::GenerateKey { file } => Some(format!(
                "generate a new node key at {file} (mode 0400; it is shown nowhere and cannot be regenerated)"
            )),
            AuthorityAction::CreateRegistry {
                description,
                adopts,
            } => Some(match adopts {
                Some(f) => format!(
                    "create a device registry ({description}); it adopts the node key in {f}, which keeps working"
                ),
                None => format!(
                    "create a device registry ({description}) with a NEW node key; the emergency code sheet is shown once"
                ),
            }),
            AuthorityAction::FinishMigration => Some(
                "stop naming the node-key file in the config (the registry already holds the key)"
                    .into(),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitState {
    Create,
    Replace,
    Same,
}

#[derive(Debug, Clone)]
pub struct UnitPlan {
    pub path: PathBuf,
    pub state: UnitState,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct PlanWarning {
    pub text: String,
    /// Shown in red.
    pub severe: bool,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub config_path: PathBuf,
    pub config_existed: bool,
    pub base_text: String,
    pub rendered: String,
    pub changes: Vec<KeyChange>,
    pub dirs: Vec<DirPlan>,
    pub ownership: Vec<OwnershipPlan>,
    pub authority: AuthorityAction,
    pub units: Vec<UnitPlan>,
    pub warnings: Vec<PlanWarning>,
    pub answers: Answers,
    pub defaults: Answers,
}

impl Plan {
    /// Nothing to do: Review says so and Apply is disabled.
    pub fn is_noop(&self) -> bool {
        self.config_existed
            && self.changes.is_empty()
            && self.dirs.iter().all(|d| d.exists)
            && self.ownership.is_empty()
            && self.units.iter().all(|u| u.state == UnitState::Same)
            && self.authority == AuthorityAction::Nothing
    }

    pub fn dirs_to_create(&self) -> impl Iterator<Item = &DirPlan> {
        self.dirs.iter().filter(|d| !d.exists)
    }
}

/// Helper mode is in effect: a registry plan with the key helper on.
pub fn helper_effective(a: &Answers) -> bool {
    a.device.use_helper && a.involves_registry()
}

/// Whether `ExecStartPre=+... --key-arm` is kept in `y2qd.service`.
pub fn arm_on_start(a: &Answers, probes: &dyn Probes) -> bool {
    match &a.authority {
        Some(Authority::NewRegistry(n)) => n.first == FirstKind::Tpm,
        Some(Authority::Keep(KeepKind::Registry)) | Some(Authority::FinishMigration { .. }) => {
            match probes.registry_summary(Path::new(&a.keystore_dir)) {
                Some(s) => s.has_home && !s.home_has_second_factor,
                None => a.device.arm_on_start,
            }
        }
        _ => false,
    }
}

/// True when the registry summary is unavailable and the toggle decides.
pub fn arm_toggle_needed(a: &Answers, probes: &dyn Probes) -> bool {
    helper_effective(a)
        && matches!(
            &a.authority,
            Some(Authority::Keep(KeepKind::Registry)) | Some(Authority::FinishMigration { .. })
        )
        && probes
            .registry_summary(Path::new(&a.keystore_dir))
            .is_none()
}

fn ids(a: &Answers, cx: &Ctx) -> (Option<(u32, u32)>, Option<u32>) {
    // (daemon uid:group gid, key uid), resolved only when ownership is applied.
    if cx.facts.euid != 0 {
        return (None, None);
    }
    let du = cx.probes.lookup_user(&a.daemon_user);
    let gid = cx.probes.lookup_group(&a.group);
    let owner = match (du, gid) {
        (Some(u), Some(g)) => Some((u.uid, g)),
        _ => None,
    };
    let key = cx.probes.lookup_user(&a.device.key_user).map(|u| u.uid);
    (owner, key)
}

fn config_parent(config: &Path) -> PathBuf {
    let target = fs::canonicalize(config).unwrap_or_else(|_| config.to_path_buf());
    target
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn rw_dirs(a: &Answers) -> Vec<String> {
    let mut v: Vec<String> = vec![a.base_path.clone(), a.keystore_dir.clone()];
    if let Some(idx) = &a.index_path
        && let Some(parent) = Path::new(idx).parent()
        && !is_within(parent, Path::new(&a.base_path))
    {
        v.push(parent.to_string_lossy().into_owned());
    }
    v.dedup();
    v
}

fn unit_params(a: &Answers, probes: &dyn Probes) -> UnitParams {
    UnitParams {
        bin: a.binary_path.clone(),
        config: a.config_path.to_string_lossy().into_owned(),
        daemon_user: a.daemon_user.clone(),
        key_user: a.device.key_user.clone(),
        group: a.group.clone(),
        socket_group: a.socket_group.clone(),
        key_user_group: a.key_user_group.clone(),
        socket_path: a.device.socket_path.clone(),
        state_dir: a.device.state_dir.clone(),
        keystore_dir: a.keystore_dir.clone(),
        rw_dirs: rw_dirs(a),
        helper: helper_effective(a),
        arm_on_start: arm_on_start(a, probes),
        udev_vendor_id: a.udev_vendor_id.clone(),
    }
}

/// Build the plan: render the config, diff it, and list every side effect.
pub fn build_plan(
    a: &Answers,
    defaults: &Answers,
    base_text: &str,
    cx: &Ctx,
    now: DateTime<Utc>,
) -> Result<Plan, String> {
    let config_existed = a.config_path.exists();
    let rendered = config_doc::render(base_text, a, defaults, now, None)?;
    let changes = config_doc::changes(base_text, &rendered)?;
    let (owner, key_uid) = ids(a, cx);
    let helper = helper_effective(a);

    type DirSpec = (PathBuf, u32, Option<(u32, u32)>);
    let mut dir_specs: Vec<DirSpec> = Vec::new();
    dir_specs.push((config_parent(&a.config_path), 0o755, None));
    if let Some(Authority::OperatorKey {
        mode: KeySource::Generate,
        file,
    }) = &a.authority
        && let Some(p) = Path::new(file).parent()
    {
        dir_specs.push((p.to_path_buf(), 0o755, None));
    }
    dir_specs.push((PathBuf::from(&a.base_path), 0o750, owner));
    dir_specs.push((
        PathBuf::from(&a.keystore_dir),
        if helper { 0o1770 } else { 0o700 },
        owner,
    ));
    let mut units_plan = Vec::new();
    if a.install_units {
        let root = PathBuf::from(&a.unit_root);
        dir_specs.push((root.join("systemd/system"), 0o755, None));
        if helper {
            dir_specs.push((root.join("tmpfiles.d"), 0o755, None));
        }
        if a.install_udev_rule && helper {
            dir_specs.push((root.join("udev/rules.d"), 0o755, None));
        }
        let files = units::render(&unit_params(a, cx.probes), a.install_udev_rule && helper)?;
        for f in files {
            let path = root.join(&f.rel_path);
            let state = match fs::read_to_string(&path) {
                Ok(old) if old == f.content => UnitState::Same,
                Ok(_) => UnitState::Replace,
                Err(_) => UnitState::Create,
            };
            units_plan.push(UnitPlan {
                path,
                state,
                content: f.content,
            });
        }
    }
    let mut dirs: Vec<DirPlan> = Vec::new();
    for (path, mode, owner) in dir_specs {
        if dirs.iter().any(|d| d.path == path) {
            continue;
        }
        let exists = path.exists();
        dirs.push(DirPlan {
            path,
            mode,
            owner,
            exists,
        });
    }

    let ks = PathBuf::from(&a.keystore_dir);
    let creates_registry = matches!(&a.authority, Some(Authority::NewRegistry(_)));
    let mut ownership = Vec::new();
    if cx.facts.euid == 0 {
        let reg_owner = if helper {
            key_uid.zip(owner.map(|o| o.1))
        } else {
            owner
        };
        if creates_registry {
            ownership.push(OwnershipPlan {
                path: ks.join("devices.json"),
                mode: 0o600,
                owner: reg_owner,
            });
            ownership.push(OwnershipPlan {
                path: ks.join(".devices.lock"),
                mode: 0o600,
                owner: reg_owner,
            });
        }
        if creates_registry || helper {
            ownership.push(OwnershipPlan {
                path: ks.join(".lock"),
                mode: 0o660,
                owner,
            });
        }
    }

    let authority = match &a.authority {
        Some(Authority::OperatorKey {
            mode: KeySource::Generate,
            file,
        }) => AuthorityAction::GenerateKey { file: file.clone() },
        Some(Authority::NewRegistry(n)) => AuthorityAction::CreateRegistry {
            description: match n.first {
                FirstKind::Tpm => "TPM home device".to_owned(),
                FirstKind::Fido2 => "FIDO2 away device, no home device".to_owned(),
            },
            adopts: n.adopt_key_file.clone().filter(|f| !f.is_empty()),
        },
        Some(Authority::FinishMigration { .. }) => AuthorityAction::FinishMigration,
        _ => AuthorityAction::Nothing,
    };

    let mut warnings: Vec<PlanWarning> = validate::all(a, cx)
        .into_iter()
        .filter(|i| i.sev == Sev::Warning)
        .map(|i| PlanWarning {
            text: i.msg,
            severe: matches!(i.field, "enforce_authz" | "allow_sb_off" | "uv_required"),
        })
        .collect();
    if let Some(Authority::NewRegistry(n)) = &a.authority {
        if !n.uv_required && n.first == FirstKind::Fido2 {
            warnings.push(PlanWarning {
                text: "PIN/UV is not required: the token alone unlocks the registry".into(),
                severe: true,
            });
        }
        if n.allow_secure_boot_off {
            warnings.push(PlanWarning {
                text: "PCR 7 without Secure Boot: any bootable medium can satisfy the TPM policy"
                    .into(),
                severe: true,
            });
        }
        if n.adopt_key_file.as_deref().is_some_and(|f| !f.is_empty()) {
            warnings.push(PlanWarning {
                text: "the old key file still unlocks this deployment: back it up offline or remove it; to revert, restore the .bak- config".into(),
                severe: false,
            });
        }
    }
    if a.involves_registry() && !a.device.use_helper {
        warnings.push(PlanWarning {
            text: "weaker mode: the daemon holds RMK and hardware access".into(),
            severe: false,
        });
    }
    for u in &a.unreadable {
        warnings.push(PlanWarning {
            text: format!("config key {u} has the wrong type and was reset to its default"),
            severe: false,
        });
    }

    Ok(Plan {
        config_path: a.config_path.clone(),
        config_existed,
        base_text: base_text.to_owned(),
        rendered,
        changes,
        dirs,
        ownership,
        authority,
        units: units_plan,
        warnings,
        answers: a.clone(),
        defaults: defaults.clone(),
    })
}

// --- preflight -----------------------------------------------------------------

fn review_err(field: &'static str, msg: impl Into<String>) -> Issue {
    Issue {
        step: Step::Review,
        field,
        sev: Sev::Error,
        msg: msg.into(),
    }
}

fn walk_issue(path: &Path, allowed_leaf: &[u32]) -> Option<String> {
    let anc = sys::nearest_existing_ancestor(path);
    let canon = fs::canonicalize(&anc).ok()?;
    let leaf_exists = canon == fs::canonicalize(path).unwrap_or_default();
    let mut prefix = PathBuf::new();
    let comps: Vec<_> = canon.components().collect();
    for (i, c) in comps.iter().enumerate() {
        prefix.push(c.as_os_str());
        let is_leaf = leaf_exists && i + 1 == comps.len();
        let Ok(st) = sys::lstat(&prefix) else {
            continue;
        };
        let sticky = st.perm() & 0o1000 != 0;
        if is_leaf {
            if !allowed_leaf.contains(&st.uid) {
                return Some(format!(
                    "{} is owned by uid {}, not by root or the daemon user",
                    prefix.display(),
                    st.uid
                ));
            }
            if st.perm() & 0o002 != 0 && !sticky {
                return Some(format!("{} is world-writable", prefix.display()));
            }
        } else {
            if st.uid != 0 {
                return Some(format!(
                    "{} (an ancestor of {}) is owned by uid {}, not root: whoever owns it can swap the path",
                    prefix.display(),
                    path.display(),
                    st.uid
                ));
            }
            if st.perm() & 0o022 != 0 && !sticky {
                return Some(format!(
                    "{} (an ancestor of {}) is group- or world-writable",
                    prefix.display(),
                    path.display()
                ));
            }
        }
    }
    None
}

/// Side-effect-free re-check of the plan against the current host.
pub fn preflight(plan: &Plan, cx: &Ctx) -> Vec<Issue> {
    let a = &plan.answers;
    let mut issues: Vec<Issue> = validate::all(a, cx)
        .into_iter()
        .filter(Issue::is_error)
        .collect();

    // Existing state, recomputed from the current and the loaded paths.
    let (ks, base) = (PathBuf::from(&a.keystore_dir), PathBuf::from(&a.base_path));
    let loaded_ks = a.loaded.keystore_dir.as_ref().map(PathBuf::from);
    let loaded_base = a.loaded.base_path.as_ref().map(PathBuf::from);
    let mut pairs = vec![PathPair {
        base_path: &base,
        keystore_dir: &ks,
    }];
    if let (Some(b), Some(k)) = (&loaded_base, &loaded_ks) {
        pairs.push(PathPair {
            base_path: b,
            keystore_dir: k,
        });
    }
    let ex = ExistingInstall::detect(&plan.config_path, &pairs, cx.probes);
    match ex.daemon_running {
        Tri::Yes => issues.push(review_err(
            "daemon",
            "y2qd is running against this keystore: stop y2qd first",
        )),
        Tri::Unknown => issues.push(Issue {
            step: Step::Review,
            field: "daemon",
            sev: Sev::Warning,
            msg: "cannot tell whether y2qd is running (lock file unreadable)".into(),
        }),
        Tri::No => {}
    }

    // The config must not have changed since the plan was made.
    match fs::read_to_string(&plan.config_path) {
        Ok(now_text) if plan.config_existed && now_text == plan.base_text => {}
        Ok(_) if plan.config_existed => issues.push(review_err(
            "config",
            "the config file changed on disk since setup read it; re-run `y2qd setup`",
        )),
        Ok(_) => issues.push(review_err(
            "config",
            "a config file appeared since setup started; re-run `y2qd setup`",
        )),
        Err(e) if !plan.config_existed && e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => issues.push(review_err(
            "config",
            format!("cannot read {}: {e}", plan.config_path.display()),
        )),
    }

    // The rendered file must load, and the node key must have a source.
    match Config::from_toml_str(&plan.rendered) {
        Ok(_) => {}
        Err(e) => issues.push(review_err(
            "config",
            format!("the rendered config does not load: {e}"),
        )),
    }
    let source_ok = match &a.authority {
        Some(Authority::OperatorKey { file, .. }) => !file.trim().is_empty(),
        Some(Authority::Keep(KeepKind::Operator)) => !a.loaded.node_key_file.trim().is_empty(),
        Some(Authority::Keep(KeepKind::Registry)) => ks.join("devices.json").exists(),
        Some(Authority::FinishMigration { .. }) | Some(Authority::NewRegistry(_)) => true,
        None => false,
    };
    if !source_ok {
        issues.push(review_err(
            "authority",
            "the planned configuration has no node-key source",
        ));
    }

    let staged = config_doc::staged_tmp_path(&plan.config_path);
    if staged.exists() {
        issues.push(review_err(
            "config",
            format!(
                "stale file {} from an interrupted run (or another setup is running); delete it",
                staged.display()
            ),
        ));
    }

    // Creatable parents.
    for d in plan.dirs.iter().filter(|d| !d.exists) {
        let anc = sys::nearest_existing_ancestor(&d.path);
        let info = cx.probes.dir_info(&anc);
        if !info.is_dir || (cx.facts.euid != 0 && !info.writable) {
            issues.push(review_err(
                "dirs",
                format!(
                    "cannot create {}: {} is not a writable directory",
                    d.path.display(),
                    anc.display()
                ),
            ));
        }
    }

    // As root every path the daemon will write must not be steerable by others.
    let daemon_uid = cx.probes.lookup_user(&a.daemon_user).map(|u| u.uid);
    let key_uid = cx.probes.lookup_user(&a.device.key_user).map(|u| u.uid);
    let mut leaf_owners: Vec<u32> = vec![0];
    leaf_owners.extend(daemon_uid);
    leaf_owners.extend(key_uid);
    if cx.facts.euid == 0 {
        for d in &plan.dirs {
            if let Some(msg) = walk_issue(&d.path, &leaf_owners) {
                issues.push(review_err("dirs", msg));
            }
        }
    } else {
        for d in plan.dirs.iter().filter(|d| d.exists) {
            if let Some(uid) = cx.probes.file_owner(&d.path)
                && uid != cx.facts.euid
            {
                issues.push(Issue {
                    step: Step::Review,
                    field: "dirs",
                    sev: Sev::Warning,
                    msg: format!("{} is owned by uid {uid}, not you", d.path.display()),
                });
            }
        }
    }
    issues
}

// --- apply ---------------------------------------------------------------------

#[derive(Debug)]
pub struct ApplyFailure {
    pub message: String,
    pub recovery: Vec<String>,
}

impl ApplyFailure {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            recovery: Vec::new(),
        }
    }

    fn with(mut self, line: impl Into<String>) -> Self {
        self.recovery.push(line.into());
        self
    }
}

/// Shell-quote a path for copy-paste.
pub fn shq(s: &str) -> String {
    if !s.is_empty()
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '+' | ':' | '@' | '=')
        })
    {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

fn say(line: &str) {
    println!("{}", sanitize(line));
}

struct Progress {
    done: Vec<String>,
}

impl Progress {
    fn ok(&mut self, msg: impl Into<String>) {
        let m = msg.into();
        say(&format!("  done: {m}"));
        self.done.push(m);
    }

    fn warn(&self, msg: &str) {
        say(&format!("  warning: {msg}"));
    }
}

fn io_s(what: &str, path: &Path, e: std::io::Error) -> String {
    format!("{what} {}: {e}", path.display())
}

/// Create `path` (and missing ancestors) and fix modes/owners **only on the
/// components this call created**. Returns the warnings about an existing leaf.
pub fn ensure_dir(
    path: &Path,
    mode: u32,
    owner: Option<(u32, u32)>,
    euid: u32,
) -> Result<Vec<String>, String> {
    let mut missing = Vec::new();
    let mut cur = path.to_path_buf();
    loop {
        match sys::lstat(&cur) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cur.clone());
                if !cur.pop() {
                    break;
                }
            }
            Err(e) => return Err(io_s("stat", &cur, e)),
        }
    }
    missing.reverse();
    let mut warnings = Vec::new();
    let n = missing.len();
    for (i, p) in missing.iter().enumerate() {
        let leaf = i + 1 == n;
        let m = if leaf { mode } else { 0o755 };
        fs::DirBuilder::new()
            .mode(m)
            .create(p)
            .map_err(|e| io_s("create directory", p, e))?;
        let f = sys::open_nofollow(p, libc::O_RDONLY | libc::O_DIRECTORY, 0)
            .map_err(|e| io_s("open", p, e))?;
        let st = sys::fstat(&f).map_err(|e| io_s("stat", p, e))?;
        if !st.is_dir() || st.uid != euid {
            return Err(format!(
                "{} is not the directory this run just created (changed underneath us)",
                p.display()
            ));
        }
        sys::fchmod(&f, m).map_err(|e| io_s("chmod", p, e))?;
        if leaf
            && euid == 0
            && let Some((uid, gid)) = owner
        {
            sys::fchown(&f, Some(uid), Some(gid)).map_err(|e| io_s("chown", p, e))?;
        }
    }
    if missing.is_empty() {
        let f = sys::open_nofollow(path, libc::O_RDONLY | libc::O_DIRECTORY, 0)
            .map_err(|e| io_s("open directory", path, e))?;
        let st = sys::fstat(&f).map_err(|e| io_s("stat", path, e))?;
        if let Some((uid, _)) = owner
            && st.uid != uid
        {
            warnings.push(format!(
                "{} exists and is owned by uid {}, not {uid}; left as is",
                path.display(),
                st.uid
            ));
        }
        // Only a wider existing mode is worth a warning; stricter is safe.
        if st.perm() & !mode != 0 {
            warnings.push(format!(
                "{} exists with mode {:04o}, not {mode:04o}; left as is",
                path.display(),
                st.perm()
            ));
        }
    }
    Ok(warnings)
}

/// Pre-create a lock file so core's by-path open cannot be redirected. An
/// existing entry must be a regular, singly-linked file. Returns whether this
/// call created it.
fn precreate_lock(
    path: &Path,
    mode: u32,
    owner: Option<(u32, u32)>,
    euid: u32,
) -> Result<bool, String> {
    match sys::lstat(path) {
        Ok(st) => {
            if !st.is_file() || st.nlink != 1 {
                return Err(format!(
                    "{} exists but is not a regular, singly-linked file (symlink or hard link?); remove it",
                    path.display()
                ));
            }
            Ok(false)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let f = sys::open_nofollow(
                path,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOCTTY,
                mode,
            )
            .map_err(|e| io_s("create", path, e))?;
            sys::fchmod(&f, mode).map_err(|e| io_s("chmod", path, e))?;
            if euid == 0
                && let Some((uid, gid)) = owner
            {
                sys::fchown(&f, Some(uid), Some(gid)).map_err(|e| io_s("chown", path, e))?;
            }
            Ok(true)
        }
        Err(e) => Err(io_s("stat", path, e)),
    }
}

/// chown/chmod an existing regular file through an fd, never by path.
fn fix_file(path: &Path, mode: u32, owner: Option<(u32, u32)>) -> Result<(), String> {
    let f = sys::open_nofollow(path, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY, 0)
        .map_err(|e| io_s("open", path, e))?;
    let st = sys::fstat(&f).map_err(|e| io_s("stat", path, e))?;
    if !st.is_file() || st.nlink != 1 {
        return Err(format!(
            "{} is not a regular, singly-linked file",
            path.display()
        ));
    }
    if let Some((uid, gid)) = owner {
        sys::fchown(&f, Some(uid), Some(gid)).map_err(|e| io_s("chown", path, e))?;
    }
    sys::fchmod(&f, mode).map_err(|e| io_s("chmod", path, e))
}

fn recheck_config_unchanged(plan: &Plan) -> Result<(), ApplyFailure> {
    match fs::read_to_string(&plan.config_path) {
        Ok(t) if plan.config_existed && t == plan.base_text => Ok(()),
        Err(e) if !plan.config_existed && e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(ApplyFailure::new(
            "the config file changed on disk while setup was running; nothing was committed to it",
        )),
    }
}

/// Run the plan. Prints progress and the summary; the TUI has been left.
pub fn run(plan: &Plan, probes: &dyn Probes, now: DateTime<Utc>) -> Result<(), ApplyFailure> {
    let a = &plan.answers;
    let euid = sys::euid();
    let root = euid == 0;
    let mut prog = Progress { done: Vec::new() };
    let helper = helper_effective(a);
    let ks = PathBuf::from(&a.keystore_dir);

    // 1. Directories.
    for d in &plan.dirs {
        let owner = if root { d.owner } else { None };
        match ensure_dir(&d.path, d.mode, owner, euid) {
            Ok(w) => {
                for line in &w {
                    prog.warn(line);
                }
                if !d.exists {
                    prog.ok(format!(
                        "created directory {} ({:04o})",
                        d.path.display(),
                        d.mode
                    ));
                }
            }
            Err(e) => return Err(ApplyFailure::new(e)),
        }
    }

    // 2. Lock files, before core runs.
    let creates_registry = matches!(&a.authority, Some(Authority::NewRegistry(_)));
    let mut made_locks: Vec<PathBuf> = Vec::new();
    if creates_registry || helper {
        let owner_of = |p: &Path| {
            plan.ownership
                .iter()
                .find(|o| o.path == p)
                .and_then(|o| o.owner)
        };
        let lock = ks.join(".lock");
        if precreate_lock(&lock, 0o660, owner_of(&lock), euid).map_err(ApplyFailure::new)? {
            made_locks.push(lock);
        }
        if creates_registry {
            let dl = ks.join(".devices.lock");
            if precreate_lock(&dl, 0o600, owner_of(&dl), euid).map_err(ApplyFailure::new)? {
                made_locks.push(dl);
            }
        }
        prog.ok("lock files ready");
    }

    // 3. Units.
    for u in &plan.units {
        match u.state {
            UnitState::Same => say(&format!("  same: {}", u.path.display())),
            state => {
                let backup =
                    (state == UnitState::Replace).then(|| config_doc::backup_path(&u.path, now));
                let staged = config_doc::stage(&u.path, u.content.as_bytes(), 0o644)
                    .map_err(|e| ApplyFailure::new(e.to_string()))?;
                config_doc::commit(staged, backup.as_deref())
                    .map_err(|e| ApplyFailure::new(e.to_string()))?;
                prog.ok(format!("installed {}", u.path.display()));
                if let Some(b) = backup {
                    say(&format!("    previous version saved as {}", b.display()));
                }
            }
        }
    }

    // 4. Stage the config (holds its flock until commit).
    let config_changed = !plan.changes.is_empty() || !plan.config_existed;
    let backup = (plan.config_existed && config_changed)
        .then(|| config_doc::backup_path(&plan.config_path, now));
    let staged = if config_changed {
        let text = config_doc::render(&plan.base_text, a, &plan.defaults, now, backup.as_deref())
            .map_err(ApplyFailure::new)?;
        Some(
            config_doc::stage(&plan.config_path, text.as_bytes(), 0o644)
                .map_err(|e| ApplyFailure::new(e.to_string()))?,
        )
    } else {
        None
    };

    // 5. Authority.
    #[cfg_attr(not(feature = "devices"), allow(unused_mut))]
    let mut registry_made = false;
    #[cfg_attr(not(feature = "devices"), allow(unused_mut))]
    let mut registry_line: Option<String> = None;
    match &plan.authority {
        AuthorityAction::GenerateKey { file } => {
            let owner = if root {
                probes
                    .lookup_user(&a.daemon_user)
                    .map(|u| (u.uid, probes.lookup_group(&a.group).unwrap_or(u.gid)))
            } else {
                if probes
                    .lookup_user(&a.daemon_user)
                    .is_some_and(|u| u.uid != euid)
                {
                    prog.warn(
                        "the daemon uid cannot read the generated key file (it is owned by you)",
                    );
                }
                None
            };
            authority::generate_key_file(Path::new(file), owner).map_err(|e| {
                ApplyFailure::new(e)
                    .with("if a previous attempt created the key file, re-run setup and choose \"Use existing\" for the key source")
            })?;
            prog.ok(format!("generated node key {file} (0400)"));
        }
        AuthorityAction::CreateRegistry { .. } => {
            let Some(Authority::NewRegistry(n)) = &a.authority else {
                return Err(ApplyFailure::new("internal: authority mismatch"));
            };
            #[cfg(feature = "devices")]
            {
                say("  creating the device registry (PIN and touch prompts may follow)...");
                let outcome = authority::create_registry(
                    &ks,
                    n,
                    &a.device.tcti,
                    y2q_core::crypto::devices::now_unix(),
                );
                match outcome {
                    Ok(o) => {
                        registry_made = true;
                        registry_line = Some(format!(
                            "registry {} (device {} id {})",
                            o.registry_path.display(),
                            o.device_label,
                            o.device_id
                        ));
                        prog.ok("device registry created (emergency codes were shown)");
                    }
                    Err(f) => {
                        let mut fail = ApplyFailure::new(f.message);
                        if f.registry_exists {
                            fail = fail
                                .with("the registry exists; the codes shown are valid")
                                .with("the config was NOT written; re-run `y2qd setup` and choose \"Keep current\"");
                            let mut created = made_locks.clone();
                            created.push(ks.join("devices.json"));
                            let _ = apply_ownership(plan, &created, &mut prog);
                        } else {
                            fail = fail.with("codes shown (if any) are VOID; nothing was created");
                        }
                        return Err(fail);
                    }
                }
            }
            #[cfg(not(feature = "devices"))]
            {
                let _ = n;
                return Err(ApplyFailure::new("this build has no device support"));
            }
        }
        AuthorityAction::FinishMigration | AuthorityAction::Nothing => {}
    }

    // Ownership fixes for files this run created. Fatal for root.
    let mut created = made_locks.clone();
    if registry_made {
        created.push(ks.join("devices.json"));
    }
    if let Err(f) = apply_ownership(plan, &created, &mut prog) {
        let mut f = f;
        if registry_made {
            f = f.with("the registry exists and its codes are valid; fix the ownership above and re-run `y2qd setup` (choose \"Keep current\")");
        }
        return Err(f);
    }

    // 6. Commit the config.
    if let Some(staged) = staged {
        if let Err(f) = recheck_config_unchanged(plan) {
            let mut f = f;
            if registry_made {
                f = f.with("the registry was created (codes were shown); config NOT written; re-run `y2qd setup`");
            }
            return Err(f);
        }
        config_doc::commit(staged, backup.as_deref()).map_err(|e| {
            let mut f = ApplyFailure::new(e.to_string());
            if registry_made {
                f = f.with("the registry was created (codes were shown); config NOT written; re-run `y2qd setup` and choose \"Keep current\" (or \"Finish registry migration\" when adopting)");
            }
            f
        })?;
        prog.ok(format!("wrote {}", plan.config_path.display()));
        if let Some(b) = &backup {
            say(&format!("    previous version saved as {}", b.display()));
        }

        // 7. Post-check on the file as written.
        let check = fs::read_to_string(&plan.config_path)
            .map_err(|e| e.to_string())
            .and_then(|t| Config::from_toml_str(&t).map_err(|e| e.to_string()))
            .and_then(|c| c.validate_node_key_source().map_err(|e| e.to_string()));
        if let Err(e) = check {
            let mut f = ApplyFailure::new(format!("the written config does not validate: {e}"));
            if let Some(b) = &backup {
                f = f.with(format!(
                    "restore the previous config: mv {} {}",
                    shq(&b.to_string_lossy()),
                    shq(&plan.config_path.to_string_lossy())
                ));
            }
            if matches!(a.authority, Some(Authority::NewRegistry(_)))
                && !a.loaded.node_key_file.is_empty()
            {
                f = f.with("the old node key file remains valid");
            }
            return Err(f);
        }
    }

    // 8. Summary.
    for line in summary(plan, probes, backup.as_deref(), registry_line.as_deref()) {
        say(&line);
    }
    Ok(())
}

/// Fix owner and mode of the files this run created (`created`). Fatal as
/// root; a mismatch is only a warning otherwise.
fn apply_ownership(
    plan: &Plan,
    created: &[PathBuf],
    prog: &mut Progress,
) -> Result<(), ApplyFailure> {
    let root = sys::euid() == 0;
    for o in plan.ownership.iter().filter(|o| created.contains(&o.path)) {
        if root {
            if let Err(e) = fix_file(&o.path, o.mode, o.owner) {
                let (u, g) = o.owner.unzip();
                let p = shq(&o.path.to_string_lossy());
                return Err(ApplyFailure::new(e).with(format!(
                    "fix by hand: chown {}:{} {p} && chmod {:04o} {p}",
                    u.map_or("?".into(), |v| v.to_string()),
                    g.map_or("?".into(), |v| v.to_string()),
                    o.mode,
                )));
            }
            prog.ok(format!("set {} to {:04o}", o.path.display(), o.mode));
        } else if let Ok(st) = sys::lstat(&o.path)
            && let Some((uid, _)) = o.owner
            && st.uid != uid
        {
            prog.warn(&format!(
                "{} is owned by uid {}, not {uid}; fix with chown as root",
                o.path.display(),
                st.uid
            ));
        }
    }
    Ok(())
}

/// The closing report: what changed and only the applicable next steps.
pub fn summary(
    plan: &Plan,
    probes: &dyn Probes,
    backup: Option<&Path>,
    registry_line: Option<&str>,
) -> Vec<String> {
    let a = &plan.answers;
    let q = |p: &Path| shq(&p.to_string_lossy());
    let mut out = vec![String::new(), "y2qd setup complete.".to_owned()];
    out.push(format!("  config: {}", q(&plan.config_path)));
    if let Some(b) = backup {
        out.push(format!("  previous config: {}", q(b)));
    }
    if let Some(l) = registry_line {
        out.push(format!("  {l}"));
    }
    out.push(String::new());
    out.push("Next steps:".to_owned());
    let helper = helper_effective(a);
    let units_on = a.install_units;
    if units_on {
        let root = Path::new(&a.unit_root);
        if helper {
            out.push(format!(
                "  systemd-tmpfiles --create {}",
                q(&root.join("tmpfiles.d/y2q-keyd.conf"))
            ));
            if a.install_udev_rule {
                out.push("  udevadm control --reload && udevadm trigger".to_owned());
            }
            out.push(
                "  systemctl daemon-reload && systemctl enable --now y2q-keyd.socket y2qd.service"
                    .to_owned(),
            );
            // The timer's OnBootSec has already elapsed on a running host, so enabling
            // it fires a sweep at once; that sweep holds the registry lock and would
            // make the daemon's first key fetch fail with "registry is busy".
            out.push(
                "  systemctl enable --now y2q-keyd-sweep.timer   # once `systemctl status y2qd` shows it running"
                    .to_owned(),
            );
        } else {
            out.push("  systemctl daemon-reload && systemctl enable --now y2qd.service".to_owned());
        }
    } else {
        out.push(format!("  y2qd --config {}", q(&plan.config_path)));
    }
    if !Path::new(&a.keystore_dir).join("keystore.json").exists() {
        out.push(format!(
            "  The first start writes {} (mode 0600); setup creates no root user.",
            q(&Path::new(&a.keystore_dir).join("initial-root-password"))
        ));
    }
    if let AuthorityAction::GenerateKey { file } = &plan.authority {
        out.push(format!(
            "  Back up {} out of band: it is shown nowhere and cannot be regenerated.",
            shq(file)
        ));
    }
    if matches!(&plan.authority, AuthorityAction::CreateRegistry { .. }) || a.involves_registry() {
        out.push("  y2q admin device add-fido2 ...   (enroll further away tokens)".to_owned());
        out.push("  y2q admin device check-time ...  (verify Roughtime)".to_owned());
        if helper && !arm_on_start(a, probes) {
            out.push(format!(
                "  sudo y2qd --key-arm --prompt-passcode --prompt-pin --config {}   (before each start)",
                q(&plan.config_path)
            ));
        }
    }
    out.push("  Restart y2qd if it was running before.".to_owned());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::answers::normalize;
    use crate::setup::scan::test_facts;
    use crate::setup::validate::{FakeProbes, ProbeCache};
    use chrono::TimeZone;
    use std::os::unix::fs::PermissionsExt;

    struct Env {
        facts: crate::setup::scan::Facts,
        probes: FakeProbes,
        cache: ProbeCache,
        dir: tempfile::TempDir,
    }

    impl Env {
        fn new() -> Self {
            Self {
                facts: test_facts(),
                probes: FakeProbes::default(),
                cache: ProbeCache::default(),
                dir: tempfile::tempdir().unwrap(),
            }
        }

        fn cx(&self) -> Ctx<'_> {
            Ctx {
                facts: &self.facts,
                probes: &self.probes,
                cache: &self.cache,
                force_probe: false,
            }
        }

        fn config(&self) -> PathBuf {
            self.dir.path().join("etc/config.toml")
        }

        fn answers(&self) -> (Answers, Answers) {
            let d = Answers::defaults(&self.facts, &self.probes, &self.config());
            let mut a = d.clone();
            let root = self.dir.path();
            a.base_path = root.join("data").to_string_lossy().into_owned();
            a.keystore_dir = root.join("keys").to_string_lossy().into_owned();
            a.authority = Some(Authority::OperatorKey {
                mode: KeySource::Generate,
                file: root.join("secret/node.key").to_string_lossy().into_owned(),
            });
            (a, d)
        }

        fn plan(&self, a: &Answers, d: &Answers) -> Plan {
            let base = if a.config_path.exists() {
                fs::read_to_string(&a.config_path).unwrap()
            } else {
                config_doc::fresh_base_text()
            };
            build_plan(a, d, &base, &self.cx(), at(0)).unwrap()
        }
    }

    fn at(s: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_800_000_000 + s, 0).unwrap()
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn fresh_operator_key_install_creates_everything_with_the_stated_modes() {
        let env = Env::new();
        let (a, d) = env.answers();
        let plan = env.plan(&a, &d);
        assert!(!plan.is_noop());
        let issues = preflight(&plan, &env.cx());
        assert!(!validate::has_errors(&issues), "{issues:?}");
        run(&plan, &env.probes, at(1)).unwrap();

        let root = env.dir.path();
        assert_eq!(mode(&root.join("data")), 0o750);
        assert_eq!(mode(&root.join("keys")), 0o700);
        assert_eq!(mode(&root.join("secret")), 0o755);
        let key = root.join("secret/node.key");
        assert_eq!(mode(&key), 0o400);
        assert_eq!(fs::metadata(&key).unwrap().len(), 45);
        let text = fs::read_to_string(env.config()).unwrap();
        assert!(text.starts_with("# y2qd setup: written by `y2qd setup`"));
        assert!(text.contains("# y2qd setup: last updated 2027-01-15T08:00:01Z (UTC)"));
        let cfg = Config::from_toml_str(&text).unwrap();
        cfg.validate_node_key_source().unwrap();
        assert_eq!(cfg.crypto.node_key_file, key.to_string_lossy());
        assert_eq!(cfg.storage.base_path, root.join("data").to_string_lossy());
    }

    #[test]
    fn identical_second_apply_is_a_noop_without_backup() {
        let env = Env::new();
        let (a, d) = env.answers();
        run(&env.plan(&a, &d), &env.probes, at(1)).unwrap();
        let before = fs::read_to_string(env.config()).unwrap();

        // Re-run: existing config, Keep current.
        let facts = &env.facts;
        let doc: toml_edit::DocumentMut = before.parse().unwrap();
        let loaded = Answers::from_doc(&doc, d.clone(), facts, &env.probes);
        assert!(matches!(
            loaded.authority,
            Some(Authority::Keep(KeepKind::Operator))
        ));
        let plan = env.plan(&loaded, &d);
        assert!(plan.is_noop(), "{:?}", plan.changes);
        assert_eq!(fs::read_to_string(env.config()).unwrap(), before);
        let baks: Vec<_> = fs::read_dir(env.dir.path().join("etc"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".bak-"))
            .collect();
        assert!(baks.is_empty());
    }

    #[test]
    fn changed_answers_yield_one_header_and_one_backup() {
        let env = Env::new();
        let (a, d) = env.answers();
        run(&env.plan(&a, &d), &env.probes, at(1)).unwrap();
        let first = fs::read_to_string(env.config()).unwrap();

        let doc: toml_edit::DocumentMut = first.parse().unwrap();
        let mut loaded = Answers::from_doc(&doc, d.clone(), &env.facts, &env.probes);
        loaded.port = 9191;
        let plan = env.plan(&loaded, &d);
        assert_eq!(
            plan.changes
                .iter()
                .map(|c| c.path.as_str())
                .collect::<Vec<_>>(),
            ["server.port"]
        );
        run(&plan, &env.probes, at(60)).unwrap();
        let second = fs::read_to_string(env.config()).unwrap();
        assert_eq!(second.matches("# y2qd setup: written by").count(), 1);
        assert!(second.contains("port             = 9191") || second.contains("= 9191"));
        assert!(second.contains("# y2qd setup: previous version saved as"));
        let baks: Vec<_> = fs::read_dir(env.dir.path().join("etc"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".bak-"))
            .collect();
        assert_eq!(baks.len(), 1);
        assert_eq!(fs::read_to_string(baks[0].path()).unwrap(), first);
    }

    #[test]
    fn stale_staged_temp_aborts_preflight_naming_it() {
        let env = Env::new();
        let (a, d) = env.answers();
        fs::create_dir_all(env.dir.path().join("etc")).unwrap();
        let tmp = config_doc::staged_tmp_path(&env.config());
        fs::write(&tmp, "x").unwrap();
        let issues = preflight(&env.plan(&a, &d), &env.cx());
        assert!(
            issues
                .iter()
                .any(|i| i.is_error() && i.msg.contains(&tmp.to_string_lossy().into_owned()))
        );
    }

    #[test]
    fn held_temp_lock_reports_another_setup_running() {
        let env = Env::new();
        let (a, d) = env.answers();
        let plan = env.plan(&a, &d);
        fs::create_dir_all(env.dir.path().join("etc")).unwrap();
        let _held = config_doc::stage(&env.config(), b"other", 0o644).unwrap();
        let err = run(&plan, &env.probes, at(1)).unwrap_err();
        assert!(
            err.message.contains("another y2qd setup is running"),
            "{}",
            err.message
        );
    }

    #[test]
    fn linked_lock_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::write(&real, "").unwrap();
        let sym = dir.path().join("sym.lock");
        std::os::unix::fs::symlink(&real, &sym).unwrap();
        assert!(precreate_lock(&sym, 0o660, None, sys::euid()).is_err());
        let hard = dir.path().join("hard.lock");
        fs::hard_link(&real, &hard).unwrap();
        assert!(precreate_lock(&hard, 0o660, None, sys::euid()).is_err());
        let fresh = dir.path().join("fresh.lock");
        assert!(precreate_lock(&fresh, 0o660, None, sys::euid()).unwrap());
        assert_eq!(mode(&fresh), 0o660);
        assert!(!precreate_lock(&fresh, 0o660, None, sys::euid()).unwrap());
    }

    #[test]
    fn ensure_dir_sets_modes_only_on_created_components() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("keep");
        fs::create_dir(&existing).unwrap();
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o711)).unwrap();
        let leaf = existing.join("a/b");
        let w = ensure_dir(&leaf, 0o750, None, sys::euid()).unwrap();
        assert!(w.is_empty());
        assert_eq!(mode(&existing), 0o711);
        assert_eq!(mode(&existing.join("a")), 0o755);
        assert_eq!(mode(&leaf), 0o750);
        // An existing leaf is never chmod-ed; a mismatch is only a warning.
        let w = ensure_dir(&leaf, 0o700, None, sys::euid()).unwrap();
        assert_eq!(mode(&leaf), 0o750);
        assert_eq!(w.len(), 1);
        // A symlinked leaf is refused.
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&leaf, &link).unwrap();
        assert!(ensure_dir(&link, 0o750, None, sys::euid()).is_err());
    }

    #[test]
    fn config_changed_since_plan_is_refused() {
        let env = Env::new();
        let (a, d) = env.answers();
        run(&env.plan(&a, &d), &env.probes, at(1)).unwrap();
        let text = fs::read_to_string(env.config()).unwrap();
        let doc: toml_edit::DocumentMut = text.parse().unwrap();
        let mut loaded = Answers::from_doc(&doc, d.clone(), &env.facts, &env.probes);
        loaded.port = 9000;
        let plan = env.plan(&loaded, &d);
        fs::write(env.config(), format!("{text}\n# edited\n")).unwrap();
        let issues = preflight(&plan, &env.cx());
        assert!(
            issues
                .iter()
                .any(|i| i.is_error() && i.msg.contains("changed on disk"))
        );
        let err = run(&plan, &env.probes, at(5)).unwrap_err();
        assert!(err.message.contains("changed on disk"));
    }

    #[test]
    fn running_daemon_blocks_preflight() {
        let mut env = Env::new();
        let (a, d) = env.answers();
        env.probes.daemon = Tri::Yes;
        let issues = preflight(&env.plan(&a, &d), &env.cx());
        assert!(
            issues
                .iter()
                .any(|i| i.is_error() && i.msg.contains("stop y2qd"))
        );
    }

    #[test]
    fn shell_quoting_round_trips_awkward_paths() {
        assert_eq!(shq("/etc/y2q/node.key"), "/etc/y2q/node.key");
        assert_eq!(shq("/a b/c"), "'/a b/c'");
        assert_eq!(shq("/it's"), "'/it'\\''s'");
    }

    #[test]
    fn normalize_is_lexical() {
        assert_eq!(normalize(Path::new("/a/./b/../c")), PathBuf::from("/a/c"));
    }
}
