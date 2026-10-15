//! Rendering of the config file (format-preserving edits via `toml_edit`),
//! the change list shown on Review, and the staged atomic write.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, TableLike, Value};

use super::answers::{
    Answers, Authority, DEFAULT_ROUGHTIME_MIN_RESPONSES, DEFAULT_ROUGHTIME_TIMEOUT_MS,
    DEFAULT_STATE_DIR, DeviceConfig, KeepKind, KeyChange, RoughtimeServerAnswer, TlsAnswers,
};
use super::sanitize;

/// Compiled default of `crypto.devices.tpm_tcti`.
const COMPILED_TPM_TCTI: &str = "device:/dev/tpmrm0";
const HEADER_PREFIX: &str = "# y2qd setup:";
const NODE_KEY_FILE: &str = "crypto.node_key_file";

/// Keys written even when they equal the compiled default and are absent.
const ALWAYS_WRITTEN: [&str; 4] = [
    "server.host",
    "server.port",
    "storage.base_path",
    "crypto.keystore_dir",
];

/// Fresh-install base: `config.default.toml` without its leading reference
/// block (lines 1-9: the title, usage notes and the blank line after them).
pub fn fresh_base_text() -> String {
    include_str!("../../../../config.default.toml")
        .split_inclusive('\n')
        .skip(9)
        .collect()
}

fn resolve_target(path: &Path) -> io::Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => fs::canonicalize(path),
        _ => Ok(path.to_path_buf()),
    }
}

fn dir_of(p: &Path) -> &Path {
    match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    }
}

/// Next free backup path for `config`: `<name>.bak-<now>`, then `-1`, `-2`...
pub fn backup_path(config: &Path, now: DateTime<Utc>) -> PathBuf {
    let target = resolve_target(config).unwrap_or_else(|_| config.to_path_buf());
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.toml".into());
    let stamp = now.format("%Y%m%dT%H%M%SZ");
    let dir = dir_of(&target);
    let first = dir.join(format!("{name}.bak-{stamp}"));
    if fs::symlink_metadata(&first).is_err() {
        return first;
    }
    (1u32..)
        .map(|n| dir.join(format!("{name}.bak-{stamp}-{n}")))
        .find(|p| fs::symlink_metadata(p).is_err())
        .unwrap_or(first)
}

// --- document editing -------------------------------------------------------

fn lookup<'a>(root: &'a dyn TableLike, path: &str) -> Option<&'a Item> {
    let mut segs: Vec<&str> = path.split('.').collect();
    let key = segs.pop()?;
    let mut cur = root;
    for seg in segs {
        cur = cur.get(seg)?.as_table_like()?;
    }
    cur.get(key)
}

fn walk<'a>(
    t: &'a mut dyn TableLike,
    segs: &[&str],
    create: bool,
) -> Option<&'a mut dyn TableLike> {
    let Some((first, rest)) = segs.split_first() else {
        return Some(t);
    };
    if !t.contains_key(first) {
        if !create {
            return None;
        }
        let mut nt = Table::new();
        nt.set_implicit(true);
        t.insert(first, Item::Table(nt));
    }
    let child = t.get_mut(first)?.as_table_like_mut()?;
    walk(child, rest, create)
}

fn same(old: &Item, new: &Value) -> bool {
    old.as_str() == new.as_str()
        && old.as_integer() == new.as_integer()
        && old.as_bool() == new.as_bool()
}

fn sv(s: &str) -> Value {
    Value::from(s)
}

fn iv(i: impl Into<i64>) -> Value {
    Value::from(i.into())
}

fn bv(b: bool) -> Value {
    Value::from(b)
}

struct Writer<'a> {
    root: &'a mut Table,
}

impl Writer<'_> {
    fn exists(&self, path: &str) -> bool {
        lookup(&*self.root, path).is_some()
    }

    /// Write `new` at `path` when the key exists, `differs` from the compiled
    /// default, or the key is always written. An existing equal value is left
    /// alone (keeps literals and formatting); a different one is replaced with
    /// the old value's decor so trailing comments survive.
    fn put(&mut self, path: &str, new: Value, differs: bool) -> Result<(), String> {
        let existing = lookup(&*self.root, path);
        if let Some(old) = existing {
            if same(old, &new) {
                return Ok(());
            }
        } else if !(differs || ALWAYS_WRITTEN.contains(&path)) {
            return Ok(());
        }
        let mut segs: Vec<&str> = path.split('.').collect();
        let key = segs.pop().unwrap_or_default();
        let blocked = || format!("cannot set {path}: a non-table value is in the way");
        let t = walk(&mut *self.root, &segs, true).ok_or_else(blocked)?;
        match t.get_mut(key) {
            Some(item) => {
                let mut nv = new;
                if let Some(ov) = item.as_value() {
                    *nv.decor_mut() = ov.decor().clone();
                }
                *item = Item::Value(nv);
            }
            None => {
                t.insert(key, Item::Value(new));
            }
        }
        Ok(())
    }

    /// Remove `path` if present. Comments directly above the key are part of
    /// the key's decor and go with it.
    fn unset(&mut self, path: &str) {
        let mut segs: Vec<&str> = path.split('.').collect();
        let Some(key) = segs.pop() else { return };
        if let Some(t) = walk(&mut *self.root, &segs, false) {
            t.remove(key);
        }
    }

    fn put_opt(&mut self, path: &str, v: &str, default: &str) -> Result<(), String> {
        if v.is_empty() {
            self.unset(path);
            Ok(())
        } else {
            self.put(path, sv(v), v != default)
        }
    }

    fn tls(&mut self, prefix: &str, a: &TlsAnswers, d: &TlsAnswers) -> Result<(), String> {
        self.put(
            &format!("{prefix}.enabled"),
            bv(a.enabled),
            a.enabled != d.enabled,
        )?;
        self.put_opt(&format!("{prefix}.cert_path"), &a.cert_path, &d.cert_path)?;
        self.put_opt(&format!("{prefix}.key_path"), &a.key_path, &d.key_path)?;
        self.put_opt(
            &format!("{prefix}.client_ca_path"),
            &a.client_ca_path,
            &d.client_ca_path,
        )?;
        self.put(
            &format!("{prefix}.require_pq_kex"),
            bv(a.require_pq_kex),
            a.require_pq_kex != d.require_pq_kex,
        )
    }

    fn servers(&mut self, new: &[RoughtimeServerAnswer]) -> Result<(), String> {
        const PATH: &str = "crypto.devices.roughtime.servers";
        let cur = current_servers(&*self.root);
        if cur.as_deref() == Some(new) {
            return Ok(());
        }
        let segs = ["crypto", "devices", "roughtime"];
        if new.is_empty() {
            if let Some(t) = walk(&mut *self.root, &segs, false) {
                t.remove("servers");
            }
            return Ok(());
        }
        let mut aot = ArrayOfTables::new();
        for s in new {
            let mut t = Table::new();
            t.insert("name", Item::Value(sv(&s.name)));
            t.insert("addr", Item::Value(sv(&s.addr)));
            t.insert("public_key_b64", Item::Value(sv(&s.public_key_b64)));
            aot.push(t);
        }
        let t = walk(&mut *self.root, &segs, true)
            .ok_or_else(|| format!("cannot set {PATH}: a non-table value is in the way"))?;
        t.insert("servers", Item::ArrayOfTables(aot));
        Ok(())
    }

    fn devices(&mut self, d: &DeviceConfig) -> Result<(), String> {
        self.put(
            "crypto.devices.tpm_tcti",
            sv(&d.tcti),
            d.tcti != COMPILED_TPM_TCTI,
        )?;
        let sock = if d.use_helper {
            d.socket_path.as_str()
        } else {
            ""
        };
        self.put(
            "crypto.devices.key_agent_socket",
            sv(sock),
            !sock.is_empty(),
        )?;
        self.put(
            "crypto.devices.key_agent_state_dir",
            sv(&d.state_dir),
            d.state_dir != DEFAULT_STATE_DIR,
        )?;
        if d.use_helper {
            if let Some(uid) = d.peer_uid {
                self.put("crypto.devices.key_agent_peer_uid", iv(uid), true)?;
            }
            self.put("crypto.devices.key_agent_arm_uid", iv(d.arm_uid), true)?;
        }
        self.put(
            "crypto.devices.roughtime.timeout_ms",
            iv(i64::try_from(d.roughtime_timeout_ms).unwrap_or(i64::MAX)),
            d.roughtime_timeout_ms != DEFAULT_ROUGHTIME_TIMEOUT_MS,
        )?;
        self.put(
            "crypto.devices.roughtime.min_responses",
            iv(d.roughtime_min_responses),
            d.roughtime_min_responses != DEFAULT_ROUGHTIME_MIN_RESPONSES,
        )?;
        self.servers(&d.roughtime_servers)
    }
}

/// The server list the document currently holds: absent = empty; `None` when
/// the key holds something that is not a list of tables.
fn current_servers(root: &dyn TableLike) -> Option<Vec<RoughtimeServerAnswer>> {
    let Some(item) = lookup(root, "crypto.devices.roughtime.servers") else {
        return Some(Vec::new());
    };
    let read = |t: &dyn TableLike| {
        let get = |k: &str| {
            t.get(k)
                .and_then(Item::as_str)
                .unwrap_or_default()
                .to_string()
        };
        RoughtimeServerAnswer {
            name: get("name"),
            addr: get("addr"),
            public_key_b64: get("public_key_b64"),
        }
    };
    if let Some(aot) = item.as_array_of_tables() {
        Some(aot.iter().map(|t| read(t)).collect())
    } else if let Some(arr) = item.as_array() {
        arr.iter()
            .map(|v| v.as_inline_table().map(|t| read(t)))
            .collect()
    } else {
        None
    }
}

/// Strip the leading `# y2qd setup:` lines plus one following blank line.
fn strip_header(text: &str) -> &str {
    let mut rest = text;
    let mut stripped = false;
    while rest.starts_with(HEADER_PREFIX) {
        rest = rest.split_once('\n').map_or("", |(_, r)| r);
        stripped = true;
    }
    if stripped && let Some(r) = rest.strip_prefix('\n') {
        rest = r;
    }
    rest
}

/// Render the new config text.
///
/// `base_text` is the existing file text, or [`fresh_base_text`]. `defaults`
/// supplies the compiled defaults for the write rule: a key absent from the
/// document is written only when its value differs from the default (or it is
/// one of the always-written keys).
pub fn render(
    base_text: &str,
    a: &Answers,
    defaults: &Answers,
    now: DateTime<Utc>,
    backup: Option<&Path>,
) -> Result<String, String> {
    let d = defaults;
    let crlf = base_text.contains("\r\n");
    let lf = base_text.replace("\r\n", "\n");
    let mut doc: DocumentMut = strip_header(&lf)
        .parse()
        .map_err(|e| format!("config does not parse: {e}"))?;
    let mut w = Writer {
        root: doc.as_table_mut(),
    };

    w.put("server.host", sv(&a.host), a.host != d.host)?;
    w.put("server.port", iv(a.port), a.port != d.port)?;
    w.tls("server.tls", &a.tls, &d.tls)?;
    w.put(
        "server.allow_insecure_bind",
        bv(a.allow_insecure_bind),
        a.allow_insecure_bind != d.allow_insecure_bind,
    )?;
    w.put(
        "server.allow_unprotected_memory",
        bv(a.allow_unprotected_memory),
        a.allow_unprotected_memory != d.allow_unprotected_memory,
    )?;

    w.put(
        "storage.base_path",
        sv(&a.base_path),
        a.base_path != d.base_path,
    )?;
    w.put("storage.backend", sv(&a.backend), a.backend != d.backend)?;
    w.put(
        "storage.default_sync",
        sv(&a.default_sync),
        a.default_sync != d.default_sync,
    )?;

    w.put(
        "crypto.keystore_dir",
        sv(&a.keystore_dir),
        a.keystore_dir != d.keystore_dir,
    )?;
    w.put(
        "crypto.argon2.m_cost_kib",
        iv(a.argon_m_cost_kib),
        a.argon_m_cost_kib != d.argon_m_cost_kib,
    )?;
    w.put(
        "crypto.argon2.t_cost",
        iv(a.argon_t_cost),
        a.argon_t_cost != d.argon_t_cost,
    )?;
    w.put(
        "crypto.argon2.p_cost",
        iv(a.argon_p_cost),
        a.argon_p_cost != d.argon_p_cost,
    )?;

    w.put(
        "auth.default_ttl_seconds",
        iv(i64::try_from(a.default_ttl_seconds).unwrap_or(i64::MAX)),
        a.default_ttl_seconds != d.default_ttl_seconds,
    )?;
    w.put(
        "auth.max_ttl_seconds",
        iv(i64::try_from(a.max_ttl_seconds).unwrap_or(i64::MAX)),
        a.max_ttl_seconds != d.max_ttl_seconds,
    )?;
    w.put(
        "auth.max_failed_logins",
        iv(a.max_failed_logins),
        a.max_failed_logins != d.max_failed_logins,
    )?;
    w.put(
        "auth.lockout_seconds",
        iv(i64::try_from(a.lockout_seconds).unwrap_or(i64::MAX)),
        a.lockout_seconds != d.lockout_seconds,
    )?;
    w.put(
        "auth.enforce_authorization",
        bv(a.enforce_authorization),
        a.enforce_authorization != d.enforce_authorization,
    )?;
    w.put(
        "auth.max_refreshes",
        iv(a.max_refreshes),
        a.max_refreshes != d.max_refreshes,
    )?;

    w.put("s3.enabled", bv(a.s3_enabled), a.s3_enabled != d.s3_enabled)?;
    if a.s3_enabled {
        w.put("s3.host", sv(&a.s3_host), a.s3_host != d.s3_host)?;
        w.put("s3.port", iv(a.s3_port), a.s3_port != d.s3_port)?;
        w.put("s3.region", sv(&a.s3_region), a.s3_region != d.s3_region)?;
        w.put(
            "s3.virtual_host_domain",
            sv(&a.s3_virtual_host_domain),
            a.s3_virtual_host_domain != d.s3_virtual_host_domain,
        )?;
        w.tls("s3.tls", &a.s3_tls, &d.s3_tls)?;
        w.put(
            "s3.allow_insecure_bind",
            bv(a.s3_allow_insecure_bind),
            a.s3_allow_insecure_bind != d.s3_allow_insecure_bind,
        )?;
    }

    w.put(
        "observability.log_filter",
        sv(&a.log_filter),
        a.log_filter != d.log_filter,
    )?;
    w.put(
        "observability.log_format",
        sv(&a.log_format),
        a.log_format != d.log_format,
    )?;

    match a.authority.as_ref().ok_or("no authority chosen")? {
        Authority::Keep(KeepKind::Operator) => {}
        Authority::OperatorKey { file, .. } => {
            w.put(NODE_KEY_FILE, sv(file), true)?;
            if !a.loaded.key_agent_socket.is_empty() {
                w.put("crypto.devices.key_agent_socket", sv(""), true)?;
            }
        }
        Authority::Keep(KeepKind::Registry)
        | Authority::FinishMigration { .. }
        | Authority::NewRegistry(_) => {
            if w.exists(NODE_KEY_FILE) {
                w.put(NODE_KEY_FILE, sv(""), true)?;
            }
            w.devices(&a.device)?;
        }
    }

    let mut body = doc.to_string();
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }
    let mut out = format!(
        "{HEADER_PREFIX} written by `y2qd setup` (y2qd {}); hand edits are kept on the next run.\n\
         {HEADER_PREFIX} last updated {} (UTC)\n",
        env!("CARGO_PKG_VERSION"),
        now.format("%Y-%m-%dT%H:%M:%SZ"),
    );
    if let Some(b) = backup {
        out.push_str(&format!(
            "{HEADER_PREFIX} previous version saved as {}\n",
            sanitize(&b.display().to_string())
        ));
    }
    out.push('\n');
    out.push_str(&body);
    if crlf {
        out = out.replace('\n', "\r\n");
    }
    Ok(out)
}

// --- change list ------------------------------------------------------------

fn display_value(v: &Value) -> String {
    if let Some(s) = v.as_str() {
        return format!("{s:?}");
    }
    if let Some(i) = v.as_integer() {
        return i.to_string();
    }
    if let Some(b) = v.as_bool() {
        return b.to_string();
    }
    let mut c = v.clone();
    c.decor_mut().clear();
    c.to_string().trim().to_string()
}

fn flatten_table(t: &dyn TableLike, prefix: &str, out: &mut Vec<(String, String)>) {
    for (k, item) in t.iter() {
        let p = if prefix.is_empty() {
            k.to_string()
        } else {
            format!("{prefix}.{k}")
        };
        match item {
            Item::Value(v) => out.push((p, display_value(v))),
            Item::Table(t) => flatten_table(t, &p, out),
            Item::ArrayOfTables(a) => {
                for (i, t) in a.iter().enumerate() {
                    flatten_table(t, &format!("{p}[{i}]"), out);
                }
            }
            Item::None => {}
        }
    }
}

fn flatten(text: &str) -> Result<Vec<(String, String)>, String> {
    let doc: DocumentMut = text
        .parse()
        .map_err(|e| format!("config does not parse: {e}"))?;
    let mut out = Vec::new();
    flatten_table(doc.as_table(), "", &mut out);
    Ok(out)
}

/// Flatten both documents to `(dotted.path, display value)` and diff them.
/// New-document order first, then keys that were removed.
pub fn changes(old_text: &str, new_text: &str) -> Result<Vec<KeyChange>, String> {
    let old = flatten(old_text)?;
    let new = flatten(new_text)?;
    let old_map: HashMap<&str, &str> = old.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let new_map: HashMap<&str, &str> = new.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut out = Vec::new();
    for (p, nv) in &new {
        let ov = old_map.get(p.as_str());
        if ov != Some(&nv.as_str()) {
            out.push(KeyChange {
                path: p.clone(),
                old: ov.map(|s| (*s).to_string()),
                new: Some(nv.clone()),
            });
        }
    }
    for (p, ov) in &old {
        if !new_map.contains_key(p.as_str()) {
            out.push(KeyChange {
                path: p.clone(),
                old: Some(ov.clone()),
                new: None,
            });
        }
    }
    Ok(out)
}

// --- staged write -------------------------------------------------------------

/// A staged (not yet visible) file. Holds an exclusive lock on its temp file;
/// dropping it without [`commit`] removes the temp.
pub struct Staged {
    tmp: PathBuf,
    fin: PathBuf,
    file: File,
    done: bool,
}

#[cfg(test)]
impl Staged {
    pub fn final_path(&self) -> &Path {
        &self.fin
    }

    pub fn tmp_path(&self) -> &Path {
        &self.tmp
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.done {
            // We created it and hold its lock, so it is ours to remove.
            let _ = fs::remove_file(&self.tmp);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StageError {
    #[error("another y2qd setup is running (it holds {0})")]
    Busy(String),
    #[error("stale file {0} from an interrupted run; delete it")]
    Stale(String),
    #[error("{0}")]
    Io(String),
}

fn io_err(path: &Path, what: &str, e: io::Error) -> StageError {
    StageError::Io(format!("{what} {}: {e}", path.display()))
}

/// `<dir>/.<name>.y2qd-setup.tmp` for `path` (beside the target of a symlink).
pub fn staged_tmp_path(path: &Path) -> PathBuf {
    let target = resolve_target(path).unwrap_or_else(|_| path.to_path_buf());
    let mut name = OsString::from(".");
    name.push(target.file_name().unwrap_or_else(|| "config".as_ref()));
    name.push(".y2qd-setup.tmp");
    dir_of(&target).join(name)
}

/// Decide whether a pre-existing temp is live (locked) or stale.
fn classify_existing(tmp: &Path) -> StageError {
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_NOCTTY)
        .open(tmp);
    match opened {
        Ok(f) => match f.try_lock() {
            Ok(()) => StageError::Stale(tmp.display().to_string()),
            Err(fs::TryLockError::WouldBlock) => StageError::Busy(tmp.display().to_string()),
            Err(fs::TryLockError::Error(e)) => io_err(tmp, "lock", e),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => io_err(tmp, "open", e),
        Err(_) => StageError::Stale(tmp.display().to_string()),
    }
}

/// Write `bytes` to a locked temp beside `path`. The final mode is the
/// existing file's permission bits, else `mode_if_new`.
pub fn stage(path: &Path, bytes: &[u8], mode_if_new: u32) -> Result<Staged, StageError> {
    let fin = resolve_target(path).map_err(|e| io_err(path, "resolve", e))?;
    let existing = match fs::metadata(&fin) {
        Ok(m) => Some(m),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(io_err(&fin, "stat", e)),
    };
    let mode = existing
        .as_ref()
        .map_or(mode_if_new, |m| m.permissions().mode() & 0o7777);
    let tmp = staged_tmp_path(&fin);
    let file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(classify_existing(&tmp));
        }
        Err(e) => return Err(io_err(&tmp, "create", e)),
    };
    let staged = Staged {
        tmp,
        fin,
        file,
        done: false,
    };
    match staged.file.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => {
            return Err(StageError::Busy(staged.tmp.display().to_string()));
        }
        Err(fs::TryLockError::Error(e)) => return Err(io_err(&staged.tmp, "lock", e)),
    }
    (&staged.file)
        .write_all(bytes)
        .map_err(|e| io_err(&staged.tmp, "write", e))?;
    staged
        .file
        .sync_all()
        .map_err(|e| io_err(&staged.tmp, "sync", e))?;
    // Undo the umask: the file must end up with exactly `mode`.
    staged
        .file
        .set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|e| io_err(&staged.tmp, "chmod", e))?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let is_root = unsafe { libc::geteuid() } == 0;
    if let (true, Some(m)) = (is_root, existing.as_ref()) {
        // SAFETY: the fd is owned by `staged.file`, which outlives the call.
        let rc = unsafe { libc::fchown(staged.file.as_raw_fd(), m.uid(), m.gid()) };
        if rc != 0 {
            return Err(io_err(&staged.tmp, "chown", io::Error::last_os_error()));
        }
    }
    Ok(staged)
}

/// Copy an existing final file to `backup` (create_new, never deleted), then
/// rename the temp over it and fsync the directory. `Ok(true)` when a backup
/// was written.
pub fn commit(mut staged: Staged, backup: Option<&Path>) -> Result<bool, StageError> {
    let mut backed_up = false;
    if let Some(b) = backup {
        match fs::metadata(&staged.fin) {
            Ok(m) => {
                let mode = m.permissions().mode() & 0o7777;
                let mut src =
                    File::open(&staged.fin).map_err(|e| io_err(&staged.fin, "open", e))?;
                let mut dst = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(mode)
                    .open(b)
                    .map_err(|e| io_err(b, "create backup", e))?;
                io::copy(&mut src, &mut dst).map_err(|e| io_err(b, "write backup", e))?;
                dst.sync_all().map_err(|e| io_err(b, "sync backup", e))?;
                dst.set_permissions(fs::Permissions::from_mode(mode))
                    .map_err(|e| io_err(b, "chmod backup", e))?;
                backed_up = true;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_err(&staged.fin, "stat", e)),
        }
    }
    fs::rename(&staged.tmp, &staged.fin).map_err(|e| io_err(&staged.fin, "rename to", e))?;
    staged.done = true;
    let dir = dir_of(&staged.fin);
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| io_err(dir, "sync directory", e))?;
    Ok(backed_up)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::super::answers::{DeviceConfig, KeySource, Loaded};
    use super::*;

    const MIN: &str = "[server]\nhost = \"127.0.0.1\"\nport = 8080\n\n[storage]\nbase_path = \"/d\"\n\n[crypto]\nkeystore_dir = \"/k\"\n";

    fn at(h: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 14, h, 0, 0).unwrap()
    }

    fn base_answers() -> Answers {
        Answers {
            config_path: PathBuf::from("/etc/y2q/config.toml"),
            base_path: "/d".into(),
            keystore_dir: "/k".into(),
            ack_data_risk: false,
            index_path: None,
            host: "127.0.0.1".into(),
            port: 8080,
            tls: TlsAnswers::default(),
            allow_insecure_bind: false,
            s3_enabled: false,
            s3_host: "127.0.0.1".into(),
            s3_port: 9000,
            s3_region: "y2q".into(),
            s3_virtual_host_domain: String::new(),
            s3_tls: TlsAnswers::default(),
            s3_allow_insecure_bind: false,
            backend: "filesystem".into(),
            default_sync: "durable".into(),
            log_filter: "info".into(),
            log_format: "text".into(),
            default_ttl_seconds: 3600,
            max_ttl_seconds: 86400,
            max_failed_logins: 10,
            lockout_seconds: 900,
            enforce_authorization: true,
            max_refreshes: 0,
            argon_m_cost_kib: 65536,
            argon_t_cost: 3,
            argon_p_cost: 4,
            allow_unprotected_memory: false,
            authority: Some(Authority::Keep(KeepKind::Operator)),
            device: DeviceConfig {
                use_helper: false,
                key_user: "y2q-keyd".into(),
                socket_path: "/run/y2q-keyd.sock".into(),
                state_dir: "/run/y2q-keyd".into(),
                tcti: COMPILED_TPM_TCTI.into(),
                roughtime_servers: Vec::new(),
                roughtime_timeout_ms: 3000,
                roughtime_min_responses: 2,
                arm_on_start: false,
                peer_uid: None,
                arm_uid: 0,
            },
            daemon_user: "y2qd".into(),
            group: "y2q".into(),
            install_units: false,
            unit_root: "/etc".into(),
            binary_path: "/usr/local/bin/y2qd".into(),
            socket_group: "y2qd".into(),
            key_user_group: "y2q-keyd".into(),
            install_udev_rule: false,
            udev_vendor_id: "1050".into(),
            loaded: Loaded::default(),
            unreadable: Vec::new(),
        }
    }

    fn rd(base: &str, a: &Answers, now: DateTime<Utc>) -> String {
        render(base, a, &base_answers(), now, None).unwrap()
    }

    fn body(out: &str) -> &str {
        strip_header(out)
    }

    #[test]
    fn header_written_once_and_refreshed() {
        let a = base_answers();
        let out1 = rd(MIN, &a, at(10));
        let want = format!(
            "# y2qd setup: written by `y2qd setup` (y2qd {}); hand edits are kept on the next run.\n\
             # y2qd setup: last updated 2026-10-14T10:00:00Z (UTC)\n\n",
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(out1, format!("{want}{MIN}"));
        let out2 = rd(&out1, &a, at(11));
        assert_eq!(out2, out1.replace("T10:00:00Z", "T11:00:00Z"));
        assert_eq!(out2.matches(HEADER_PREFIX).count(), 2);
    }

    #[test]
    fn backup_line_added_then_replaced() {
        let a = base_answers();
        let b = Path::new("/etc/y2q/config.toml.bak-1");
        let out1 = render(MIN, &a, &a, at(10), Some(b)).unwrap();
        assert!(
            out1.contains("# y2qd setup: previous version saved as /etc/y2q/config.toml.bak-1\n\n")
        );
        let out2 = rd(&out1, &a, at(11));
        assert_eq!(out2.matches(HEADER_PREFIX).count(), 2);
        assert_eq!(body(&out2), MIN);
    }

    #[test]
    fn suffix_comments_and_unknown_keys_survive() {
        let base = "# top note\n[server]\nhost = \"127.0.0.1\"  # required — IP\nport = 8080  # required — TCP port\nweird_key = 7\n\n[storage]\nbase_path = \"/d\"\n\n[crypto]\nkeystore_dir = \"/k\"\n";
        let mut a = base_answers();
        a.port = 9090;
        let out = rd(base, &a, at(10));
        assert_eq!(body(&out), base.replace("port = 8080  #", "port = 9090  #"));
    }

    #[test]
    fn equal_values_are_untouched() {
        let base =
            format!("{MIN}\n[auth]\nmax_ttl_seconds = 86_400\ndefault_ttl_seconds = 0xE10\n");
        let out = rd(&base, &base_answers(), at(10));
        assert_eq!(body(&out), base);
    }

    #[test]
    fn absent_default_keys_not_written_but_exceptions_are() {
        let out = rd("", &base_answers(), at(10));
        assert_eq!(
            body(&out),
            "[server]\nhost = \"127.0.0.1\"\nport = 8080\n\n[storage]\nbase_path = \"/d\"\n\n[crypto]\nkeystore_dir = \"/k\"\n"
        );
        let mut a = base_answers();
        a.max_refreshes = 3;
        let out = rd(MIN, &a, at(10));
        assert_eq!(body(&out), format!("{MIN}\n[auth]\nmax_refreshes = 3\n"));
    }

    #[test]
    fn client_ca_path_is_removed() {
        let base = "[server]\nhost = \"127.0.0.1\"\nport = 8080\n\n[server.tls]\nenabled = false\nclient_ca_path = \"/ca.pem\"\n\n[storage]\nbase_path = \"/d\"\n\n[crypto]\nkeystore_dir = \"/k\"\n";
        let out = rd(base, &base_answers(), at(10));
        assert!(!out.contains("client_ca_path"));
        assert!(out.contains("[server.tls]\nenabled = false\n"));
    }

    #[test]
    fn missing_table_is_created_after_last_position() {
        let mut a = base_answers();
        a.argon_m_cost_kib = 1;
        let out = rd(MIN, &a, at(10));
        assert_eq!(
            body(&out),
            format!("{MIN}\n[crypto.argon2]\nm_cost_kib = 1\n")
        );
    }

    #[test]
    fn new_key_lands_after_last_key_before_trailing_comments() {
        let base = "[server]\nhost = \"127.0.0.1\"\nport = 8080\n\n# storage notes\n[storage]\nbase_path = \"/d\"\n\n[crypto]\nkeystore_dir = \"/k\"\n";
        let mut a = base_answers();
        a.allow_unprotected_memory = true;
        let out = rd(base, &a, at(10));
        assert_eq!(
            body(&out),
            "[server]\nhost = \"127.0.0.1\"\nport = 8080\nallow_unprotected_memory = true\n\n# storage notes\n[storage]\nbase_path = \"/d\"\n\n[crypto]\nkeystore_dir = \"/k\"\n"
        );
    }

    fn server(name: &str) -> RoughtimeServerAnswer {
        RoughtimeServerAnswer {
            name: name.into(),
            addr: "h:1".into(),
            public_key_b64: "AAAA".into(),
        }
    }

    #[test]
    fn roughtime_array_rewritten_only_when_changed() {
        let base = format!(
            "{MIN}\n[[crypto.devices.roughtime.servers]]\n# my server\nname = \"x\"\naddr = \"h:1\"\npublic_key_b64 = \"AAAA\"\n"
        );
        let mut a = base_answers();
        a.authority = Some(Authority::Keep(KeepKind::Registry));
        a.device.roughtime_servers = vec![server("x")];
        let out = rd(&base, &a, at(10));
        assert_eq!(body(&out), base);

        a.device.roughtime_servers = vec![server("y")];
        let out = rd(&base, &a, at(10));
        assert!(out.contains("name = \"y\""));
        assert!(!out.contains("# my server"));
        assert_eq!(
            out.matches("[[crypto.devices.roughtime.servers]]").count(),
            1
        );

        a.device.roughtime_servers.clear();
        let out = rd(&base, &a, at(10));
        assert!(!out.contains("roughtime"));
    }

    #[test]
    fn inline_server_array_is_compared_by_value() {
        let base = format!(
            "{MIN}\n[crypto.devices.roughtime]\nservers = [{{ name = \"x\", addr = \"h:1\", public_key_b64 = \"AAAA\" }}]\n"
        );
        let mut a = base_answers();
        a.authority = Some(Authority::Keep(KeepKind::Registry));
        a.device.roughtime_servers = vec![server("x")];
        assert_eq!(body(&rd(&base, &a, at(10))), base);
    }

    #[test]
    fn registry_authority_blanks_node_key_file_only_if_present() {
        let mut a = base_answers();
        a.authority = Some(Authority::FinishMigration { ack_adopted: true });
        let out = rd(MIN, &a, at(10));
        assert!(!out.contains("node_key_file"));
        let base = format!("{MIN}node_key_file = \"/etc/y2q/node.key\"  # old\n");
        let out = rd(&base, &a, at(10));
        assert!(out.contains("node_key_file = \"\"  # old\n"));
    }

    #[test]
    fn operator_key_sets_file_and_clears_helper_socket() {
        let mut a = base_answers();
        a.authority = Some(Authority::OperatorKey {
            mode: KeySource::Generate,
            file: "/etc/y2q/node.key".into(),
        });
        a.loaded.key_agent_socket = "/run/y2q-keyd.sock".into();
        let base = format!("{MIN}\n[crypto.devices]\nkey_agent_socket = \"/run/y2q-keyd.sock\"\n");
        let out = rd(&base, &a, at(10));
        assert!(out.contains("node_key_file = \"/etc/y2q/node.key\"\n"));
        assert!(out.contains("key_agent_socket = \"\"\n"));
    }

    #[test]
    fn no_authority_is_an_error() {
        let mut a = base_answers();
        a.authority = None;
        assert!(render(MIN, &a, &a, at(10), None).is_err());
    }

    #[test]
    fn crlf_base_stays_crlf() {
        let base = MIN.replace('\n', "\r\n");
        let a = base_answers();
        let out1 = rd(&base, &a, at(10));
        assert!(!out1.replace("\r\n", "").contains('\n'));
        assert!(out1.starts_with("# y2qd setup:"));
        let out2 = rd(&out1, &a, at(11));
        assert_eq!(out2, out1.replace("T10:", "T11:"));
    }

    #[test]
    fn fresh_render_parses_and_loads() {
        let fresh = fresh_base_text();
        assert!(fresh.starts_with("# ------"));
        assert!(!fresh.contains("Copy this file"));
        let mut a = base_answers();
        a.base_path = "/srv/y2q/data".into();
        a.keystore_dir = "/srv/y2q/keys".into();
        a.authority = Some(Authority::OperatorKey {
            mode: KeySource::Generate,
            file: "/etc/y2q/node.key".into(),
        });
        let out = render(&fresh, &a, &a, at(10), None).unwrap();
        assert!(out.starts_with("# y2qd setup: written by"));
        assert!(out.contains("base_path = \"/srv/y2q/data\""));
        assert!(out.contains("node_key_file = \"/etc/y2q/node.key\""));
        crate::config::Config::from_toml_str(&out).expect("rendered fresh config must load");
        // Idempotent on its own output.
        let again = render(&out, &a, &a, at(11), None).unwrap();
        assert_eq!(again, out.replace("T10:", "T11:"));
    }

    #[test]
    fn changes_empty_for_identical_and_lists_only_port() {
        assert!(changes(MIN, MIN).unwrap().is_empty());
        let new = MIN.replace("8080", "9090");
        let c = changes(MIN, &new).unwrap();
        assert_eq!(
            c,
            vec![KeyChange {
                path: "server.port".into(),
                old: Some("8080".into()),
                new: Some("9090".into()),
            }]
        );
        // Literal spelling is not a change.
        let lit = MIN.replace("8080", "8_080");
        assert!(changes(MIN, &lit).unwrap().is_empty());
    }

    #[test]
    fn changes_reports_added_removed_and_array_rows() {
        let old = "[a]\nx = 1\ny = \"s\"\n[[a.rows]]\nn = 1\n";
        let new = "[a]\nx = 1\nz = true\n[[a.rows]]\nn = 1\n[[a.rows]]\nn = 2\n";
        let c = changes(old, new).unwrap();
        let paths: Vec<_> = c.iter().map(|k| k.path.as_str()).collect();
        assert_eq!(paths, ["a.z", "a.rows[1].n", "a.y"]);
        assert_eq!(c[0].old, None);
        assert_eq!(c[2].new, None);
        assert!(changes("[a", new).is_err());
    }

    #[test]
    fn backup_path_avoids_collisions() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        fs::write(&cfg, "x").unwrap();
        let p1 = backup_path(&cfg, at(10));
        assert!(p1.ends_with("config.toml.bak-20261014T100000Z"));
        fs::write(&p1, "x").unwrap();
        let p2 = backup_path(&cfg, at(10));
        assert!(p2.ends_with("config.toml.bak-20261014T100000Z-1"));
    }

    #[test]
    fn stage_busy_stale_drop_and_commit() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        let tmp = staged_tmp_path(&cfg);
        assert_eq!(tmp, dir.path().join(".config.toml.y2qd-setup.tmp"));

        let s1 = stage(&cfg, b"one", 0o640).unwrap();
        assert_eq!(s1.tmp_path(), tmp);
        assert_eq!(s1.final_path(), cfg);
        assert_eq!(
            fs::metadata(&tmp).unwrap().permissions().mode() & 0o7777,
            0o640
        );
        assert!(matches!(
            stage(&cfg, b"two", 0o640),
            Err(StageError::Busy(_))
        ));
        drop(s1);
        assert!(!tmp.exists());

        fs::write(&tmp, "leftover").unwrap();
        match stage(&cfg, b"x", 0o640) {
            Err(StageError::Stale(p)) => assert!(p.contains(".config.toml.y2qd-setup.tmp")),
            Err(e) => panic!("expected Stale, got {e:?}"),
            Ok(_) => panic!("expected Stale, got Ok"),
        }
        assert_eq!(fs::read_to_string(&tmp).unwrap(), "leftover");
        fs::remove_file(&tmp).unwrap();

        // First write: no backup possible, mode from `mode_if_new`.
        let s = stage(&cfg, b"v1", 0o640).unwrap();
        let bak = dir.path().join("config.toml.bak-1");
        assert!(!commit(s, Some(&bak)).unwrap());
        assert_eq!(fs::read_to_string(&cfg).unwrap(), "v1");
        assert!(!tmp.exists());
        assert!(!bak.exists());

        // Replacement keeps the existing mode and backs the old content up.
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o600)).unwrap();
        let s = stage(&cfg, b"v2", 0o644).unwrap();
        assert!(commit(s, Some(&bak)).unwrap());
        assert_eq!(fs::read_to_string(&cfg).unwrap(), "v2");
        assert_eq!(fs::read_to_string(&bak).unwrap(), "v1");
        assert_eq!(
            fs::metadata(&cfg).unwrap().permissions().mode() & 0o7777,
            0o600
        );

        // An existing backup path is never overwritten.
        let s = stage(&cfg, b"v3", 0o644).unwrap();
        assert!(matches!(commit(s, Some(&bak)), Err(StageError::Io(_))));
        assert_eq!(fs::read_to_string(&cfg).unwrap(), "v2");
        assert!(!tmp.exists());
    }

    #[test]
    fn symlinked_config_is_written_beside_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        let target = real.join("config.toml");
        fs::write(&target, "old").unwrap();
        let link = dir.path().join("link.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let s = stage(&link, b"new", 0o644).unwrap();
        assert_eq!(s.tmp_path(), real.join(".config.toml.y2qd-setup.tmp"));
        commit(s, None).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), "new");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
