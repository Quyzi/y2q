//! The wizard state machine: steps, forms, key handling.
//!
//! Pure with respect to the terminal: `on_key` mutates state and returns what
//! the run loop should do next. Slow device probes are deferred so the loop
//! can draw a "probing..." frame first.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::answers::{
    Answers, Authority, AuthorityContext, AuthorityKind, FirstKind, KeySource, NewRegistryAnswers,
    RoughtimeServerAnswer, normalize,
};
use super::apply::{self, Plan};
use super::config_doc;
use super::existing::{ExistingInstall, PathPair};
use super::scan::{self, Facts, Finding, SecureBoot};
use super::validate::{self, Ctx, Issue, ProbeCache, Probes, Step};

#[derive(Debug, Clone, PartialEq)]
pub enum FieldKind {
    Text,
    Number { min: u64, max: u64 },
    Toggle,
    Choice(Vec<String>),
    List,
    ReadOnly,
}

#[derive(Debug, Clone)]
pub struct Field {
    pub id: &'static str,
    pub label: String,
    pub kind: FieldKind,
    pub value: String,
    pub notes: Vec<String>,
    pub help: Option<&'static str>,
}

#[derive(Debug, Default)]
pub struct Form {
    pub fields: Vec<Field>,
    pub cursor: usize,
    /// Text being typed into the field under the cursor.
    pub editing: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Deferred {
    Next,
    Check,
    Apply,
}

/// Row editor for the Roughtime list: name, then address, then base64 key.
#[derive(Debug, Clone)]
pub struct ListEdit {
    pub stage: usize,
    pub name: String,
    pub addr: String,
    pub key: String,
    pub target: Option<usize>,
}

impl ListEdit {
    pub const PROMPTS: [&'static str; 3] = ["name", "address (host:port)", "public key (base64)"];

    pub fn buffer(&mut self) -> &mut String {
        match self.stage {
            0 => &mut self.name,
            1 => &mut self.addr,
            _ => &mut self.key,
        }
    }
}

pub enum Outcome {
    Apply(Box<Plan>),
    Cancel,
}

pub enum Reaction {
    Idle,
    /// Draw this message, then call [`Wizard::resume`].
    Probe(String),
    Done(Outcome),
}

pub struct Wizard {
    pub facts: Facts,
    probes: Box<dyn Probes>,
    cache: ProbeCache,
    pub step: Step,
    pub a: Answers,
    pub defaults: Answers,
    pub base_text: String,
    pub existing: ExistingInstall,
    pub findings: Vec<Finding>,
    pub scroll: usize,
    pub form: Form,
    pub issues: Vec<Issue>,
    pub quit_prompt: bool,
    pub parse_failed: bool,
    pub plan: Option<Result<Plan, String>>,
    pub review_cursor: usize,
    pub confirm_armed: bool,
    pub review_failures: Vec<Issue>,
    pub busy: Option<String>,
    pub flash: Option<String>,
    pub review_scroll: usize,
    pub list_edit: Option<ListEdit>,
    pub rt_sel: usize,
    deferred: Option<Deferred>,
    clock: fn() -> DateTime<Utc>,
}

pub struct Init {
    pub facts: Facts,
    pub probes: Box<dyn Probes>,
    pub answers: Answers,
    pub defaults: Answers,
    pub base_text: String,
    pub existing: ExistingInstall,
    pub clock: fn() -> DateTime<Utc>,
}

fn is_ctrl(k: &KeyEvent, c: char) -> bool {
    k.modifiers.contains(KeyModifiers::CONTROL) && k.code == KeyCode::Char(c)
}

fn on_off(b: bool) -> String {
    if b { "yes" } else { "no" }.to_owned()
}

fn is_on(v: &str) -> bool {
    v == "yes"
}

impl Wizard {
    pub fn new(init: Init) -> Self {
        let parse_failed = init.existing.config_exists && init.existing.config_parse.is_err();
        let mut w = Wizard {
            findings: Vec::new(),
            facts: init.facts,
            probes: init.probes,
            cache: ProbeCache::default(),
            step: Step::Scan,
            a: init.answers,
            defaults: init.defaults,
            base_text: init.base_text,
            existing: init.existing,
            scroll: 0,
            form: Form::default(),
            issues: Vec::new(),
            quit_prompt: false,
            parse_failed,
            plan: None,
            review_cursor: 0,
            confirm_armed: false,
            review_failures: Vec::new(),
            busy: None,
            flash: None,
            review_scroll: 0,
            list_edit: None,
            rt_sel: 0,
            deferred: None,
            clock: init.clock,
        };
        w.findings = scan::findings(&w.facts, &w.existing);
        w
    }

    fn cx(&self, force: bool) -> Ctx<'_> {
        Ctx {
            facts: &self.facts,
            probes: self.probes.as_ref(),
            cache: &self.cache,
            force_probe: force,
        }
    }

    pub fn authority_context(&self) -> AuthorityContext {
        validate::authority_context(&self.a, &self.cx(false))
    }

    pub fn orphan_risk(&self) -> bool {
        validate::orphan_risk(&self.a, &self.cx(false))
    }

    // --- steps ------------------------------------------------------------

    fn has_existing_warning(&self) -> bool {
        self.existing.any()
    }

    fn next_step(&self) -> Step {
        match self.step {
            Step::Scan if self.has_existing_warning() => Step::ExistingWarning,
            Step::Scan | Step::ExistingWarning => Step::Paths,
            Step::Paths => Step::Network,
            Step::Network => Step::S3,
            Step::S3 => Step::StorageLogging,
            Step::StorageLogging => Step::Security,
            Step::Security => Step::Authority,
            Step::Authority => Step::System,
            Step::System | Step::Review => Step::Review,
        }
    }

    fn prev_step(&self) -> Step {
        match self.step {
            Step::Scan | Step::ExistingWarning => self.step,
            Step::Paths if self.has_existing_warning() => Step::ExistingWarning,
            Step::Paths => Step::Scan,
            Step::Network => Step::Paths,
            Step::S3 => Step::Network,
            Step::StorageLogging => Step::S3,
            Step::Security => Step::StorageLogging,
            Step::Authority => Step::Security,
            Step::System => Step::Authority,
            Step::Review => Step::System,
        }
    }

    fn goto(&mut self, step: Step) {
        self.step = step;
        self.issues.clear();
        self.flash = None;
        self.form = Form::default();
        self.list_edit = None;
        if matches!(
            step,
            Step::Paths
                | Step::Network
                | Step::S3
                | Step::StorageLogging
                | Step::Security
                | Step::Authority
                | Step::System
        ) {
            self.rebuild();
            // Cheap steps show their warnings on entry; Authority probes on Tab.
            if step != Step::Authority {
                self.issues = validate::for_step(step, &self.a, &self.cx(false));
            }
        }
        if step == Step::Review {
            self.review_cursor = 0;
            self.confirm_armed = false;
            self.review_failures.clear();
            self.review_scroll = 0;
            self.a.resolve_ids(self.probes.as_ref());
            let now = (self.clock)();
            let plan = apply::build_plan(
                &self.a,
                &self.defaults,
                &self.base_text,
                &self.cx(false),
                now,
            );
            self.plan = Some(plan);
        }
    }

    fn refresh_existing(&mut self) {
        let base = PathBuf::from(&self.a.base_path);
        let ks = PathBuf::from(&self.a.keystore_dir);
        let lb = self.a.loaded.base_path.as_ref().map(PathBuf::from);
        let lk = self.a.loaded.keystore_dir.as_ref().map(PathBuf::from);
        let mut pairs = vec![PathPair {
            base_path: &base,
            keystore_dir: &ks,
        }];
        if let (Some(b), Some(k)) = (&lb, &lk) {
            pairs.push(PathPair {
                base_path: b,
                keystore_dir: k,
            });
        }
        self.existing = ExistingInstall::detect(&self.a.config_path, &pairs, self.probes.as_ref());
    }

    // --- key handling ------------------------------------------------------

    pub fn on_key(&mut self, k: KeyEvent) -> Reaction {
        self.flash = None;
        if self.quit_prompt {
            match k.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => return Reaction::Done(Outcome::Cancel),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => self.quit_prompt = false,
                _ => {}
            }
            return Reaction::Idle;
        }
        if is_ctrl(&k, 'c') {
            self.quit_prompt = true;
            return Reaction::Idle;
        }
        match self.step {
            Step::Scan => self.key_scan(k),
            Step::ExistingWarning => self.key_existing(k),
            Step::Review => self.key_review(k),
            _ => self.key_form(k),
        }
    }

    fn key_scan(&mut self, k: KeyEvent) -> Reaction {
        match k.code {
            KeyCode::Up => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::Down => self.scroll = (self.scroll + 1).min(self.findings.len()),
            KeyCode::Tab | KeyCode::Enter => {
                let next = self.next_step();
                self.goto(next);
            }
            KeyCode::Esc | KeyCode::Char('q') => self.quit_prompt = true,
            _ => {}
        }
        Reaction::Idle
    }

    fn key_existing(&mut self, k: KeyEvent) -> Reaction {
        if self.parse_failed {
            match k.code {
                KeyCode::Char('s') => {
                    self.base_text = config_doc::fresh_base_text();
                    self.a = self.defaults.clone();
                    self.parse_failed = false;
                    self.refresh_existing();
                    self.existing.config_parse = Ok(toml_edit::DocumentMut::new());
                    self.goto(Step::Paths);
                }
                KeyCode::Char('q') | KeyCode::Esc => self.quit_prompt = true,
                _ => {}
            }
            return Reaction::Idle;
        }
        match k.code {
            KeyCode::Enter | KeyCode::Tab => self.goto(Step::Paths),
            KeyCode::Esc | KeyCode::Char('q') => self.quit_prompt = true,
            KeyCode::BackTab => self.goto(Step::Scan),
            _ => {}
        }
        Reaction::Idle
    }

    fn key_review(&mut self, k: KeyEvent) -> Reaction {
        let can_apply = matches!(&self.plan, Some(Ok(p)) if !p.is_noop());
        match k.code {
            KeyCode::Up | KeyCode::Down => {
                self.review_cursor = 1 - self.review_cursor.min(1);
                self.confirm_armed = false;
            }
            KeyCode::PageDown => self.review_scroll += 5,
            KeyCode::PageUp => self.review_scroll = self.review_scroll.saturating_sub(5),
            KeyCode::BackTab | KeyCode::Esc => self.back_from_review(),
            KeyCode::Enter => {
                if self.review_cursor == 1 {
                    self.back_from_review();
                } else if can_apply {
                    let irreversible =
                        matches!(&self.plan, Some(Ok(p)) if p.authority.irreversible());
                    if irreversible && !self.confirm_armed {
                        self.confirm_armed = true;
                    } else {
                        self.deferred = Some(Deferred::Apply);
                        return Reaction::Probe("checking the host before applying...".into());
                    }
                }
            }
            _ => {}
        }
        Reaction::Idle
    }

    fn back_from_review(&mut self) {
        let target = self
            .review_failures
            .iter()
            .find(|i| i.is_error() && i.step != Step::Review)
            .map_or(Step::System, |i| i.step);
        self.goto(target);
    }

    fn key_form(&mut self, k: KeyEvent) -> Reaction {
        if self.list_edit.is_some() {
            self.key_list_edit(k);
            return Reaction::Idle;
        }
        if let Some(buf) = self.form.editing.as_mut() {
            match k.code {
                KeyCode::Enter => {
                    let value = std::mem::take(buf);
                    self.form.editing = None;
                    self.commit_current(&value);
                }
                KeyCode::Esc => self.form.editing = None,
                KeyCode::Backspace => {
                    buf.pop();
                }
                KeyCode::Char('u') if is_ctrl(&k, 'u') => buf.clear(),
                KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => buf.push(c),
                _ => {}
            }
            return Reaction::Idle;
        }
        let n = self.form.fields.len();
        match k.code {
            KeyCode::Up => self.form.cursor = self.form.cursor.saturating_sub(1),
            KeyCode::Down if n > 0 => self.form.cursor = (self.form.cursor + 1).min(n - 1),
            KeyCode::Tab => return self.tab(),
            KeyCode::BackTab | KeyCode::Esc => {
                let prev = self.prev_step();
                self.goto(prev);
            }
            KeyCode::Enter => self.activate(1),
            KeyCode::Right => self.activate_choice(1),
            KeyCode::Left => self.activate_choice(-1),
            KeyCode::Char('c') if self.step == Step::Authority => {
                self.deferred = Some(Deferred::Check);
                return Reaction::Probe("probing the TPM and Roughtime servers...".into());
            }
            KeyCode::Char('a') if self.current_kind() == Some(FieldKind::List) => {
                self.list_edit = Some(ListEdit {
                    stage: 0,
                    name: String::new(),
                    addr: String::new(),
                    key: String::new(),
                    target: None,
                });
            }
            KeyCode::Char('d') if self.current_kind() == Some(FieldKind::List) => {
                let sel = self.rt_sel;
                if sel < self.a.device.roughtime_servers.len() {
                    self.a.device.roughtime_servers.remove(sel);
                    self.rt_sel = self.rt_sel.saturating_sub(1);
                    self.rebuild();
                }
            }
            _ => {}
        }
        Reaction::Idle
    }

    fn tab(&mut self) -> Reaction {
        if self.step == Step::Authority && self.a.involves_registry() {
            self.deferred = Some(Deferred::Next);
            return Reaction::Probe("probing...".into());
        }
        self.try_next();
        Reaction::Idle
    }

    /// Run the deferred action after the probing frame was drawn.
    pub fn resume(&mut self) -> Option<Outcome> {
        let what = self.deferred.take();
        self.busy = None;
        match what {
            Some(Deferred::Next) => self.try_next(),
            Some(Deferred::Check) => {
                self.issues = validate::for_step(Step::Authority, &self.a, &self.cx(true));
                self.flash = Some(if validate::has_errors(&self.issues) {
                    "check finished: see the errors below".to_owned()
                } else {
                    "check finished: no errors".to_owned()
                });
            }
            Some(Deferred::Apply) => {
                let Some(Ok(plan)) = self.plan.take() else {
                    return None;
                };
                let found = apply::preflight(&plan, &self.cx(false));
                if validate::has_errors(&found) {
                    self.review_failures = found;
                    self.confirm_armed = false;
                    self.plan = Some(Ok(plan));
                } else {
                    return Some(Outcome::Apply(Box::new(plan)));
                }
            }
            None => {}
        }
        None
    }

    fn try_next(&mut self) {
        let found = validate::for_step(self.step, &self.a, &self.cx(false));
        let blocked = validate::has_errors(&found);
        self.issues = found;
        if blocked {
            return;
        }
        if self.step == Step::Paths {
            self.refresh_existing();
        }
        let next = self.next_step();
        self.goto(next);
    }

    fn current_kind(&self) -> Option<FieldKind> {
        self.form
            .fields
            .get(self.form.cursor)
            .map(|f| f.kind.clone())
    }

    fn activate(&mut self, dir: i32) {
        let Some(field) = self.form.fields.get(self.form.cursor).cloned() else {
            return;
        };
        match &field.kind {
            FieldKind::Text | FieldKind::Number { .. } => {
                self.form.editing = Some(field.value.clone());
            }
            FieldKind::Toggle => {
                let v = on_off(!is_on(&field.value));
                self.commit_current(&v);
            }
            FieldKind::Choice(_) => self.activate_choice(dir),
            FieldKind::List => self.edit_selected_row(),
            FieldKind::ReadOnly => {}
        }
    }

    fn activate_choice(&mut self, dir: i32) {
        let Some(field) = self.form.fields.get(self.form.cursor).cloned() else {
            return;
        };
        match &field.kind {
            FieldKind::Choice(opts) if !opts.is_empty() => {
                let cur = opts.iter().position(|o| *o == field.value).unwrap_or(0) as i32;
                let next = (cur + dir).rem_euclid(opts.len() as i32) as usize;
                let value = opts[next].clone();
                self.commit_current(&value);
            }
            FieldKind::List => {
                let n = self.a.device.roughtime_servers.len();
                if n > 0 {
                    self.rt_sel = (self.rt_sel as i32 + dir).rem_euclid(n as i32) as usize;
                }
            }
            _ => {}
        }
    }

    fn edit_selected_row(&mut self) {
        if let Some(s) = self.a.device.roughtime_servers.get(self.rt_sel) {
            self.list_edit = Some(ListEdit {
                stage: 0,
                name: s.name.clone(),
                addr: s.addr.clone(),
                key: s.public_key_b64.clone(),
                target: Some(self.rt_sel),
            });
        }
    }

    fn key_list_edit(&mut self, k: KeyEvent) {
        let Some(edit) = self.list_edit.as_mut() else {
            return;
        };
        match k.code {
            KeyCode::Esc => self.list_edit = None,
            KeyCode::Backspace => {
                edit.buffer().pop();
            }
            KeyCode::Char('u') if is_ctrl(&k, 'u') => edit.buffer().clear(),
            KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => {
                edit.buffer().push(c)
            }
            KeyCode::Enter => {
                if edit.stage < 2 {
                    edit.stage += 1;
                    return;
                }
                let row = RoughtimeServerAnswer {
                    name: edit.name.trim().to_owned(),
                    addr: edit.addr.trim().to_owned(),
                    public_key_b64: edit.key.trim().to_owned(),
                };
                let target = edit.target;
                self.list_edit = None;
                if row.name.is_empty() || row.addr.is_empty() || row.public_key_b64.is_empty() {
                    self.flash =
                        Some("a Roughtime server needs a name, an address and a key".into());
                    return;
                }
                match target {
                    Some(i) if i < self.a.device.roughtime_servers.len() => {
                        self.a.device.roughtime_servers[i] = row;
                    }
                    _ => {
                        self.a.device.roughtime_servers.push(row);
                        self.rt_sel = self.a.device.roughtime_servers.len() - 1;
                    }
                }
                self.rebuild();
            }
            _ => {}
        }
    }

    fn commit_current(&mut self, value: &str) {
        let Some(field) = self.form.fields.get(self.form.cursor) else {
            return;
        };
        let id = field.id;
        match self.set_field(id, value) {
            Ok(()) => {}
            Err(e) => self.flash = Some(e),
        }
        self.rebuild();
    }

    // --- answers <-> fields -----------------------------------------------

    fn reg(&mut self) -> Option<&mut NewRegistryAnswers> {
        match &mut self.a.authority {
            Some(Authority::NewRegistry(n)) => Some(n),
            _ => None,
        }
    }

    /// Parse `value` into the answers. Errors are shown as a flash and leave
    /// the answers unchanged.
    pub fn set_field(&mut self, id: &str, value: &str) -> Result<(), String> {
        fn num(value: &str, min: u64, max: u64) -> Result<u64, String> {
            let n: u64 = value
                .trim()
                .replace('_', "")
                .parse()
                .map_err(|_| "enter a whole number".to_owned())?;
            if n < min || n > max {
                return Err(format!("must be between {min} and {max}"));
            }
            Ok(n)
        }
        let path = |v: &str| {
            normalize(Path::new(v.trim()))
                .to_string_lossy()
                .into_owned()
        };
        let opt = |v: &str| -> Option<String> {
            let t = v.trim();
            (!t.is_empty()).then(|| t.to_owned())
        };
        let facts_io_uring_ok = self.facts.io_uring.is_ok();
        match id {
            "base_path" => self.a.base_path = path(value),
            "keystore_dir" => self.a.keystore_dir = path(value),
            "ack_data_risk" => self.a.ack_data_risk = is_on(value),
            "host" => self.a.host = value.trim().to_owned(),
            "port" => self.a.port = num(value, 0, 65_535)? as u16,
            "tls_enabled" => self.a.tls.enabled = is_on(value),
            "tls_cert" => self.a.tls.cert_path = path_or_empty(value),
            "tls_key" => self.a.tls.key_path = path_or_empty(value),
            "tls_client_ca" => self.a.tls.client_ca_path = path_or_empty(value),
            "tls_pq" => self.a.tls.require_pq_kex = is_on(value),
            "allow_insecure_bind" => self.a.allow_insecure_bind = is_on(value),
            "s3_enabled" => self.a.s3_enabled = is_on(value),
            "s3_host" => self.a.s3_host = value.trim().to_owned(),
            "s3_port" => self.a.s3_port = num(value, 0, 65_535)? as u16,
            "s3_region" => self.a.s3_region = value.trim().to_owned(),
            "s3_vhost" => self.a.s3_virtual_host_domain = value.trim().to_owned(),
            "s3_tls_enabled" => self.a.s3_tls.enabled = is_on(value),
            "s3_tls_cert" => self.a.s3_tls.cert_path = path_or_empty(value),
            "s3_tls_key" => self.a.s3_tls.key_path = path_or_empty(value),
            "s3_tls_client_ca" => self.a.s3_tls.client_ca_path = path_or_empty(value),
            "s3_tls_pq" => self.a.s3_tls.require_pq_kex = is_on(value),
            "s3_allow_insecure_bind" => self.a.s3_allow_insecure_bind = is_on(value),
            "backend" => {
                if value == "uring" && !facts_io_uring_ok {
                    return Err("io_uring is unavailable on this host".into());
                }
                self.a.backend = value.to_owned();
            }
            "default_sync" => self.a.default_sync = value.to_owned(),
            "log_filter" => self.a.log_filter = value.trim().to_owned(),
            "log_format" => self.a.log_format = value.to_owned(),
            "default_ttl" => self.a.default_ttl_seconds = num(value, 0, u64::MAX)?,
            "max_ttl" => self.a.max_ttl_seconds = num(value, 0, u64::MAX)?,
            "max_failed" => self.a.max_failed_logins = num(value, 0, u32::MAX.into())? as u32,
            "lockout" => self.a.lockout_seconds = num(value, 0, u64::MAX)?,
            "enforce_authz" => self.a.enforce_authorization = is_on(value),
            "max_refreshes" => self.a.max_refreshes = num(value, 0, u32::MAX.into())? as u32,
            "argon_m" => self.a.argon_m_cost_kib = num(value, 0, u32::MAX.into())? as u32,
            "argon_t" => self.a.argon_t_cost = num(value, 0, u32::MAX.into())? as u32,
            "argon_p" => self.a.argon_p_cost = num(value, 0, u32::MAX.into())? as u32,
            "allow_unprotected" => self.a.allow_unprotected_memory = is_on(value),
            "authority" => {
                let kind = AuthorityKind::ALL
                    .iter()
                    .find(|k| k.label() == value)
                    .copied()
                    .ok_or_else(|| "unknown authority".to_owned())?;
                if self.a.authority.as_ref().map(Authority::kind) != Some(kind) {
                    self.a.select_authority(kind, &self.facts);
                }
            }
            "key_source" => {
                if let Some(Authority::OperatorKey { mode, .. }) = &mut self.a.authority {
                    *mode = if value.starts_with("Use") {
                        KeySource::UseExisting
                    } else {
                        KeySource::Generate
                    };
                }
            }
            "key_file" => {
                if let Some(Authority::OperatorKey { file, .. }) = &mut self.a.authority {
                    *file = path_or_empty(value);
                }
            }
            "first_device" => {
                let first = if value.starts_with("FIDO2") {
                    FirstKind::Fido2
                } else {
                    FirstKind::Tpm
                };
                if let Some(n) = self.reg() {
                    n.first = first;
                }
                self.a.install_udev_rule = first == FirstKind::Fido2;
            }
            "tpm_label" | "fido_label" => {
                let l = opt(value);
                if let Some(n) = self.reg() {
                    n.label = l;
                }
            }
            "tpm_tcti" => self.a.device.tcti = value.trim().to_owned(),
            "tpm_pcrs" => {
                let mut pcrs = Vec::new();
                for part in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                    let n: u8 = part
                        .parse()
                        .ok()
                        .filter(|n| *n <= 23)
                        .ok_or_else(|| format!("'{part}' is not a PCR index 0..=23"))?;
                    pcrs.push(n);
                }
                pcrs.sort_unstable();
                pcrs.dedup();
                if pcrs.is_empty() {
                    return Err("name at least one PCR".into());
                }
                if let Some(n) = self.reg() {
                    n.pcrs = pcrs;
                }
            }
            "allow_sb_off" => {
                if let Some(n) = self.reg() {
                    n.allow_secure_boot_off = is_on(value);
                }
            }
            "away_grant" => {
                let secs = num(value, 0, u32::MAX.into())? as u32;
                if let Some(n) = self.reg() {
                    n.away_grant_seconds = secs;
                }
            }
            "uv_required" => {
                if let Some(n) = self.reg() {
                    n.uv_required = is_on(value);
                }
            }
            "hid_path" => {
                let v = opt(value);
                if let Some(n) = self.reg() {
                    n.hid_path = v;
                }
            }
            "adopt_file" => {
                let v = path_or_empty(value);
                if let Some(n) = self.reg() {
                    n.adopt_key_file = Some(v);
                }
            }
            "ack_adopted" => {
                if let Some(Authority::FinishMigration { ack_adopted }) = &mut self.a.authority {
                    *ack_adopted = is_on(value);
                }
            }
            "use_helper" => self.a.device.use_helper = is_on(value),
            "key_user" => self.a.device.key_user = value.trim().to_owned(),
            "socket_path" => self.a.device.socket_path = path_or_empty(value),
            "state_dir" => self.a.device.state_dir = path_or_empty(value),
            "rt_timeout" => self.a.device.roughtime_timeout_ms = num(value, 0, u64::MAX)?,
            "rt_min" => self.a.device.roughtime_min_responses = num(value, 0, 255)? as u8,
            "daemon_user" => self.a.daemon_user = value.trim().to_owned(),
            "group" => self.a.group = value.trim().to_owned(),
            "install_units" => self.a.install_units = is_on(value),
            "unit_root" => self.a.unit_root = path_or_empty(value),
            "binary_path" => self.a.binary_path = path_or_empty(value),
            "socket_group" => self.a.socket_group = value.trim().to_owned(),
            "key_user_group" => self.a.key_user_group = value.trim().to_owned(),
            "install_udev" => self.a.install_udev_rule = is_on(value),
            "udev_vendor" => self.a.udev_vendor_id = value.trim().to_owned(),
            "arm_on_start" => self.a.device.arm_on_start = is_on(value),
            _ => return Err(format!("field {id} is not editable")),
        }
        Ok(())
    }

    /// Recompute the visible fields from the answers, keeping the cursor on
    /// the same field when it is still there.
    pub fn rebuild(&mut self) {
        let keep = self.form.fields.get(self.form.cursor).map(|f| f.id);
        let fields = self.build_fields();
        self.form.cursor = keep
            .and_then(|id| fields.iter().position(|f| f.id == id))
            .unwrap_or(self.form.cursor.min(fields.len().saturating_sub(1)));
        self.form.fields = fields;
    }

    fn build_fields(&self) -> Vec<Field> {
        let a = &self.a;
        let mut v: Vec<Field> = Vec::new();
        let text = |id, label: &str, value: &str| Field {
            id,
            label: label.to_owned(),
            kind: FieldKind::Text,
            value: value.to_owned(),
            notes: Vec::new(),
            help: None,
        };
        let number = |id, label: &str, value: u64, min, max| Field {
            id,
            label: label.to_owned(),
            kind: FieldKind::Number { min, max },
            value: value.to_string(),
            notes: Vec::new(),
            help: None,
        };
        let toggle = |id, label: &str, value: bool| Field {
            id,
            label: label.to_owned(),
            kind: FieldKind::Toggle,
            value: on_off(value),
            notes: Vec::new(),
            help: None,
        };
        let choice = |id, label: &str, opts: Vec<String>, value: &str| Field {
            id,
            label: label.to_owned(),
            kind: FieldKind::Choice(opts),
            value: value.to_owned(),
            notes: Vec::new(),
            help: None,
        };
        let loopback = |h: &str| crate::config::host_is_loopback(h);
        match self.step {
            Step::Paths => {
                v.push(Field {
                    id: "config_file",
                    label: "Config file".into(),
                    kind: FieldKind::ReadOnly,
                    value: a.config_path.to_string_lossy().into_owned(),
                    notes: Vec::new(),
                    help: None,
                });
                v.push(text("base_path", "Data directory", &a.base_path));
                v.push(text("keystore_dir", "Keystore directory", &a.keystore_dir));
                if self.orphan_risk() {
                    v.push(toggle(
                        "ack_data_risk",
                        "I understand existing data is not moved and may become unreadable",
                        a.ack_data_risk,
                    ));
                }
            }
            Step::Network => {
                v.push(text("host", "Listen address", &a.host));
                v.push(number("port", "Port", a.port.into(), 0, 65_535));
                v.push(toggle("tls_enabled", "Enable TLS", a.tls.enabled));
                if a.tls.enabled {
                    v.push(text("tls_cert", "TLS certificate (PEM)", &a.tls.cert_path));
                    v.push(text("tls_key", "TLS private key (PEM)", &a.tls.key_path));
                    v.push(text(
                        "tls_client_ca",
                        "Client CA bundle (optional, enables mTLS)",
                        &a.tls.client_ca_path,
                    ));
                    v.push(toggle(
                        "tls_pq",
                        "Require post-quantum key exchange",
                        a.tls.require_pq_kex,
                    ));
                } else if !loopback(&a.host) {
                    v.push(toggle(
                        "allow_insecure_bind",
                        "Allow insecure bind",
                        a.allow_insecure_bind,
                    ));
                }
            }
            Step::S3 => {
                v.push(toggle("s3_enabled", "Enable S3 gateway", a.s3_enabled));
                if a.s3_enabled {
                    v.push(text("s3_host", "S3 listen address", &a.s3_host));
                    v.push(number("s3_port", "S3 port", a.s3_port.into(), 0, 65_535));
                    v.push(text("s3_region", "Region", &a.s3_region));
                    v.push(text(
                        "s3_vhost",
                        "Virtual-host domain (optional)",
                        &a.s3_virtual_host_domain,
                    ));
                    v.push(toggle("s3_tls_enabled", "S3 TLS enabled", a.s3_tls.enabled));
                    if a.s3_tls.enabled {
                        v.push(text(
                            "s3_tls_cert",
                            "S3 TLS certificate (PEM)",
                            &a.s3_tls.cert_path,
                        ));
                        v.push(text(
                            "s3_tls_key",
                            "S3 TLS private key (PEM)",
                            &a.s3_tls.key_path,
                        ));
                        v.push(text(
                            "s3_tls_client_ca",
                            "S3 client CA bundle (optional)",
                            &a.s3_tls.client_ca_path,
                        ));
                        v.push(toggle(
                            "s3_tls_pq",
                            "S3 require post-quantum key exchange",
                            a.s3_tls.require_pq_kex,
                        ));
                    } else if !loopback(&a.s3_host) {
                        v.push(toggle(
                            "s3_allow_insecure_bind",
                            "Allow insecure bind (S3)",
                            a.s3_allow_insecure_bind,
                        ));
                    }
                }
            }
            Step::StorageLogging => {
                let mut backends = vec!["filesystem".to_owned()];
                if self.facts.io_uring.is_ok() {
                    backends.push("uring".to_owned());
                }
                v.push(choice("backend", "Storage backend", backends, &a.backend));
                v.push(choice(
                    "default_sync",
                    "Default durability",
                    vec!["durable".into(), "best-effort".into()],
                    &a.default_sync,
                ));
                v.push(text("log_filter", "Log filter", &a.log_filter));
                v.push(choice(
                    "log_format",
                    "Log format",
                    vec!["text".into(), "json".into()],
                    &a.log_format,
                ));
            }
            Step::Security => {
                v.push(number(
                    "default_ttl",
                    "Default session TTL (s)",
                    a.default_ttl_seconds,
                    1,
                    u64::MAX,
                ));
                v.push(number(
                    "max_ttl",
                    "Max session TTL (s)",
                    a.max_ttl_seconds,
                    1,
                    u64::MAX,
                ));
                v.push(number(
                    "max_failed",
                    "Max failed logins (0 disables)",
                    a.max_failed_logins.into(),
                    0,
                    u32::MAX.into(),
                ));
                v.push(number(
                    "lockout",
                    "Lockout (s)",
                    a.lockout_seconds,
                    0,
                    u64::MAX,
                ));
                v.push(toggle(
                    "enforce_authz",
                    "Enforce authorization",
                    a.enforce_authorization,
                ));
                v.push(number(
                    "max_refreshes",
                    "Max token refreshes",
                    a.max_refreshes.into(),
                    0,
                    u32::MAX.into(),
                ));
                v.push(number(
                    "argon_m",
                    "Argon2 memory (KiB)",
                    a.argon_m_cost_kib.into(),
                    0,
                    u32::MAX.into(),
                ));
                v.push(number(
                    "argon_t",
                    "Argon2 iterations",
                    a.argon_t_cost.into(),
                    0,
                    u32::MAX.into(),
                ));
                v.push(number(
                    "argon_p",
                    "Argon2 lanes",
                    a.argon_p_cost.into(),
                    0,
                    u32::MAX.into(),
                ));
                if self.facts.memfd_secret.is_err() || a.allow_unprotected_memory {
                    v.push(toggle(
                        "allow_unprotected",
                        "Allow unprotected memory",
                        a.allow_unprotected_memory,
                    ));
                }
            }
            Step::Authority => self.authority_fields(&mut v),
            Step::System => self.system_fields(&mut v),
            _ => {}
        }
        v
    }

    fn authority_fields(&self, v: &mut Vec<Field>) {
        let a = &self.a;
        let ctx = self.authority_context();
        let kinds = a.authority_kinds(&ctx);
        let options: Vec<String> = kinds
            .iter()
            .filter(|k| k.available())
            .map(|k| k.kind.label().to_owned())
            .collect();
        let notes: Vec<String> = kinds
            .iter()
            .filter_map(|k| {
                k.reason
                    .as_ref()
                    .map(|r| format!("{}: unavailable ({r})", k.kind.label()))
            })
            .collect();
        v.push(Field {
            id: "authority",
            label: "Node-key authority".into(),
            kind: FieldKind::Choice(options),
            value: a.authority.as_ref().map_or_else(
                || "(choose one)".to_owned(),
                |x| x.kind().label().to_owned(),
            ),
            notes,
            help: Some("c: probe the TPM and Roughtime servers now"),
        });
        let f = |id, label: &str, kind, value: String| Field {
            id,
            label: label.to_owned(),
            kind,
            value,
            notes: Vec::new(),
            help: None,
        };
        let txt = |id, label: &str, value: &str| f(id, label, FieldKind::Text, value.to_owned());
        let tog = |id, label: &str, b: bool| f(id, label, FieldKind::Toggle, on_off(b));
        match &a.authority {
            Some(Authority::OperatorKey { mode, file }) => {
                v.push(f(
                    "key_source",
                    "Key source",
                    FieldKind::Choice(vec!["Generate new key".into(), "Use existing key".into()]),
                    match mode {
                        KeySource::Generate => "Generate new key",
                        KeySource::UseExisting => "Use existing key",
                    }
                    .to_owned(),
                ));
                v.push(txt("key_file", "Key file", file));
            }
            Some(Authority::NewRegistry(n)) => {
                v.push(f(
                    "first_device",
                    "First device",
                    FieldKind::Choice(vec![
                        "TPM 2.0 (home device)".into(),
                        "FIDO2 token (away device)".into(),
                    ]),
                    match n.first {
                        FirstKind::Tpm => "TPM 2.0 (home device)",
                        FirstKind::Fido2 => "FIDO2 token (away device)",
                    }
                    .to_owned(),
                ));
                match n.first {
                    FirstKind::Tpm => {
                        v.push(txt("tpm_label", "Label", n.label.as_deref().unwrap_or("")));
                        v.push(txt("tpm_tcti", "TCTI", &a.device.tcti));
                        v.push(txt(
                            "tpm_pcrs",
                            "PCRs",
                            &n.pcrs
                                .iter()
                                .map(u8::to_string)
                                .collect::<Vec<_>>()
                                .join(","),
                        ));
                        let sb = self.facts.secure_boot.unwrap_or(SecureBoot::Unknown);
                        if n.pcrs.contains(&7) && sb != SecureBoot::Enabled {
                            v.push(tog(
                                "allow_sb_off",
                                "Allow PCR 7 without Secure Boot",
                                n.allow_secure_boot_off,
                            ));
                        }
                        v.push(f(
                            "away_grant",
                            "Away grant (s)",
                            FieldKind::Number {
                                min: 60,
                                max: 2_592_000,
                            },
                            n.away_grant_seconds.to_string(),
                        ));
                    }
                    FirstKind::Fido2 => {
                        v.push(txt("fido_label", "Label", n.label.as_deref().unwrap_or("")));
                        let mut fld = tog("uv_required", "Require PIN/UV", n.uv_required);
                        fld.help =
                            Some("a token without a PIN set fails registration while this is on");
                        v.push(fld);
                        if self.facts.fido2_count() >= 2 {
                            let list = self
                                .facts
                                .fido2
                                .as_ref()
                                .and_then(|r| r.as_ref().ok())
                                .cloned()
                                .unwrap_or_default();
                            v.push(f(
                                "hid_path",
                                "Authenticator",
                                FieldKind::Choice(list),
                                n.hid_path.clone().unwrap_or_default(),
                            ));
                        }
                    }
                }
                if ctx.keystore_json {
                    v.push(txt(
                        "adopt_file",
                        "Existing node-key file to adopt",
                        n.adopt_key_file.as_deref().unwrap_or(""),
                    ));
                }
            }
            Some(Authority::FinishMigration { ack_adopted }) => {
                v.push(tog(
                    "ack_adopted",
                    "This registry was created by adopting this key file",
                    *ack_adopted,
                ));
            }
            _ => {}
        }
        if a.involves_registry() {
            v.push(tog(
                "use_helper",
                "Use key helper (separate uid)",
                a.device.use_helper,
            ));
            if a.device.use_helper {
                v.push(txt("key_user", "Key helper user", &a.device.key_user));
                v.push(txt(
                    "socket_path",
                    "Helper socket path",
                    &a.device.socket_path,
                ));
                v.push(txt(
                    "state_dir",
                    "Helper state directory",
                    &a.device.state_dir,
                ));
            }
            if self.shows_roughtime() {
                v.push(f(
                    "roughtime",
                    "Roughtime servers",
                    FieldKind::List,
                    a.device
                        .roughtime_servers
                        .iter()
                        .map(|s| format!("{} {}", s.name, s.addr))
                        .collect::<Vec<_>>()
                        .join("\n"),
                ));
                v.push(f(
                    "rt_timeout",
                    "Roughtime timeout (ms)",
                    FieldKind::Number {
                        min: 200,
                        max: 30_000,
                    },
                    a.device.roughtime_timeout_ms.to_string(),
                ));
                v.push(f(
                    "rt_min",
                    "Roughtime min responses",
                    FieldKind::Number { min: 2, max: 16 },
                    a.device.roughtime_min_responses.to_string(),
                ));
            }
        }
    }

    fn shows_roughtime(&self) -> bool {
        match &self.a.authority {
            Some(Authority::NewRegistry(n)) => n.first == FirstKind::Tpm,
            Some(Authority::Keep(_)) | Some(Authority::FinishMigration { .. }) => self
                .probes
                .registry_summary(Path::new(&self.a.keystore_dir))
                .is_none_or(|s| s.has_home),
            _ => false,
        }
    }

    fn system_fields(&self, v: &mut Vec<Field>) {
        let a = &self.a;
        let f = |id, label: &str, kind, value: String| Field {
            id,
            label: label.to_owned(),
            kind,
            value,
            notes: Vec::new(),
            help: None,
        };
        let txt = |id, label: &str, value: &str| f(id, label, FieldKind::Text, value.to_owned());
        let tog = |id, label: &str, b: bool| f(id, label, FieldKind::Toggle, on_off(b));
        v.push(txt("daemon_user", "Daemon user", &a.daemon_user));
        v.push(txt("group", "Shared group", &a.group));
        v.push(tog(
            "install_units",
            "Install systemd units",
            a.install_units,
        ));
        if a.install_units {
            let helper = apply::helper_effective(a);
            v.push(txt("unit_root", "Unit install root", &a.unit_root));
            v.push(txt("binary_path", "Binary path", &a.binary_path));
            v.push(txt("socket_group", "Socket group", &a.socket_group));
            if helper {
                v.push(txt(
                    "key_user_group",
                    "Key user primary group",
                    &a.key_user_group,
                ));
                v.push(tog(
                    "install_udev",
                    "Install FIDO2 udev rule",
                    a.install_udev_rule,
                ));
                if a.install_udev_rule {
                    v.push(txt(
                        "udev_vendor",
                        "Authenticator USB vendor id (hex)",
                        &a.udev_vendor_id,
                    ));
                }
                if apply::arm_toggle_needed(a, self.probes.as_ref()) {
                    v.push(tog(
                        "arm_on_start",
                        "Arm unattended on start",
                        a.device.arm_on_start,
                    ));
                }
            }
        }
    }

    pub fn current_issues(&self, id: &str) -> impl Iterator<Item = &Issue> {
        let id = id.to_owned();
        self.issues.iter().filter(move |i| i.field == id)
    }

    /// Issues that name no visible field on this screen.
    pub fn unattached_issues(&self) -> Vec<&Issue> {
        self.issues
            .iter()
            .filter(|i| !self.form.fields.iter().any(|f| f.id == i.field))
            .collect()
    }

    #[cfg(test)]
    pub fn error_count(&self) -> usize {
        self.issues.iter().filter(|i| i.is_error()).count()
    }
}

fn path_or_empty(value: &str) -> String {
    let t = value.trim();
    if t.is_empty() {
        String::new()
    } else {
        normalize(Path::new(t)).to_string_lossy().into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::scan::test_facts;
    use crate::setup::validate::FakeProbes;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::KeyEventKind;

    fn key(code: KeyCode) -> KeyEvent {
        let mut k = KeyEvent::new(code, KeyModifiers::NONE);
        k.kind = KeyEventKind::Press;
        k
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn clock() -> DateTime<Utc> {
        chrono::TimeZone::timestamp_opt(&Utc, 1_800_000_000, 0).unwrap()
    }

    struct Fixture {
        dir: tempfile::TempDir,
    }

    fn init(dir: &Path, existing_config: Option<&str>) -> Init {
        let facts = test_facts();
        let probes = FakeProbes::default();
        let config = dir.join("config.toml");
        let defaults = Answers::defaults(&facts, &probes, &config);
        let mut answers = defaults.clone();
        answers.base_path = dir.join("data").to_string_lossy().into_owned();
        answers.keystore_dir = dir.join("keys").to_string_lossy().into_owned();
        answers.authority = Some(Authority::OperatorKey {
            mode: KeySource::Generate,
            file: dir.join("node.key").to_string_lossy().into_owned(),
        });
        let (base_text, existing) = match existing_config {
            Some(text) => {
                std::fs::write(&config, text).unwrap();
                let doc: toml_edit::DocumentMut = text.parse().unwrap();
                answers = Answers::from_doc(&doc, defaults.clone(), &facts, &probes);
                let ex = ExistingInstall::detect(&config, &[], &probes);
                (text.to_owned(), ex)
            }
            None => (config_doc::fresh_base_text(), ExistingInstall::empty()),
        };
        Init {
            facts,
            probes: Box::new(probes),
            answers,
            defaults,
            base_text,
            existing,
            clock,
        }
    }

    fn press(w: &mut Wizard, code: KeyCode) {
        if let Reaction::Probe(_) = w.on_key(key(code)) {
            w.resume();
        }
    }

    fn type_text(w: &mut Wizard, s: &str) {
        for c in s.chars() {
            w.on_key(key(KeyCode::Char(c)));
        }
    }

    fn render(w: &Wizard, cols: u16, rows: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(cols, rows)).unwrap();
        t.draw(|f| crate::setup::ui::draw(f, w)).unwrap();
        let buf = t.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn fresh_install_reaches_review_and_apply_is_offered() {
        let fx = Fixture {
            dir: tempfile::tempdir().unwrap(),
        };
        let mut w = Wizard::new(init(fx.dir.path(), None));
        assert_eq!(w.step, Step::Scan);
        for expect in [
            Step::Paths,
            Step::Network,
            Step::S3,
            Step::StorageLogging,
            Step::Security,
            Step::Authority,
            Step::System,
            Step::Review,
        ] {
            press(&mut w, KeyCode::Tab);
            assert_eq!(w.step, expect, "issues: {:?}", w.issues);
        }
        let plan = w.plan.as_ref().unwrap().as_ref().unwrap();
        assert!(!plan.is_noop());
        assert!(plan.authority.irreversible());
    }

    #[test]
    fn tab_on_an_invalid_field_stays_and_esc_goes_back() {
        let fx = Fixture {
            dir: tempfile::tempdir().unwrap(),
        };
        let mut w = Wizard::new(init(fx.dir.path(), None));
        press(&mut w, KeyCode::Tab); // Paths
        // Edit the data directory to a protected root.
        press(&mut w, KeyCode::Down);
        press(&mut w, KeyCode::Enter);
        w.on_key(ctrl('u'));
        type_text(&mut w, "/usr");
        press(&mut w, KeyCode::Enter);
        press(&mut w, KeyCode::Tab);
        assert_eq!(w.step, Step::Paths);
        assert!(w.error_count() > 0);
        press(&mut w, KeyCode::Esc);
        assert_eq!(w.step, Step::Scan);
    }

    #[test]
    fn existing_warning_appears_only_when_something_exists() {
        let fx = Fixture {
            dir: tempfile::tempdir().unwrap(),
        };
        let mut fresh = Wizard::new(init(fx.dir.path(), None));
        press(&mut fresh, KeyCode::Tab);
        assert_eq!(fresh.step, Step::Paths);

        let dir2 = tempfile::tempdir().unwrap();
        let mut w = Wizard::new(init(
            dir2.path(),
            Some(
                "[server]\nhost = \"127.0.0.1\"\nport = 8080\n\n[storage]\nbase_path = \"/d\"\n\n[crypto]\nkeystore_dir = \"/k\"\nnode_key_file = \"/etc/n.key\"\n",
            ),
        ));
        press(&mut w, KeyCode::Tab);
        assert_eq!(w.step, Step::ExistingWarning);
        assert!(render(&w, 100, 30).contains("existing installation"));
        press(&mut w, KeyCode::Tab);
        assert_eq!(w.step, Step::Paths);
    }

    #[test]
    fn ctrl_c_then_y_cancels_and_n_returns() {
        let fx = Fixture {
            dir: tempfile::tempdir().unwrap(),
        };
        let mut w = Wizard::new(init(fx.dir.path(), None));
        w.on_key(ctrl('c'));
        assert!(w.quit_prompt);
        w.on_key(key(KeyCode::Char('n')));
        assert!(!w.quit_prompt);
        w.on_key(ctrl('c'));
        assert!(matches!(
            w.on_key(key(KeyCode::Char('y'))),
            Reaction::Done(Outcome::Cancel)
        ));
    }

    #[test]
    fn every_step_renders_at_80x24_and_small_terminals_are_refused() {
        let fx = Fixture {
            dir: tempfile::tempdir().unwrap(),
        };
        let mut w = Wizard::new(init(fx.dir.path(), None));
        for _ in 0..9 {
            let screen = render(&w, 80, 24);
            assert!(!screen.contains("terminal too small"));
            assert!(screen.contains(w.step.title()), "{:?}\n{screen}", w.step);
            press(&mut w, KeyCode::Tab);
        }
        assert!(render(&w, 40, 10).contains("terminal too small"));
    }

    #[test]
    fn unparsable_config_offers_only_defaults_or_quit() {
        let fx = Fixture {
            dir: tempfile::tempdir().unwrap(),
        };
        let mut i = init(fx.dir.path(), None);
        i.existing.config_exists = true;
        i.existing.config_parse = Err("line 1: bad".into());
        let mut w = Wizard::new(i);
        press(&mut w, KeyCode::Tab);
        assert_eq!(w.step, Step::ExistingWarning);
        press(&mut w, KeyCode::Enter);
        assert_eq!(w.step, Step::ExistingWarning);
        assert!(render(&w, 100, 30).contains("bad"));
        press(&mut w, KeyCode::Char('s'));
        assert_eq!(w.step, Step::Paths);
    }

    #[test]
    fn roughtime_rows_are_added_edited_and_deleted() {
        let fx = Fixture {
            dir: tempfile::tempdir().unwrap(),
        };
        let mut w = Wizard::new(init(fx.dir.path(), None));
        w.a.authority = Some(Authority::NewRegistry(NewRegistryAnswers::default()));
        w.step = Step::Authority;
        w.rebuild();
        let pos = w
            .form
            .fields
            .iter()
            .position(|f| f.id == "roughtime")
            .unwrap();
        w.form.cursor = pos;
        w.on_key(key(KeyCode::Char('a')));
        type_text(&mut w, "alpha");
        w.on_key(key(KeyCode::Enter));
        type_text(&mut w, "127.0.0.1:2002");
        w.on_key(key(KeyCode::Enter));
        type_text(&mut w, "AAAA");
        w.on_key(key(KeyCode::Enter));
        assert_eq!(w.a.device.roughtime_servers.len(), 1);
        w.on_key(key(KeyCode::Enter)); // edit selected row
        w.on_key(ctrl('u'));
        type_text(&mut w, "beta");
        for _ in 0..3 {
            w.on_key(key(KeyCode::Enter));
        }
        assert_eq!(w.a.device.roughtime_servers[0].name, "beta");
        w.on_key(key(KeyCode::Char('d')));
        assert!(w.a.device.roughtime_servers.is_empty());
    }

    #[test]
    fn set_field_rejects_garbage_and_normalizes_paths() {
        let fx = Fixture {
            dir: tempfile::tempdir().unwrap(),
        };
        let mut w = Wizard::new(init(fx.dir.path(), None));
        assert!(w.set_field("port", "70000").is_err());
        assert!(w.set_field("port", "abc").is_err());
        w.set_field("port", "9090").unwrap();
        assert_eq!(w.a.port, 9090);
        w.set_field("base_path", "/srv/a/./b/../c").unwrap();
        assert_eq!(w.a.base_path, "/srv/a/c");
        assert!(w.set_field("tpm_pcrs", "7,99").is_err());
    }

    #[test]
    fn sanitize_leaves_no_control_or_format_characters() {
        let s = crate::setup::sanitize("\x1b]52;c;x\x07\u{202e}ok");
        assert!(!s.chars().any(|c| c.is_control()));
        assert!(!s.contains('\u{202e}'));
        assert!(s.ends_with("ok"));
    }
}
