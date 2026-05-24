use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::mpsc::UnboundedSender;
use y2q_client::ListOptions;

use crate::client_builder::client_from_alias;
use crate::config::{CliConfig, default_tokens_path};
use crate::output::{fmt_bytes, fmt_ns};
use crate::progress::{CountingReader, CountingWriter, ProgressReporter};
use crate::token::{TokenEntry, TokenStore};

use super::actions::Action;
use super::admin::{EventsView, LocksView, MetricsView, RebuildView, UsersView};
use super::events::{Event, RemoteFetchPath, RemoteFetchResult};
use super::pane::{LocalPane, RemotePane};
use super::state::{AdminTab, ConfirmAction, FocusedPane, InputAction, Mode};
use super::widgets::throbber::LoadingIndicator;
use super::widgets::transfer_bar::{TransferEntry, TransferStatus};

static TRANSFER_ID: AtomicU64 = AtomicU64::new(1);

/// Sends transfer progress to the TUI event channel instead of stderr.
struct TuiTransferReporter {
    id: u64,
    tx: UnboundedSender<Event>,
}

impl ProgressReporter for TuiTransferReporter {
    fn start(&mut self, _: &str, _: Option<u64>) {}
    fn update(&mut self, bytes_done: u64, speed_bps: u64) {
        let _ = self.tx.send(Event::TransferUpdate {
            id: self.id,
            bytes_done,
            speed_bps,
        });
    }
    fn finish(&mut self, _: u64) {}
}

/// Build an authenticated client for `alias` from owned config + tokens path,
/// for use inside spawned tasks. Returns a display string on failure.
fn build_client(
    config: &CliConfig,
    tokens_path: &std::path::Path,
    alias: &str,
) -> Result<y2q_client::Y2qClient, String> {
    let profile = config
        .aliases
        .get(alias)
        .ok_or_else(|| format!("unknown alias `{alias}`"))?;
    let store = TokenStore::load(tokens_path).map_err(|e| e.to_string())?;
    let token = store
        .token_for(alias)
        .ok_or_else(|| "not authenticated — press 'L' to log in".to_string())?;
    client_from_alias(profile, Some(token)).map_err(|e| e.to_string())
}

pub struct App {
    pub mode: Mode,
    pub focused: FocusedPane,
    pub local: LocalPane,
    pub remote: RemotePane,
    pub transfer_bar_visible: bool,
    pub transfers: VecDeque<TransferEntry>,
    pub remote_throbber: LoadingIndicator,
    pub rebuild: RebuildView,
    pub locks: LocksView,
    pub users_view: UsersView,
    pub metrics_view: MetricsView,
    pub events_view: EventsView,
    pub active_alias: Option<String>,
    pub event_tx: UnboundedSender<Event>,
    pub config: CliConfig,
    pub should_quit: bool,
}

impl App {
    pub fn new(config: CliConfig, event_tx: UnboundedSender<Event>) -> Self {
        let aliases: Vec<String> = config.aliases.keys().cloned().collect();
        let remote = RemotePane::new(aliases);
        Self {
            mode: Mode::default(),
            focused: FocusedPane::default(),
            local: LocalPane::new(),
            remote,
            transfer_bar_visible: true,
            transfers: VecDeque::with_capacity(50),
            remote_throbber: LoadingIndicator::default(),
            rebuild: RebuildView::default(),
            locks: LocksView::default(),
            users_view: UsersView::default(),
            metrics_view: MetricsView::default(),
            events_view: EventsView::default(),
            active_alias: None,
            event_tx,
            config,
            should_quit: false,
        }
    }

    pub fn update(&mut self, event: Event) -> Action {
        match event {
            Event::Tick => {
                self.remote_throbber.tick();
                Action::None
            }
            Event::Render => Action::None,
            Event::Quit => {
                self.should_quit = true;
                Action::Quit
            }
            Event::Key(key) => self.handle_key(key),
            Event::Resize(_, _) => Action::None,
            Event::TransferUpdate {
                id,
                bytes_done,
                speed_bps,
            } => {
                self.apply_transfer_update(id, bytes_done, speed_bps);
                Action::None
            }
            Event::TransferDone { id, result } => {
                self.apply_transfer_done(id, result);
                Action::None
            }
            Event::RemoteFetched {
                alias,
                path,
                result,
            } => {
                self.apply_remote_fetched(alias, path, result);
                Action::None
            }
            Event::RebuildStatus {
                state,
                percent,
                reason,
                ..
            } => {
                self.rebuild = RebuildView {
                    state,
                    percent,
                    reason,
                };
                Action::None
            }
            Event::UsersLoaded { users, .. } => {
                self.users_view.set_users(users);
                Action::None
            }
            Event::LocksLoaded { locks, .. } => {
                self.locks.locks = locks;
                self.locks.loading = false;
                Action::None
            }
            Event::MetricsLoaded { result, .. } => {
                match result {
                    Ok(raw) => self.metrics_view.set_raw(&raw),
                    Err(e) => {
                        self.metrics_view.loading = false;
                        self.metrics_view.error = Some(e);
                    }
                }
                Action::None
            }
            Event::TraceEventArrived { event, .. } => {
                self.events_view.push(event);
                Action::None
            }
            Event::TraceStreamEnded { error, .. } => {
                self.events_view.streaming = false;
                self.events_view.error = error;
                Action::None
            }
            Event::ObjectStatFetched { path, result } => {
                self.apply_object_stat(path, result);
                Action::None
            }
            Event::ActionFailed { message } => {
                self.mode = Mode::Error(message);
                Action::None
            }
            Event::LabelsLoaded {
                alias,
                bucket,
                key,
                labels,
            } => {
                let entries: Vec<(String, String)> = labels.into_iter().collect();
                // Preserve the cursor position across refreshes when possible.
                let prev = match &self.mode {
                    Mode::Labels { selected, .. } => *selected,
                    _ => 0,
                };
                let selected = prev.min(entries.len().saturating_sub(1));
                self.mode = Mode::Labels {
                    alias,
                    bucket,
                    key,
                    labels: entries,
                    selected,
                };
                Action::None
            }
            Event::BucketConfigLoaded {
                alias,
                bucket,
                quota_bytes,
                default_sse,
            } => {
                let selected = match &self.mode {
                    Mode::BucketConfig { selected, .. } => *selected,
                    _ => 0,
                };
                self.mode = Mode::BucketConfig {
                    alias,
                    bucket,
                    quota_bytes,
                    default_sse,
                    selected,
                };
                Action::None
            }
            Event::ResultsLoaded { title, lines } => {
                self.mode = Mode::Results {
                    title,
                    lines,
                    selected: 0,
                };
                Action::None
            }
            _ => Action::None,
        }
    }

    fn apply_transfer_update(&mut self, id: u64, bytes_done: u64, speed_bps: u64) {
        if let Some(entry) = self.transfers.iter_mut().find(|e| e.id == id) {
            entry.bytes_done = bytes_done;
            if entry.speed_samples.len() >= 60 {
                entry.speed_samples.pop_front();
            }
            entry.speed_samples.push_back(speed_bps);
            if entry.started_at.is_none() {
                entry.started_at = Some(Instant::now());
            }
            entry.status = TransferStatus::Running;
        }
    }

    fn apply_transfer_done(&mut self, id: u64, result: Result<u64, String>) {
        if let Some(entry) = self.transfers.iter_mut().find(|e| e.id == id) {
            entry.status = match result {
                Ok(n) => {
                    let elapsed = entry.started_at.map(|t| t.elapsed()).unwrap_or_default();
                    let avg_bps = if elapsed.as_secs_f64() > 0.0 {
                        (n as f64 / elapsed.as_secs_f64()) as u64
                    } else {
                        entry.speed_samples.back().copied().unwrap_or(0)
                    };
                    entry.bytes_done = n;
                    TransferStatus::Done {
                        bytes: n,
                        elapsed,
                        avg_bps,
                    }
                }
                Err(e) => TransferStatus::Failed(e),
            };
        }
    }

    fn apply_remote_fetched(
        &mut self,
        alias: String,
        path: RemoteFetchPath,
        result: RemoteFetchResult,
    ) {
        self.remote_throbber.stop();
        match result {
            RemoteFetchResult::Error(e) => {
                self.mode = Mode::Error(e);
            }
            RemoteFetchResult::Buckets(buckets) => {
                self.remote.set_buckets(&alias, buckets);
            }
            RemoteFetchResult::Objects(items, _next) => {
                if let RemoteFetchPath::Objects { bucket, .. } = path {
                    self.remote.set_objects(&alias, &bucket, items);
                }
            }
        }
    }

    fn apply_object_stat(&mut self, path: String, result: Result<y2q_client::ObjectHead, String>) {
        match result {
            Ok(head) => {
                let mut lines = vec![
                    format!("Path:     {path}"),
                    format!("Size:     {}", fmt_bytes(head.size)),
                    format!("Created:  {}", fmt_ns(head.created)),
                    format!("Modified: {}", fmt_ns(head.modified)),
                    format!("GxHash:   {}", head.checksum_gxhash),
                ];
                for (k, v) in &head.labels {
                    lines.push(format!("Label     {k}: {v}"));
                }
                if let Some(ref alg) = head.kem_alg {
                    lines.push(format!("KEM:      {alg}"));
                }
                if let Some(ref alg) = head.aead_alg {
                    lines.push(format!("AEAD:     {alg}"));
                }
                if let Some(sz) = head.cipher_size {
                    lines.push(format!("Envelope: {} on disk", fmt_bytes(sz)));
                }
                self.mode = Mode::ObjectStat { path, lines };
            }
            Err(e) => {
                self.mode = Mode::Error(e);
            }
        }
    }

    fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> Action {
        match self.mode.clone() {
            Mode::Input { value, action, .. } => self.handle_input_key(key, value, action),
            Mode::Confirm(action) => self.handle_confirm_key(key, action),
            // Any key dismisses an error or stat popup back to Browse.
            Mode::Error(_) | Mode::ObjectStat { .. } => {
                self.mode = Mode::Browse;
                Action::None
            }
            Mode::Admin(tab) => self.handle_admin_key(key, tab),
            Mode::Labels { .. } => self.handle_labels_key(key),
            Mode::BucketConfig { .. } => self.handle_bucketconfig_key(key),
            Mode::Results { .. } => self.handle_results_key(key),
            Mode::Browse => self.handle_browse_key(key),
        }
    }

    fn handle_input_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        value: String,
        action: InputAction,
    ) -> Action {
        use crossterm::event::KeyCode;
        match key.code {
            KeyCode::Esc => {
                self.mode = match action {
                    InputAction::AddUserUsername { .. } | InputAction::AddUserPassword { .. } => {
                        Mode::Admin(AdminTab::Users)
                    }
                    _ => Mode::Browse,
                };
                Action::None
            }
            KeyCode::Enter => {
                self.mode = Mode::Browse;
                self.handle_input_submit(value, action);
                Action::Enter
            }
            KeyCode::Backspace => {
                if let Mode::Input { ref mut value, .. } = self.mode {
                    value.pop();
                }
                Action::None
            }
            KeyCode::Char(c) => {
                if let Mode::Input { ref mut value, .. } = self.mode {
                    value.push(c);
                }
                Action::None
            }
            _ => Action::None,
        }
    }

    fn handle_confirm_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        action: ConfirmAction,
    ) -> Action {
        use crossterm::event::KeyCode;
        let mode_after = match action {
            ConfirmAction::DeleteUser { .. } => Mode::Admin(AdminTab::Users),
            ConfirmAction::ClearLocks { .. } => Mode::Admin(AdminTab::Locks),
            _ => Mode::Browse,
        };
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                self.execute_confirm(action);
                self.mode = mode_after;
                Action::ConfirmYes
            }
            _ => {
                self.mode = mode_after;
                Action::ConfirmNo
            }
        }
    }

    fn handle_admin_key(&mut self, key: crossterm::event::KeyEvent, tab: AdminTab) -> Action {
        use crossterm::event::KeyCode;
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                self.mode = Mode::Browse;
                Action::None
            }
            KeyCode::Tab => {
                let next = tab.next();
                self.enter_admin_tab(&next);
                self.mode = Mode::Admin(next);
                Action::NextTab
            }
            KeyCode::BackTab => {
                let prev = tab.prev();
                self.enter_admin_tab(&prev);
                self.mode = Mode::Admin(prev);
                Action::PrevTab
            }
            KeyCode::Char('r') => {
                match tab {
                    AdminTab::Metrics => self.fetch_metrics(),
                    AdminTab::Users => self.fetch_users(),
                    AdminTab::Locks => self.fetch_locks(),
                    AdminTab::Rebuild => self.fetch_rebuild_status(),
                    AdminTab::Events => {}
                }
                Action::Refresh
            }
            KeyCode::Char('s') => {
                if matches!(tab, AdminTab::Rebuild) {
                    self.start_rebuild();
                }
                Action::None
            }
            KeyCode::Char('c') => {
                if matches!(tab, AdminTab::Locks) {
                    let alias = self.active_alias.clone().unwrap_or_default();
                    self.mode = Mode::Confirm(ConfirmAction::ClearLocks {
                        alias,
                        older_than: "5m".into(),
                    });
                }
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                match tab {
                    AdminTab::Locks => self.locks.nav_up(),
                    AdminTab::Users => self.users_view.nav_up(),
                    AdminTab::Metrics => self.metrics_view.nav_up(),
                    _ => {}
                }
                Action::NavigateUp
            }
            KeyCode::Down | KeyCode::Char('j') => {
                match tab {
                    AdminTab::Locks => self.locks.nav_down(),
                    AdminTab::Users => self.users_view.nav_down(),
                    AdminTab::Metrics => self.metrics_view.nav_down(),
                    _ => {}
                }
                Action::NavigateDown
            }
            KeyCode::Char('n') => {
                if matches!(tab, AdminTab::Users) {
                    let alias = self.active_alias.clone().unwrap_or_default();
                    self.mode = Mode::Input {
                        prompt: "New username:".into(),
                        value: String::new(),
                        action: InputAction::AddUserUsername { alias },
                    };
                }
                Action::None
            }
            KeyCode::Char('d') => {
                if matches!(tab, AdminTab::Users)
                    && let Some(user) = self.users_view.users.get(self.users_view.selected).cloned()
                {
                    let alias = self.active_alias.clone().unwrap_or_default();
                    self.mode = Mode::Confirm(ConfirmAction::DeleteUser {
                        alias,
                        username: user.username,
                    });
                }
                Action::Delete
            }
            _ => Action::None,
        }
    }

    fn handle_browse_key(&mut self, key: crossterm::event::KeyEvent) -> Action {
        use crossterm::event::KeyCode;
        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
                Action::Quit
            }
            KeyCode::Tab => {
                self.focused = self.focused.toggle();
                Action::SwitchPane
            }
            KeyCode::Char('a') => {
                self.mode = Mode::Admin(AdminTab::default());
                self.fetch_rebuild_status();
                self.fetch_users();
                self.fetch_locks();
                Action::ToggleAdmin
            }
            KeyCode::Char('t') => {
                self.transfer_bar_visible = !self.transfer_bar_visible;
                Action::ToggleTransferBar
            }
            KeyCode::Up | KeyCode::Char('k') => {
                match self.focused {
                    FocusedPane::Local => self.local.nav_up(),
                    FocusedPane::Remote => self.remote.nav_up(),
                }
                Action::NavigateUp
            }
            KeyCode::Down | KeyCode::Char('j') => {
                match self.focused {
                    FocusedPane::Local => self.local.nav_down(20),
                    FocusedPane::Remote => self.remote.nav_down(20),
                }
                Action::NavigateDown
            }
            KeyCode::Enter => {
                self.handle_enter();
                Action::Enter
            }
            KeyCode::Backspace | KeyCode::Char('b') => {
                match self.focused {
                    FocusedPane::Local => {
                        self.local.enter();
                    }
                    FocusedPane::Remote => self.remote.go_back(),
                }
                Action::Back
            }
            KeyCode::Char('n') => {
                self.start_create_bucket();
                Action::None
            }
            KeyCode::Char('c') => {
                self.start_copy();
                Action::Copy
            }
            KeyCode::Char('d') => {
                self.request_delete();
                Action::Delete
            }
            KeyCode::Char('m') => {
                self.start_rename();
                Action::None
            }
            KeyCode::Char('l') => {
                self.open_labels();
                Action::None
            }
            KeyCode::Char('g') => {
                self.open_bucket_config();
                Action::None
            }
            KeyCode::Char('s') => {
                self.start_search();
                Action::None
            }
            KeyCode::Char('f') => {
                self.start_find();
                Action::None
            }
            KeyCode::Char('u') => {
                self.start_du();
                Action::None
            }
            KeyCode::Char('T') => {
                self.start_tree();
                Action::None
            }
            KeyCode::Char('D') => {
                self.start_diff();
                Action::None
            }
            KeyCode::Char('M') => {
                self.start_mirror_preview();
                Action::None
            }
            KeyCode::Char('L') => {
                self.start_login();
                Action::None
            }
            KeyCode::Char('r') => {
                self.trigger_refresh();
                Action::Refresh
            }
            _ => Action::None,
        }
    }

    fn handle_enter(&mut self) {
        match self.focused {
            FocusedPane::Local => self.local.enter(),
            FocusedPane::Remote => {
                if let Some(entry) = self.remote.selected_entry().cloned() {
                    use super::pane::remote::{RemoteEntry, RemoteLevel};
                    match entry {
                        RemoteEntry::Back => self.remote.go_back(),
                        RemoteEntry::Alias(alias) => {
                            self.active_alias = Some(alias.clone());
                            self.remote_throbber.start();
                            self.fetch_buckets(alias);
                        }
                        RemoteEntry::Bucket(bucket) => {
                            if let RemoteLevel::Buckets { ref alias } = self.remote.level.clone() {
                                let alias = alias.clone();
                                self.remote_throbber.start();
                                self.fetch_objects(alias, bucket, None);
                            }
                        }
                        RemoteEntry::Dir(_) => {}
                        RemoteEntry::Object(m) => {
                            if let RemoteLevel::Objects {
                                ref alias,
                                ref bucket,
                                ..
                            } = self.remote.level.clone()
                            {
                                let path = format!("{alias}/{bucket}/{}", m.key);
                                self.fetch_object_stat(
                                    alias.clone(),
                                    bucket.clone(),
                                    m.key.clone(),
                                    path,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    fn fetch_buckets(&self, alias: String) {
        let tx = self.event_tx.clone();
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        tokio::spawn(async move {
            let result = async {
                let profile = config
                    .aliases
                    .get(&alias)
                    .ok_or_else(|| format!("unknown alias `{alias}`"))?;
                let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                let token = store
                    .token_for(&alias)
                    .ok_or_else(|| "not authenticated".to_string())?;
                let client = client_from_alias(profile, Some(token)).map_err(|e| e.to_string())?;
                client.list_buckets().await.map_err(|e| e.to_string())
            }
            .await;
            let payload = match result {
                Ok(buckets) => RemoteFetchResult::Buckets(buckets),
                Err(e) => RemoteFetchResult::Error(e),
            };
            let _ = tx.send(Event::RemoteFetched {
                alias,
                path: RemoteFetchPath::Buckets,
                result: payload,
            });
        });
    }

    fn fetch_objects(&self, alias: String, bucket: String, prefix: Option<String>) {
        let tx = self.event_tx.clone();
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        let bucket_clone = bucket.clone();
        tokio::spawn(async move {
            let result = async {
                let profile = config
                    .aliases
                    .get(&alias)
                    .ok_or_else(|| format!("unknown alias `{alias}`"))?;
                let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                let token = store
                    .token_for(&alias)
                    .ok_or_else(|| "not authenticated".to_string())?;
                let client = client_from_alias(profile, Some(token)).map_err(|e| e.to_string())?;
                let opts = ListOptions {
                    prefix: prefix.clone(),
                    after: None,
                    limit: Some(500),
                };
                client
                    .list_objects(&bucket, &opts)
                    .await
                    .map_err(|e| e.to_string())
            }
            .await;
            let fetch_path = RemoteFetchPath::Objects {
                bucket: bucket_clone,
                prefix,
            };
            let payload = match result {
                Ok(page) => RemoteFetchResult::Objects(page.items, page.next),
                Err(e) => RemoteFetchResult::Error(e),
            };
            let _ = tx.send(Event::RemoteFetched {
                alias,
                path: fetch_path,
                result: payload,
            });
        });
    }

    fn start_copy(&mut self) {
        // Copy from focused pane to other pane
        use super::pane::remote::{RemoteEntry, RemoteLevel};
        match self.focused {
            FocusedPane::Local => {
                // local → remote
                let local_path = match self.local.selected_path() {
                    Some(p) if !p.ends_with("..") => p,
                    _ => return,
                };
                if let RemoteLevel::Objects {
                    ref alias,
                    ref bucket,
                    ..
                } = self.remote.level.clone()
                {
                    let alias = alias.clone();
                    let bucket = bucket.clone();
                    let key = local_path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let id = TRANSFER_ID.fetch_add(1, Ordering::Relaxed);
                    let label = format!("{} → {alias}/{bucket}/{key}", local_path.display());
                    let size = std::fs::metadata(&local_path).ok().map(|m| m.len());
                    self.push_transfer(TransferEntry::new(id, label, size));
                    let tx = self.event_tx.clone();
                    let config = self.config.clone();
                    let tokens_path = default_tokens_path().unwrap_or_default();
                    tokio::spawn(async move {
                        let result = async {
                            let profile = config
                                .aliases
                                .get(&alias)
                                .ok_or_else(|| "unknown alias".to_string())?;
                            let store =
                                TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                            let token = store
                                .token_for(&alias)
                                .ok_or_else(|| "unauthenticated".to_string())?;
                            let client = client_from_alias(profile, Some(token))
                                .map_err(|e| e.to_string())?;
                            let file = tokio::fs::File::open(&local_path)
                                .await
                                .map_err(|e| e.to_string())?;
                            let meta = file.metadata().await.map_err(|e| e.to_string())?;
                            let len = meta.len();
                            let reporter = Box::new(TuiTransferReporter { id, tx: tx.clone() });
                            let reader = CountingReader::new(file, reporter);
                            client
                                .put_from_reader(
                                    &bucket,
                                    &key,
                                    reader,
                                    Some(len),
                                    &Default::default(),
                                    None,
                                )
                                .await
                                .map_err(|e| e.to_string())?;
                            Ok::<u64, String>(len)
                        }
                        .await;
                        let _ = tx.send(Event::TransferDone { id, result });
                    });
                }
            }
            FocusedPane::Remote => {
                // remote → local
                if let Some(RemoteEntry::Object(m)) = self.remote.selected_entry().cloned() {
                    let alias = self.active_alias.clone().unwrap_or_default();
                    let bucket = m.bucket.clone();
                    let key = m.key.clone();
                    let local_dst = self.local.cwd.join(key.rsplit('/').next().unwrap_or(&key));
                    let id = TRANSFER_ID.fetch_add(1, Ordering::Relaxed);
                    let label = format!("{alias}/{bucket}/{key} → {}", local_dst.display());
                    let size = Some(m.size);
                    self.push_transfer(TransferEntry::new(id, label, size));
                    let tx = self.event_tx.clone();
                    let config = self.config.clone();
                    let tokens_path = default_tokens_path().unwrap_or_default();
                    tokio::spawn(async move {
                        let result = async {
                            let profile = config
                                .aliases
                                .get(&alias)
                                .ok_or_else(|| "unknown alias".to_string())?;
                            let store =
                                TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                            let token = store
                                .token_for(&alias)
                                .ok_or_else(|| "unauthenticated".to_string())?;
                            let client = client_from_alias(profile, Some(token))
                                .map_err(|e| e.to_string())?;
                            let file = tokio::fs::File::create(&local_dst)
                                .await
                                .map_err(|e| e.to_string())?;
                            let reporter = Box::new(TuiTransferReporter { id, tx: tx.clone() });
                            let mut writer = CountingWriter::new(file, reporter);
                            let n = client
                                .get_to_writer(&bucket, &key, &mut writer)
                                .await
                                .map_err(|e| e.to_string())?;
                            Ok::<u64, String>(n)
                        }
                        .await;
                        let _ = tx.send(Event::TransferDone { id, result });
                    });
                }
            }
        }
    }

    fn request_delete(&mut self) {
        use super::pane::remote::{RemoteEntry, RemoteLevel};
        if self.focused != FocusedPane::Remote {
            return;
        }
        match self.remote.selected_entry().cloned() {
            Some(RemoteEntry::Object(m)) => {
                let alias = self.active_alias.clone().unwrap_or_default();
                self.mode = Mode::Confirm(ConfirmAction::DeleteRemote {
                    alias,
                    bucket: m.bucket.clone(),
                    key: m.key.clone(),
                });
            }
            Some(RemoteEntry::Bucket(bucket)) => {
                if let RemoteLevel::Buckets { ref alias } = self.remote.level.clone() {
                    self.mode = Mode::Confirm(ConfirmAction::DeleteBucket {
                        alias: alias.clone(),
                        bucket,
                    });
                }
            }
            _ => {}
        }
    }

    fn start_rename(&mut self) {
        use super::pane::remote::RemoteEntry;
        if let FocusedPane::Remote = self.focused
            && let Some(RemoteEntry::Object(m)) = self.remote.selected_entry().cloned()
        {
            let alias = self.active_alias.clone().unwrap_or_default();
            self.mode = Mode::Input {
                prompt: format!("Rename {} to:", m.key),
                value: m.key.clone(),
                action: InputAction::RenameObject {
                    alias,
                    bucket: m.bucket.clone(),
                    key: m.key.clone(),
                },
            };
        }
    }

    fn start_login(&mut self) {
        use super::pane::remote::{RemoteEntry, RemoteLevel};
        // Determine which alias to authenticate: the selected alias entry, or
        // the currently open one.
        let alias = match self.remote.level.clone() {
            RemoteLevel::Aliases => match self.remote.selected_entry().cloned() {
                Some(RemoteEntry::Alias(a)) => Some(a),
                _ => None,
            },
            _ => self.active_alias.clone(),
        };
        let Some(alias) = alias else {
            return;
        };
        let default_user = self
            .config
            .aliases
            .get(&alias)
            .map(|a| a.username.clone())
            .unwrap_or_default();
        self.mode = Mode::Input {
            prompt: format!("Username for `{alias}`:"),
            value: default_user,
            action: InputAction::LoginUsername { alias },
        };
    }

    // ── Labels (Phase 2) ────────────────────────────────────────────────────

    fn open_labels(&mut self) {
        use super::pane::remote::RemoteEntry;
        if self.focused != FocusedPane::Remote {
            return;
        }
        if let Some(RemoteEntry::Object(m)) = self.remote.selected_entry().cloned() {
            let alias = self.active_alias.clone().unwrap_or_default();
            self.fetch_labels(alias, m.bucket.clone(), m.key.clone());
        }
    }

    fn fetch_labels(&mut self, alias: String, bucket: String, key: String) {
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        let tx = self.event_tx.clone();
        tokio::spawn(async move {
            let result = async {
                let client = build_client(&config, &tokens_path, &alias)?;
                crate::ops::objects::head(&client, &bucket, &key)
                    .await
                    .map_err(|e| e.to_string())
            }
            .await;
            match result {
                Ok(head) => {
                    let _ = tx.send(Event::LabelsLoaded {
                        alias,
                        bucket,
                        key,
                        labels: head.labels,
                    });
                }
                Err(message) => {
                    let _ = tx.send(Event::ActionFailed { message });
                }
            }
        });
    }

    fn spawn_label_mutation(
        &mut self,
        alias: String,
        bucket: String,
        key: String,
        op: &'static str,
        labels: BTreeMap<String, String>,
    ) {
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        let tx = self.event_tx.clone();
        tokio::spawn(async move {
            let result = async {
                let client = build_client(&config, &tokens_path, &alias)?;
                crate::ops::objects::set_labels(&client, &bucket, &key, op, &labels)
                    .await
                    .map_err(|e| e.to_string())
            }
            .await;
            match result {
                Ok(updated) => {
                    let _ = tx.send(Event::LabelsLoaded {
                        alias,
                        bucket,
                        key,
                        labels: updated,
                    });
                }
                Err(message) => {
                    let _ = tx.send(Event::ActionFailed { message });
                }
            }
        });
    }

    fn handle_labels_key(&mut self, key: crossterm::event::KeyEvent) -> Action {
        use crossterm::event::KeyCode;
        let (alias, bucket, okey, labels, selected) = match &self.mode {
            Mode::Labels {
                alias,
                bucket,
                key,
                labels,
                selected,
            } => (
                alias.clone(),
                bucket.clone(),
                key.clone(),
                labels.clone(),
                *selected,
            ),
            _ => return Action::None,
        };
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.mode = Mode::Browse,
            KeyCode::Up | KeyCode::Char('k') => {
                if selected > 0
                    && let Mode::Labels { selected, .. } = &mut self.mode
                {
                    *selected -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if selected + 1 < labels.len()
                    && let Mode::Labels { selected, .. } = &mut self.mode
                {
                    *selected += 1;
                }
            }
            KeyCode::Char('a') => {
                self.mode = Mode::Input {
                    prompt: "Add label (key=value):".into(),
                    value: String::new(),
                    action: InputAction::SetLabel {
                        alias,
                        bucket,
                        key: okey,
                    },
                };
            }
            KeyCode::Char('d') => {
                if let Some((k, _)) = labels.get(selected).cloned() {
                    let mut map = BTreeMap::new();
                    map.insert(k, String::new());
                    self.spawn_label_mutation(alias, bucket, okey, "remove", map);
                }
            }
            _ => {}
        }
        Action::None
    }

    // ── Bucket config (Phase 2) ─────────────────────────────────────────────

    fn open_bucket_config(&mut self) {
        use super::pane::remote::{RemoteEntry, RemoteLevel};
        if self.focused != FocusedPane::Remote {
            return;
        }
        if let (Some(RemoteEntry::Bucket(bucket)), RemoteLevel::Buckets { alias }) = (
            self.remote.selected_entry().cloned(),
            self.remote.level.clone(),
        ) {
            self.fetch_bucket_config(alias, bucket);
        }
    }

    fn fetch_bucket_config(&mut self, alias: String, bucket: String) {
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        let tx = self.event_tx.clone();
        tokio::spawn(async move {
            let result = async {
                let client = build_client(&config, &tokens_path, &alias)?;
                crate::ops::buckets::get_config(&client, &bucket)
                    .await
                    .map_err(|e| e.to_string())
            }
            .await;
            match result {
                Ok(cfg) => {
                    let _ = tx.send(Event::BucketConfigLoaded {
                        alias,
                        bucket,
                        quota_bytes: cfg.quota_bytes,
                        default_sse: cfg.default_sse,
                    });
                }
                Err(message) => {
                    let _ = tx.send(Event::ActionFailed { message });
                }
            }
        });
    }

    /// Read-modify-write a bucket's config. `set_quota`/`set_sse` of `Some(v)`
    /// assign that value (where `v` may itself be `None` to clear); `None` leaves
    /// the field unchanged.
    fn spawn_set_bucket_config(
        &mut self,
        alias: String,
        bucket: String,
        set_quota: Option<Option<u64>>,
        set_sse: Option<Option<String>>,
    ) {
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        let tx = self.event_tx.clone();
        tokio::spawn(async move {
            let result = async {
                let client = build_client(&config, &tokens_path, &alias)?;
                let mut cfg = crate::ops::buckets::get_config(&client, &bucket)
                    .await
                    .map_err(|e| e.to_string())?;
                if let Some(q) = set_quota {
                    cfg.quota_bytes = q;
                }
                if let Some(s) = set_sse {
                    cfg.default_sse = s;
                }
                crate::ops::buckets::set_config(&client, &bucket, &cfg)
                    .await
                    .map_err(|e| e.to_string())
            }
            .await;
            match result {
                Ok(cfg) => {
                    let _ = tx.send(Event::BucketConfigLoaded {
                        alias,
                        bucket,
                        quota_bytes: cfg.quota_bytes,
                        default_sse: cfg.default_sse,
                    });
                }
                Err(message) => {
                    let _ = tx.send(Event::ActionFailed { message });
                }
            }
        });
    }

    fn handle_bucketconfig_key(&mut self, key: crossterm::event::KeyEvent) -> Action {
        use crossterm::event::KeyCode;
        let (alias, bucket, selected) = match &self.mode {
            Mode::BucketConfig {
                alias,
                bucket,
                selected,
                ..
            } => (alias.clone(), bucket.clone(), *selected),
            _ => return Action::None,
        };
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.mode = Mode::Browse,
            KeyCode::Up | KeyCode::Char('k') => {
                if let Mode::BucketConfig { selected, .. } = &mut self.mode {
                    *selected = selected.saturating_sub(1);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Mode::BucketConfig { selected, .. } = &mut self.mode {
                    *selected = (*selected + 1).min(1);
                }
            }
            KeyCode::Enter => {
                let (prompt, action) = if selected == 0 {
                    (
                        "Set quota (e.g. 500m, 2g):".to_string(),
                        InputAction::SetQuota { alias, bucket },
                    )
                } else {
                    (
                        "Set default SSE algorithm:".to_string(),
                        InputAction::SetSse { alias, bucket },
                    )
                };
                self.mode = Mode::Input {
                    prompt,
                    value: String::new(),
                    action,
                };
            }
            KeyCode::Char('d') => {
                if selected == 0 {
                    self.spawn_set_bucket_config(alias, bucket, Some(None), None);
                } else {
                    self.spawn_set_bucket_config(alias, bucket, None, Some(None));
                }
            }
            _ => {}
        }
        Action::None
    }

    // ── Query views: search / find (Phase 3) ────────────────────────────────

    /// The current remote scope as `(alias, bucket, prefix)`, if resolvable.
    fn remote_scope(&self) -> Option<(String, Option<String>, Option<String>)> {
        use super::pane::remote::RemoteLevel;
        match self.remote.level.clone() {
            RemoteLevel::Aliases => self.active_alias.clone().map(|a| (a, None, None)),
            RemoteLevel::Buckets { alias } => Some((alias, None, None)),
            RemoteLevel::Objects {
                alias,
                bucket,
                prefix,
            } => Some((alias, Some(bucket), prefix)),
        }
    }

    fn start_search(&mut self) {
        let Some((alias, bucket, prefix)) = self.remote_scope() else {
            return;
        };
        self.mode = Mode::Input {
            prompt: "Label query (e.g. env == prod):".into(),
            value: String::new(),
            action: InputAction::SearchQuery {
                alias,
                bucket,
                prefix,
            },
        };
    }

    fn start_find(&mut self) {
        use super::pane::remote::RemoteLevel;
        if let RemoteLevel::Objects {
            alias,
            bucket,
            prefix,
        } = self.remote.level.clone()
        {
            self.mode = Mode::Input {
                prompt: "Find name glob (e.g. *.log):".into(),
                value: "*".into(),
                action: InputAction::FindName {
                    alias,
                    bucket,
                    prefix,
                },
            };
        }
    }

    fn spawn_search(
        &mut self,
        alias: String,
        bucket: Option<String>,
        prefix: Option<String>,
        query: String,
    ) {
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        let tx = self.event_tx.clone();
        tokio::spawn(async move {
            let result = async {
                let client = build_client(&config, &tokens_path, &alias)?;
                crate::ops::listing::search(&client, bucket, prefix, &query)
                    .await
                    .map_err(|e| e.to_string())
            }
            .await;
            match result {
                Ok(hits) => {
                    let lines = hits
                        .iter()
                        .map(|m| {
                            format!(
                                "{alias}/{}/{}  {}  {}",
                                m.bucket,
                                m.key,
                                fmt_bytes(m.size),
                                fmt_ns(m.modified)
                            )
                        })
                        .collect();
                    let _ = tx.send(Event::ResultsLoaded {
                        title: format!("Search: {query} ({} hit(s))", hits.len()),
                        lines,
                    });
                }
                Err(message) => {
                    let _ = tx.send(Event::ActionFailed { message });
                }
            }
        });
    }

    fn spawn_find(&mut self, alias: String, bucket: String, prefix: Option<String>, name: String) {
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        let tx = self.event_tx.clone();
        tokio::spawn(async move {
            let result = async {
                let filter = crate::ops::listing::FindFilter::build(Some(&name), None, None, None)?;
                let client = build_client(&config, &tokens_path, &alias)?;
                crate::ops::listing::find(&client, &bucket, prefix, &filter)
                    .await
                    .map_err(|e| e.to_string())
            }
            .await;
            match result {
                Ok(hits) => {
                    let lines = hits
                        .iter()
                        .map(|m| {
                            format!(
                                "{alias}/{bucket}/{}  {}  {}",
                                m.key,
                                fmt_bytes(m.size),
                                fmt_ns(m.modified)
                            )
                        })
                        .collect();
                    let _ = tx.send(Event::ResultsLoaded {
                        title: format!("Find {name} ({} match(es))", hits.len()),
                        lines,
                    });
                }
                Err(message) => {
                    let _ = tx.send(Event::ActionFailed { message });
                }
            }
        });
    }

    fn handle_results_key(&mut self, key: crossterm::event::KeyEvent) -> Action {
        use crossterm::event::KeyCode;
        let (len, selected) = match &self.mode {
            Mode::Results {
                lines, selected, ..
            } => (lines.len(), *selected),
            _ => return Action::None,
        };
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.mode = Mode::Browse,
            KeyCode::Up | KeyCode::Char('k') => {
                if selected > 0
                    && let Mode::Results { selected, .. } = &mut self.mode
                {
                    *selected -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if selected + 1 < len
                    && let Mode::Results { selected, .. } = &mut self.mode
                {
                    *selected += 1;
                }
            }
            _ => {}
        }
        Action::None
    }

    fn start_du(&mut self) {
        let Some((alias, bucket, prefix)) = self.remote_scope() else {
            return;
        };
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        let tx = self.event_tx.clone();
        self.remote_throbber.start();
        tokio::spawn(async move {
            let result = async {
                let client = build_client(&config, &tokens_path, &alias)?;
                match &bucket {
                    Some(b) => {
                        let (total, count, groups) =
                            crate::ops::listing::du(&client, b, prefix.as_deref(), 1)
                                .await
                                .map_err(|e| e.to_string())?;
                        let mut lines: Vec<String> = groups
                            .iter()
                            .map(|(g, (bytes, c))| {
                                format!("{:>10}  {:>6}  {b}/{g}", fmt_bytes(*bytes), c)
                            })
                            .collect();
                        lines.push(format!("{:>10}  {:>6}  TOTAL", fmt_bytes(total), count));
                        Ok::<_, String>((format!("du {alias}/{b}"), lines))
                    }
                    None => {
                        let summary = crate::ops::listing::du_buckets(&client)
                            .await
                            .map_err(|e| e.to_string())?;
                        let lines = summary
                            .iter()
                            .map(|(b, bytes, c)| {
                                format!("{:>10}  {:>6}  {b}/", fmt_bytes(*bytes), c)
                            })
                            .collect();
                        Ok((format!("du {alias}"), lines))
                    }
                }
            }
            .await;
            match result {
                Ok((title, lines)) => {
                    let _ = tx.send(Event::ResultsLoaded { title, lines });
                }
                Err(message) => {
                    let _ = tx.send(Event::ActionFailed { message });
                }
            }
        });
    }

    fn start_tree(&mut self) {
        use super::pane::remote::RemoteLevel;
        let RemoteLevel::Objects {
            alias,
            bucket,
            prefix,
        } = self.remote.level.clone()
        else {
            return;
        };
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        let tx = self.event_tx.clone();
        self.remote_throbber.start();
        tokio::spawn(async move {
            let result = async {
                let client = build_client(&config, &tokens_path, &alias)?;
                crate::ops::listing::build_tree(&client, &bucket, prefix.as_deref())
                    .await
                    .map_err(|e| e.to_string())
            }
            .await;
            match result {
                Ok(root) => {
                    let _ = tx.send(Event::ResultsLoaded {
                        title: format!("tree {alias}/{bucket}"),
                        lines: root.render_lines(false, 0),
                    });
                }
                Err(message) => {
                    let _ = tx.send(Event::ActionFailed { message });
                }
            }
        });
    }

    /// Diff the local working directory against the current remote prefix.
    fn start_diff(&mut self) {
        use super::pane::remote::RemoteLevel;
        let RemoteLevel::Objects {
            alias,
            bucket,
            prefix,
        } = self.remote.level.clone()
        else {
            return;
        };
        let local = self.local.cwd.clone();
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        let tx = self.event_tx.clone();
        self.remote_throbber.start();
        tokio::spawn(async move {
            let result = async {
                let local_entries = crate::ops::listing::collect_local_entries(&local)?;
                let client = build_client(&config, &tokens_path, &alias)?;
                let remote_entries = crate::ops::listing::collect_remote_entries(
                    &client,
                    &bucket,
                    prefix.as_deref(),
                )
                .await
                .map_err(|e| e.to_string())?;
                Ok::<_, String>(crate::ops::listing::diff_entries(
                    &local_entries,
                    &remote_entries,
                ))
            }
            .await;
            match result {
                Ok(rows) => {
                    let lines = rows
                        .iter()
                        .map(|r| {
                            let s = r.src_size.map(fmt_bytes).unwrap_or_else(|| "-".into());
                            let d = r.dst_size.map(fmt_bytes).unwrap_or_else(|| "-".into());
                            format!("{:1}  {:>10}  {:>10}  {}", r.op, s, d, r.key)
                        })
                        .collect();
                    let _ = tx.send(Event::ResultsLoaded {
                        title: format!("diff {} <-> {alias}/{bucket}", local.display()),
                        lines,
                    });
                }
                Err(message) => {
                    let _ = tx.send(Event::ActionFailed { message });
                }
            }
        });
    }

    /// Preview a one-way mirror of the local working directory onto the current
    /// remote prefix. Read-only: shows the plan, does not execute (use the CLI
    /// `mirror` to apply).
    fn start_mirror_preview(&mut self) {
        use super::pane::remote::RemoteLevel;
        let RemoteLevel::Objects {
            alias,
            bucket,
            prefix,
        } = self.remote.level.clone()
        else {
            return;
        };
        let local = self.local.cwd.clone();
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        let tx = self.event_tx.clone();
        self.remote_throbber.start();
        tokio::spawn(async move {
            let result = async {
                let src = crate::ops::listing::collect_local_entries(&local)?;
                let client = build_client(&config, &tokens_path, &alias)?;
                let dst = crate::ops::listing::collect_remote_entries(
                    &client,
                    &bucket,
                    prefix.as_deref(),
                )
                .await
                .map_err(|e| e.to_string())?;
                Ok::<_, String>(crate::ops::listing::mirror_plan(&src, &dst, false))
            }
            .await;
            match result {
                Ok(plan) => {
                    let mut lines: Vec<String> = plan
                        .actions
                        .iter()
                        .map(|(key, action)| format!("{:<7} {key}", action.label()))
                        .collect();
                    for key in &plan.deletions {
                        lines.push(format!("{:<7} {key}", "delete?"));
                    }
                    lines.push(String::new());
                    lines.push(format!(
                        "{} to copy/update, {} dst-only (delete with --remove), {} unchanged",
                        plan.actions.len(),
                        plan.deletions.len(),
                        plan.skipped
                    ));
                    lines.push("Run `y2q mirror` from the CLI to apply.".into());
                    let _ = tx.send(Event::ResultsLoaded {
                        title: format!("mirror {} -> {alias}/{bucket} (preview)", local.display()),
                        lines,
                    });
                }
                Err(message) => {
                    let _ = tx.send(Event::ActionFailed { message });
                }
            }
        });
    }

    fn execute_confirm(&mut self, action: ConfirmAction) {
        match action {
            ConfirmAction::DeleteRemote { alias, bucket, key } => {
                let config = self.config.clone();
                let tokens_path = default_tokens_path().unwrap_or_default();
                let tx = self.event_tx.clone();
                let prefix = self.remote.objects_prefix();
                tokio::spawn(async move {
                    let result = async {
                        let client = build_client(&config, &tokens_path, &alias)?;
                        crate::ops::objects::delete(&client, &bucket, &key)
                            .await
                            .map_err(|e| e.to_string())?;
                        let page = client
                            .list_objects(
                                &bucket,
                                &ListOptions {
                                    prefix: prefix.clone(),
                                    after: None,
                                    limit: Some(500),
                                },
                            )
                            .await
                            .map_err(|e| e.to_string())?;
                        Ok::<_, String>((page.items, page.next))
                    }
                    .await;
                    match result {
                        Ok((items, next)) => {
                            let _ = tx.send(Event::RemoteFetched {
                                alias,
                                path: RemoteFetchPath::Objects { bucket, prefix },
                                result: RemoteFetchResult::Objects(items, next),
                            });
                        }
                        Err(message) => {
                            let _ = tx.send(Event::ActionFailed { message });
                        }
                    }
                });
            }
            ConfirmAction::DeleteBucket { alias, bucket } => {
                let config = self.config.clone();
                let tokens_path = default_tokens_path().unwrap_or_default();
                let tx = self.event_tx.clone();
                let alias_clone = alias.clone();
                tokio::spawn(async move {
                    let result = async {
                        let client = build_client(&config, &tokens_path, &alias_clone)?;
                        crate::ops::buckets::delete(&client, &bucket)
                            .await
                            .map_err(|e| e.to_string())?;
                        client.list_buckets().await.map_err(|e| e.to_string())
                    }
                    .await;
                    match result {
                        Ok(buckets) => {
                            let _ = tx.send(Event::RemoteFetched {
                                alias: alias_clone,
                                path: RemoteFetchPath::Buckets,
                                result: RemoteFetchResult::Buckets(buckets),
                            });
                        }
                        Err(message) => {
                            let _ = tx.send(Event::ActionFailed { message });
                        }
                    }
                });
            }
            ConfirmAction::ClearLocks { alias, older_than } => {
                let config = self.config.clone();
                let tokens_path = default_tokens_path().unwrap_or_default();
                let tx = self.event_tx.clone();
                let alias_clone = alias.clone();
                tokio::spawn(async move {
                    let result = async {
                        let client = build_client(&config, &tokens_path, &alias_clone)?;
                        crate::ops::admin::locks_clear(&client, &older_than)
                            .await
                            .map_err(|e| e.to_string())?;
                        crate::ops::admin::locks_list(&client, &older_than)
                            .await
                            .map_err(|e| e.to_string())
                    }
                    .await;
                    match result {
                        Ok(locks) => {
                            let _ = tx.send(Event::LocksLoaded {
                                alias: alias_clone,
                                locks,
                            });
                        }
                        Err(message) => {
                            let _ = tx.send(Event::ActionFailed { message });
                        }
                    }
                });
            }
            ConfirmAction::DeleteUser { alias, username } => {
                let config = self.config.clone();
                let tokens_path = default_tokens_path().unwrap_or_default();
                let tx = self.event_tx.clone();
                let alias_clone = alias.clone();
                tokio::spawn(async move {
                    let result = async {
                        let profile = config
                            .aliases
                            .get(&alias_clone)
                            .ok_or_else(|| "unknown alias".to_string())?;
                        let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                        let token = store
                            .token_for(&alias_clone)
                            .ok_or_else(|| "not authenticated".to_string())?;
                        let client =
                            client_from_alias(profile, Some(token)).map_err(|e| e.to_string())?;
                        client
                            .delete_user(&username)
                            .await
                            .map_err(|e| e.to_string())?;
                        client.list_users().await.map_err(|e| e.to_string())
                    }
                    .await;
                    if let Ok(users) = result {
                        let _ = tx.send(Event::UsersLoaded {
                            alias: alias_clone,
                            users,
                        });
                    }
                });
            }
        }
    }

    fn trigger_refresh(&mut self) {
        use super::pane::remote::RemoteLevel;
        match self.remote.level.clone() {
            RemoteLevel::Buckets { ref alias } => {
                let alias = alias.clone();
                self.remote_throbber.start();
                self.fetch_buckets(alias);
            }
            RemoteLevel::Objects {
                ref alias,
                ref bucket,
                ref prefix,
            } => {
                let alias = alias.clone();
                let bucket = bucket.clone();
                let prefix = prefix.clone();
                self.remote_throbber.start();
                self.fetch_objects(alias, bucket, prefix);
            }
            _ => {}
        }
    }

    fn fetch_object_stat(&self, alias: String, bucket: String, key: String, path: String) {
        let tx = self.event_tx.clone();
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        tokio::spawn(async move {
            let result = async {
                let profile = config
                    .aliases
                    .get(&alias)
                    .ok_or_else(|| format!("unknown alias `{alias}`"))?;
                let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                let token = store
                    .token_for(&alias)
                    .ok_or_else(|| "not authenticated".to_string())?;
                let client = client_from_alias(profile, Some(token)).map_err(|e| e.to_string())?;
                client.head(&bucket, &key).await.map_err(|e| e.to_string())
            }
            .await;
            let _ = tx.send(super::events::Event::ObjectStatFetched { path, result });
        });
    }

    pub fn fetch_users(&mut self) {
        let alias = match &self.active_alias {
            Some(a) => a.clone(),
            None => return,
        };
        self.users_view.loading = true;
        let tx = self.event_tx.clone();
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        tokio::spawn(async move {
            let result = async {
                let profile = config
                    .aliases
                    .get(&alias)
                    .ok_or_else(|| format!("unknown alias `{alias}`"))?;
                let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                let token = store
                    .token_for(&alias)
                    .ok_or_else(|| "not authenticated".to_string())?;
                let client = client_from_alias(profile, Some(token)).map_err(|e| e.to_string())?;
                client.list_users().await.map_err(|e| e.to_string())
            }
            .await;
            if let Ok(users) = result {
                let _ = tx.send(super::events::Event::UsersLoaded { alias, users });
            }
        });
    }

    pub fn fetch_locks(&mut self) {
        let alias = match &self.active_alias {
            Some(a) => a.clone(),
            None => return,
        };
        self.locks.loading = true;
        let tx = self.event_tx.clone();
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        tokio::spawn(async move {
            let result = async {
                let profile = config
                    .aliases
                    .get(&alias)
                    .ok_or_else(|| format!("unknown alias `{alias}`"))?;
                let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                let token = store
                    .token_for(&alias)
                    .ok_or_else(|| "not authenticated".to_string())?;
                let client = client_from_alias(profile, Some(token)).map_err(|e| e.to_string())?;
                client.locks_list("5m").await.map_err(|e| e.to_string())
            }
            .await;
            if let Ok(locks) = result {
                let _ = tx.send(super::events::Event::LocksLoaded { alias, locks });
            }
        });
    }

    /// Kick off the data load for the admin tab the user just switched to.
    fn enter_admin_tab(&mut self, tab: &AdminTab) {
        match tab {
            AdminTab::Users => self.fetch_users(),
            AdminTab::Locks => self.fetch_locks(),
            AdminTab::Metrics => self.fetch_metrics(),
            AdminTab::Events => self.start_trace_stream(),
            AdminTab::Rebuild => self.fetch_rebuild_status(),
        }
    }

    pub fn fetch_rebuild_status(&mut self) {
        let alias = match &self.active_alias {
            Some(a) => a.clone(),
            None => return,
        };
        let tx = self.event_tx.clone();
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        tokio::spawn(async move {
            let result = async {
                let client = build_client(&config, &tokens_path, &alias)?;
                crate::ops::admin::rebuild_status(&client)
                    .await
                    .map_err(|e| e.to_string())
            }
            .await;
            match result {
                Ok(status) => {
                    let _ = tx.send(Event::RebuildStatus {
                        alias,
                        state: status.state,
                        percent: status.percent,
                        reason: status.reason,
                    });
                }
                Err(message) => {
                    let _ = tx.send(Event::ActionFailed { message });
                }
            }
        });
    }

    fn start_rebuild(&mut self) {
        let alias = match &self.active_alias {
            Some(a) => a.clone(),
            None => return,
        };
        let tx = self.event_tx.clone();
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        tokio::spawn(async move {
            let result = async {
                let client = build_client(&config, &tokens_path, &alias)?;
                crate::ops::admin::rebuild_start(&client)
                    .await
                    .map_err(|e| e.to_string())?;
                crate::ops::admin::rebuild_status(&client)
                    .await
                    .map_err(|e| e.to_string())
            }
            .await;
            match result {
                Ok(status) => {
                    let _ = tx.send(Event::RebuildStatus {
                        alias,
                        state: status.state,
                        percent: status.percent,
                        reason: status.reason,
                    });
                }
                Err(message) => {
                    let _ = tx.send(Event::ActionFailed { message });
                }
            }
        });
    }

    pub fn fetch_metrics(&mut self) {
        let alias = match &self.active_alias {
            Some(a) => a.clone(),
            None => return,
        };
        self.metrics_view.loading = true;
        let tx = self.event_tx.clone();
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        tokio::spawn(async move {
            let result = async {
                let profile = config
                    .aliases
                    .get(&alias)
                    .ok_or_else(|| format!("unknown alias `{alias}`"))?;
                let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                let token = store
                    .token_for(&alias)
                    .ok_or_else(|| "not authenticated".to_string())?;
                let client = client_from_alias(profile, Some(token)).map_err(|e| e.to_string())?;
                crate::ops::admin::prometheus_metrics(&client)
                    .await
                    .map_err(|e| e.to_string())
            }
            .await;
            let _ = tx.send(super::events::Event::MetricsLoaded { alias, result });
        });
    }

    /// Start a long-lived trace SSE forwarder. Idempotent: does nothing if a
    /// stream is already running.
    pub fn start_trace_stream(&mut self) {
        if self.events_view.streaming {
            return;
        }
        let alias = match &self.active_alias {
            Some(a) => a.clone(),
            None => return,
        };
        self.events_view.streaming = true;
        self.events_view.error = None;
        let tx = self.event_tx.clone();
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        tokio::spawn(async move {
            // Build the client first and keep it alive: the trace stream borrows
            // it for its whole lifetime, so it must outlive the loop below.
            let client = match (|| {
                let profile = config
                    .aliases
                    .get(&alias)
                    .ok_or_else(|| format!("unknown alias `{alias}`"))?;
                let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                let token = store
                    .token_for(&alias)
                    .ok_or_else(|| "not authenticated".to_string())?;
                client_from_alias(profile, Some(token)).map_err(|e| e.to_string())
            })() {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx.send(super::events::Event::TraceStreamEnded {
                        alias,
                        error: Some(e),
                    });
                    return;
                }
            };

            match client.connect_trace().await {
                Ok(mut stream) => {
                    use futures::StreamExt;
                    while let Some(event) = stream.next().await {
                        if tx
                            .send(super::events::Event::TraceEventArrived {
                                alias: alias.clone(),
                                event,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                    let _ = tx.send(super::events::Event::TraceStreamEnded { alias, error: None });
                }
                Err(e) => {
                    let _ = tx.send(super::events::Event::TraceStreamEnded {
                        alias,
                        error: Some(e.to_string()),
                    });
                }
            }
        });
    }

    /// Authenticate against `alias`, persist the token, then refresh buckets.
    fn spawn_login(&mut self, alias: String, username: String, password: String) {
        let config = self.config.clone();
        let tokens_path = default_tokens_path().unwrap_or_default();
        let tx = self.event_tx.clone();
        let alias_clone = alias.clone();
        self.active_alias = Some(alias);
        self.remote_throbber.start();
        tokio::spawn(async move {
            let result = async {
                let profile = config
                    .aliases
                    .get(&alias_clone)
                    .ok_or_else(|| format!("unknown alias `{alias_clone}`"))?;
                let client = client_from_alias(profile, None).map_err(|e| e.to_string())?;
                let resp = crate::ops::auth::login(&client, &username, &password, None)
                    .await
                    .map_err(|e| e.to_string())?;
                let mut store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                store.set(
                    &alias_clone,
                    TokenEntry {
                        token: resp.token,
                        expires_at: resp.expires_at,
                        username: resp.username,
                    },
                );
                store.save(&tokens_path).map_err(|e| e.to_string())?;
                let authed = build_client(&config, &tokens_path, &alias_clone)?;
                authed.list_buckets().await.map_err(|e| e.to_string())
            }
            .await;
            match result {
                Ok(buckets) => {
                    let _ = tx.send(Event::RemoteFetched {
                        alias: alias_clone,
                        path: RemoteFetchPath::Buckets,
                        result: RemoteFetchResult::Buckets(buckets),
                    });
                }
                Err(message) => {
                    let _ = tx.send(Event::ActionFailed { message });
                }
            }
        });
    }

    fn push_transfer(&mut self, entry: TransferEntry) {
        if self.transfers.len() >= 50 {
            self.transfers.pop_front();
        }
        self.transfers.push_back(entry);
    }

    fn start_create_bucket(&mut self) {
        use super::pane::remote::RemoteLevel;
        if let FocusedPane::Remote = self.focused
            && let RemoteLevel::Buckets { ref alias } = self.remote.level.clone()
        {
            self.mode = Mode::Input {
                prompt: "New bucket name:".into(),
                value: String::new(),
                action: InputAction::CreateBucket {
                    alias: alias.clone(),
                },
            };
        }
    }

    fn handle_input_submit(&mut self, value: String, action: InputAction) {
        match action {
            InputAction::CreateBucket { alias } => {
                let bucket = value.trim().to_owned();
                if bucket.is_empty() {
                    return;
                }
                let config = self.config.clone();
                let tokens_path = default_tokens_path().unwrap_or_default();
                let tx = self.event_tx.clone();
                let alias_clone = alias.clone();
                self.remote_throbber.start();
                tokio::spawn(async move {
                    let result = async {
                        let client = build_client(&config, &tokens_path, &alias_clone)?;
                        crate::ops::buckets::create(&client, &bucket)
                            .await
                            .map_err(|e| e.to_string())?;
                        client.list_buckets().await.map_err(|e| e.to_string())
                    }
                    .await;
                    match result {
                        Ok(buckets) => {
                            let _ = tx.send(Event::RemoteFetched {
                                alias: alias_clone,
                                path: RemoteFetchPath::Buckets,
                                result: RemoteFetchResult::Buckets(buckets),
                            });
                        }
                        Err(message) => {
                            let _ = tx.send(Event::ActionFailed { message });
                        }
                    }
                });
            }
            InputAction::RenameObject { alias, bucket, key } => {
                let dst = value.trim().to_owned();
                if dst.is_empty() || dst == key {
                    return;
                }
                let config = self.config.clone();
                let tokens_path = default_tokens_path().unwrap_or_default();
                let tx = self.event_tx.clone();
                let alias_clone = alias.clone();
                let prefix = self.remote.objects_prefix();
                self.remote_throbber.start();
                tokio::spawn(async move {
                    let result = async {
                        let client = build_client(&config, &tokens_path, &alias_clone)?;
                        crate::ops::objects::rename(&client, &bucket, &key, &dst)
                            .await
                            .map_err(|e| e.to_string())?;
                        let page = client
                            .list_objects(
                                &bucket,
                                &ListOptions {
                                    prefix: prefix.clone(),
                                    after: None,
                                    limit: Some(500),
                                },
                            )
                            .await
                            .map_err(|e| e.to_string())?;
                        Ok::<_, String>((page.items, page.next))
                    }
                    .await;
                    match result {
                        Ok((items, next)) => {
                            let _ = tx.send(Event::RemoteFetched {
                                alias: alias_clone,
                                path: RemoteFetchPath::Objects { bucket, prefix },
                                result: RemoteFetchResult::Objects(items, next),
                            });
                        }
                        Err(message) => {
                            let _ = tx.send(Event::ActionFailed { message });
                        }
                    }
                });
            }
            InputAction::SetLabel { alias, bucket, key } => {
                let raw = value.trim();
                let Some((k, v)) = raw.split_once('=') else {
                    self.mode = Mode::Error(format!("expected key=value, got `{raw}`"));
                    return;
                };
                if k.is_empty() {
                    self.mode = Mode::Error("label key must not be empty".into());
                    return;
                }
                let mut map = BTreeMap::new();
                map.insert(k.to_lowercase(), v.to_owned());
                self.spawn_label_mutation(alias, bucket, key, "set", map);
            }
            InputAction::SetQuota { alias, bucket } => {
                match crate::ops::buckets::parse_size(value.trim()) {
                    Ok(bytes) => {
                        self.spawn_set_bucket_config(alias, bucket, Some(Some(bytes)), None)
                    }
                    Err(e) => self.mode = Mode::Error(e),
                }
            }
            InputAction::SetSse { alias, bucket } => {
                let algo = value.trim().to_owned();
                if algo.is_empty() {
                    return;
                }
                self.spawn_set_bucket_config(alias, bucket, None, Some(Some(algo)));
            }
            InputAction::SearchQuery {
                alias,
                bucket,
                prefix,
            } => {
                let query = value.trim().to_owned();
                if query.is_empty() {
                    return;
                }
                self.spawn_search(alias, bucket, prefix, query);
            }
            InputAction::FindName {
                alias,
                bucket,
                prefix,
            } => {
                let name = value.trim().to_owned();
                let name = if name.is_empty() { "*".into() } else { name };
                self.spawn_find(alias, bucket, prefix, name);
            }
            InputAction::LoginUsername { alias } => {
                let username = value.trim().to_owned();
                if username.is_empty() {
                    return;
                }
                self.mode = Mode::Input {
                    prompt: format!("Password for {username}:"),
                    value: String::new(),
                    action: InputAction::LoginPassword { alias, username },
                };
            }
            InputAction::LoginPassword { alias, username } => {
                if value.is_empty() {
                    return;
                }
                self.spawn_login(alias, username, value);
            }
            InputAction::AddUserUsername { alias } => {
                let username = value.trim().to_owned();
                if username.is_empty() {
                    self.mode = Mode::Admin(AdminTab::Users);
                    return;
                }
                self.mode = Mode::Input {
                    prompt: format!("Password for {username}:"),
                    value: String::new(),
                    action: InputAction::AddUserPassword { alias, username },
                };
            }
            InputAction::AddUserPassword { alias, username } => {
                if value.is_empty() {
                    self.mode = Mode::Admin(AdminTab::Users);
                    return;
                }
                let password = value;
                let config = self.config.clone();
                let tokens_path = default_tokens_path().unwrap_or_default();
                let tx = self.event_tx.clone();
                let alias_clone = alias.clone();
                tokio::spawn(async move {
                    let result = async {
                        let profile = config
                            .aliases
                            .get(&alias_clone)
                            .ok_or_else(|| "unknown alias".to_string())?;
                        let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                        let token = store
                            .token_for(&alias_clone)
                            .ok_or_else(|| "not authenticated".to_string())?;
                        let client =
                            client_from_alias(profile, Some(token)).map_err(|e| e.to_string())?;
                        client
                            .add_user(&username, &password)
                            .await
                            .map_err(|e| e.to_string())?;
                        client.list_users().await.map_err(|e| e.to_string())
                    }
                    .await;
                    if let Ok(users) = result {
                        let _ = tx.send(super::events::Event::UsersLoaded {
                            alias: alias_clone,
                            users,
                        });
                    }
                });
                self.mode = Mode::Admin(AdminTab::Users);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Alias;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::time::Duration;
    use tokio::sync::mpsc::UnboundedReceiver;
    use y2q_client::{MetadataView, ObjectHead, StaleLockEntry, TraceEvent, UserView};

    use super::super::pane::remote::RemoteLevel;

    fn test_app() -> (App, UnboundedReceiver<Event>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut cfg = CliConfig::default();
        cfg.add_alias(
            "a".into(),
            Alias {
                url: "http://127.0.0.1:1".into(),
                username: "u".into(),
                password: None,
                insecure: false,
                ca_cert_path: None,
                client_cert_path: None,
                client_key_path: None,
            },
        );
        (App::new(cfg, tx), rx)
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ch(c: char) -> KeyEvent {
        key(KeyCode::Char(c))
    }

    fn meta(key: &str) -> MetadataView {
        MetadataView {
            created: 0,
            modified: 0,
            size: 10,
            checksum_gxhash: "h".into(),
            bucket: "b".into(),
            key: key.into(),
            disk_path: "/d".into(),
            url_path: "/u".into(),
            labels: Default::default(),
            cipher_size: None,
            cipher_sha256: None,
            kem_alg: None,
            aead_alg: None,
            envelope_version: None,
        }
    }

    fn head_full() -> ObjectHead {
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("env".into(), "prod".into());
        ObjectHead {
            size: 2048,
            created: 1,
            modified: 2,
            checksum_gxhash: "gx".into(),
            labels,
            cipher_size: Some(4096),
            cipher_sha256: Some("sha".into()),
            kem_alg: Some("ml-kem-768".into()),
            aead_alg: Some("aes-256-gcm".into()),
            envelope_version: Some(1),
        }
    }

    // ── Browse-mode keys ────────────────────────────────────────────────────

    #[tokio::test]
    async fn browse_quit_and_pane_toggle() {
        let (mut app, _rx) = test_app();
        assert_eq!(app.handle_key(ch('q')), Action::Quit);
        assert!(app.should_quit);

        let (mut app, _rx) = test_app();
        assert_eq!(app.handle_key(key(KeyCode::Tab)), Action::SwitchPane);
        assert_eq!(app.focused, FocusedPane::Remote);
    }

    #[tokio::test]
    async fn browse_misc_keys() {
        let (mut app, _rx) = test_app();
        assert_eq!(app.handle_key(ch('t')), Action::ToggleTransferBar);
        assert!(!app.transfer_bar_visible);
        assert_eq!(app.handle_key(ch('a')), Action::ToggleAdmin);
        assert!(matches!(app.mode, Mode::Admin(_)));

        let (mut app, _rx) = test_app();
        assert_eq!(app.handle_key(key(KeyCode::Down)), Action::NavigateDown);
        assert_eq!(app.handle_key(ch('k')), Action::NavigateUp);
        assert_eq!(app.handle_key(key(KeyCode::Enter)), Action::Enter);
        assert_eq!(app.handle_key(key(KeyCode::Backspace)), Action::Back);
        assert_eq!(app.handle_key(ch('n')), Action::None);
        assert_eq!(app.handle_key(ch('c')), Action::Copy);
        assert_eq!(app.handle_key(ch('d')), Action::Delete);
        assert_eq!(app.handle_key(ch('r')), Action::Refresh);
        assert_eq!(app.handle_key(key(KeyCode::F(1))), Action::None);
    }

    // ── Admin-mode keys ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn admin_tab_cycle_and_exit() {
        let (mut app, _rx) = test_app();
        app.mode = Mode::Admin(AdminTab::Rebuild);
        assert_eq!(app.handle_key(key(KeyCode::Tab)), Action::NextTab);
        assert_eq!(app.mode, Mode::Admin(AdminTab::Locks));
        assert_eq!(app.handle_key(key(KeyCode::BackTab)), Action::PrevTab);
        assert_eq!(app.mode, Mode::Admin(AdminTab::Rebuild));
        assert_eq!(app.handle_key(ch('q')), Action::None);
        assert_eq!(app.mode, Mode::Browse);
    }

    #[tokio::test]
    async fn admin_nav_and_actions() {
        for tab in [AdminTab::Locks, AdminTab::Users, AdminTab::Metrics] {
            let (mut app, _rx) = test_app();
            app.mode = Mode::Admin(tab.clone());
            assert_eq!(app.handle_key(key(KeyCode::Up)), Action::NavigateUp);
            assert_eq!(app.handle_key(key(KeyCode::Down)), Action::NavigateDown);
        }
        // 'r' on Metrics tab triggers a refresh; active_alias None -> no spawn.
        let (mut app, _rx) = test_app();
        app.mode = Mode::Admin(AdminTab::Metrics);
        assert_eq!(app.handle_key(ch('r')), Action::Refresh);

        // 'n' on Users opens the new-user input.
        let (mut app, _rx) = test_app();
        app.mode = Mode::Admin(AdminTab::Users);
        assert_eq!(app.handle_key(ch('n')), Action::None);
        assert!(matches!(app.mode, Mode::Input { .. }));

        // 'd' on Users with a selected user opens a delete confirm.
        let (mut app, _rx) = test_app();
        app.mode = Mode::Admin(AdminTab::Users);
        app.users_view.set_users(vec![UserView {
            username: "bob".into(),
            created_at: 0,
            last_login: None,
        }]);
        assert_eq!(app.handle_key(ch('d')), Action::Delete);
        assert!(matches!(
            app.mode,
            Mode::Confirm(ConfirmAction::DeleteUser { .. })
        ));
        // Esc while a confirm is open declines it.
        assert_eq!(app.handle_key(key(KeyCode::Esc)), Action::ConfirmNo);
    }

    // ── Input-mode keys ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn input_typing_and_escape() {
        let (mut app, _rx) = test_app();
        app.mode = Mode::Input {
            prompt: "p".into(),
            value: String::new(),
            action: InputAction::CreateBucket { alias: "a".into() },
        };
        app.handle_key(ch('h'));
        app.handle_key(ch('i'));
        app.handle_key(key(KeyCode::Backspace));
        match &app.mode {
            Mode::Input { value, .. } => assert_eq!(value, "h"),
            _ => panic!("expected input mode"),
        }
        assert_eq!(app.handle_key(key(KeyCode::Esc)), Action::None);
        assert_eq!(app.mode, Mode::Browse);

        // Esc from an add-user input returns to the Users admin tab.
        let (mut app, _rx) = test_app();
        app.mode = Mode::Input {
            prompt: "p".into(),
            value: String::new(),
            action: InputAction::AddUserUsername { alias: "a".into() },
        };
        app.handle_key(key(KeyCode::Esc));
        assert_eq!(app.mode, Mode::Admin(AdminTab::Users));
    }

    #[tokio::test]
    async fn input_submit_create_bucket_and_add_user() {
        let (mut app, _rx) = test_app();
        app.mode = Mode::Input {
            prompt: "p".into(),
            value: "newbucket".into(),
            action: InputAction::CreateBucket { alias: "a".into() },
        };
        assert_eq!(app.handle_key(key(KeyCode::Enter)), Action::Enter);
        // Create now issues a real server call in the background; the pane refreshes
        // via a RemoteFetched event on success. Input mode closes back to Browse.
        assert_eq!(app.mode, Mode::Browse);
        tokio::time::sleep(Duration::from_millis(60)).await;

        // username -> password chained input
        let (mut app, _rx) = test_app();
        app.mode = Mode::Input {
            prompt: "p".into(),
            value: "alice".into(),
            action: InputAction::AddUserUsername { alias: "a".into() },
        };
        app.handle_key(key(KeyCode::Enter));
        assert!(matches!(
            app.mode,
            Mode::Input {
                action: InputAction::AddUserPassword { .. },
                ..
            }
        ));
        // submit password (spawns a network task that fails harmlessly)
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.mode, Mode::Admin(AdminTab::Users));
        tokio::time::sleep(Duration::from_millis(60)).await;
    }

    // ── Confirm-mode keys ───────────────────────────────────────────────────

    #[tokio::test]
    async fn confirm_yes_no() {
        let (mut app, _rx) = test_app();
        app.mode = Mode::Confirm(ConfirmAction::DeleteRemote {
            alias: "a".into(),
            bucket: "b".into(),
            key: "k".into(),
        });
        assert_eq!(app.handle_key(ch('y')), Action::ConfirmYes);
        assert_eq!(app.mode, Mode::Browse);

        let (mut app, _rx) = test_app();
        app.mode = Mode::Confirm(ConfirmAction::DeleteUser {
            alias: "a".into(),
            username: "bob".into(),
        });
        assert_eq!(app.handle_key(ch('n')), Action::ConfirmNo);
        assert_eq!(app.mode, Mode::Admin(AdminTab::Users));

        let (mut app, _rx) = test_app();
        app.mode = Mode::Confirm(ConfirmAction::DeleteUser {
            alias: "a".into(),
            username: "bob".into(),
        });
        assert_eq!(app.handle_key(ch('y')), Action::ConfirmYes);
        tokio::time::sleep(Duration::from_millis(60)).await;
    }

    #[tokio::test]
    async fn error_and_stat_dismiss() {
        let (mut app, _rx) = test_app();
        app.mode = Mode::Error("boom".into());
        assert_eq!(app.handle_key(ch('x')), Action::None);
        assert_eq!(app.mode, Mode::Browse);

        app.mode = Mode::ObjectStat {
            path: "p".into(),
            lines: vec![],
        };
        assert_eq!(app.handle_key(ch('x')), Action::None);
        assert_eq!(app.mode, Mode::Browse);
    }

    // ── handle_enter (remote pane) ──────────────────────────────────────────

    #[tokio::test]
    async fn handle_enter_remote_levels() {
        // Alias entry -> fetch buckets
        let (mut app, _rx) = test_app();
        app.focused = FocusedPane::Remote;
        assert_eq!(app.handle_key(key(KeyCode::Enter)), Action::Enter);
        assert_eq!(app.active_alias.as_deref(), Some("a"));

        // Bucket entry -> fetch objects
        let (mut app, _rx) = test_app();
        app.focused = FocusedPane::Remote;
        app.remote.set_buckets("a", vec!["b".into()]);
        app.remote.selected = 1; // the bucket
        app.handle_key(key(KeyCode::Enter));

        // Object entry -> fetch stat
        let (mut app, _rx) = test_app();
        app.focused = FocusedPane::Remote;
        app.remote.set_objects("a", "b", vec![meta("k")]);
        app.remote.selected = 1;
        app.handle_key(key(KeyCode::Enter));

        // Back entry -> go back
        let (mut app, _rx) = test_app();
        app.focused = FocusedPane::Remote;
        app.remote.set_objects("a", "b", vec![meta("k")]);
        app.remote.selected = 0; // Back
        app.handle_key(key(KeyCode::Enter));
        tokio::time::sleep(Duration::from_millis(60)).await;
    }

    // ── start_copy both directions ──────────────────────────────────────────

    #[tokio::test]
    async fn start_copy_remote_to_local() {
        let (mut app, _rx) = test_app();
        app.focused = FocusedPane::Remote;
        app.active_alias = Some("a".into());
        app.remote.set_objects("a", "b", vec![meta("k")]);
        app.remote.selected = 1;
        app.start_copy();
        assert_eq!(app.transfers.len(), 1);
        tokio::time::sleep(Duration::from_millis(60)).await;
    }

    #[tokio::test]
    async fn start_copy_local_to_remote() {
        let dir = std::env::temp_dir().join(format!("y2q-tui-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("file.bin");
        std::fs::write(&f, b"data").unwrap();

        let (mut app, _rx) = test_app();
        app.focused = FocusedPane::Local;
        app.local.cwd = dir.clone();
        app.local.entries = vec![
            super::super::pane::local::LocalEntry::Dir("..".into()),
            super::super::pane::local::LocalEntry::File {
                name: "file.bin".into(),
                size: 4,
            },
        ];
        app.local.selected = 1;
        app.remote.level = RemoteLevel::Objects {
            alias: "a".into(),
            bucket: "b".into(),
            prefix: None,
        };
        app.start_copy();
        assert_eq!(app.transfers.len(), 1);
        tokio::time::sleep(Duration::from_millis(60)).await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── request_delete + create_bucket guards ───────────────────────────────

    #[tokio::test]
    async fn request_delete_and_create_bucket() {
        let (mut app, _rx) = test_app();
        app.focused = FocusedPane::Remote;
        app.active_alias = Some("a".into());
        app.remote.set_objects("a", "b", vec![meta("k")]);
        app.remote.selected = 1;
        app.request_delete();
        assert!(matches!(
            app.mode,
            Mode::Confirm(ConfirmAction::DeleteRemote { .. })
        ));

        let (mut app, _rx) = test_app();
        app.focused = FocusedPane::Remote;
        app.remote.set_buckets("a", vec![]);
        app.start_create_bucket();
        assert!(matches!(app.mode, Mode::Input { .. }));
    }

    // ── update() event handling ─────────────────────────────────────────────

    #[tokio::test]
    async fn update_lifecycle_events() {
        let (mut app, _rx) = test_app();
        assert_eq!(app.update(Event::Tick), Action::None);
        assert_eq!(app.update(Event::Render), Action::None);
        assert_eq!(app.update(Event::Resize(1, 1)), Action::None);
        assert_eq!(app.update(Event::Quit), Action::Quit);
        assert!(app.should_quit);
        // Key event is delegated to handle_key.
        let (mut app, _rx) = test_app();
        assert_eq!(app.update(Event::Key(ch('q'))), Action::Quit);
    }

    #[tokio::test]
    async fn update_transfer_events() {
        let (mut app, _rx) = test_app();
        app.transfers
            .push_back(TransferEntry::new(1, "t".into(), Some(100)));
        app.update(Event::TransferUpdate {
            id: 1,
            bytes_done: 50,
            speed_bps: 10,
        });
        assert_eq!(app.transfers[0].bytes_done, 50);

        app.update(Event::TransferDone {
            id: 1,
            result: Ok(100),
        });
        assert!(matches!(
            app.transfers[0].status,
            TransferStatus::Done { .. }
        ));

        app.transfers
            .push_back(TransferEntry::new(2, "t2".into(), None));
        app.update(Event::TransferDone {
            id: 2,
            result: Err("nope".into()),
        });
        assert!(matches!(app.transfers[1].status, TransferStatus::Failed(_)));
    }

    #[tokio::test]
    async fn update_remote_fetched() {
        let (mut app, _rx) = test_app();
        app.update(Event::RemoteFetched {
            alias: "a".into(),
            path: RemoteFetchPath::Buckets,
            result: RemoteFetchResult::Buckets(vec!["b".into()]),
        });
        assert!(matches!(app.remote.level, RemoteLevel::Buckets { .. }));

        app.update(Event::RemoteFetched {
            alias: "a".into(),
            path: RemoteFetchPath::Objects {
                bucket: "b".into(),
                prefix: None,
            },
            result: RemoteFetchResult::Objects(vec![meta("k")], None),
        });
        assert!(matches!(app.remote.level, RemoteLevel::Objects { .. }));

        app.update(Event::RemoteFetched {
            alias: "a".into(),
            path: RemoteFetchPath::Buckets,
            result: RemoteFetchResult::Error("err".into()),
        });
        assert!(matches!(app.mode, Mode::Error(_)));
    }

    #[tokio::test]
    async fn update_admin_data_events() {
        let (mut app, _rx) = test_app();
        app.update(Event::RebuildStatus {
            alias: "a".into(),
            state: "running".into(),
            percent: Some(50),
            reason: None,
        });
        assert_eq!(app.rebuild.percent, Some(50));

        app.update(Event::UsersLoaded {
            alias: "a".into(),
            users: vec![UserView {
                username: "u".into(),
                created_at: 0,
                last_login: None,
            }],
        });
        assert_eq!(app.users_view.users.len(), 1);

        app.update(Event::LocksLoaded {
            alias: "a".into(),
            locks: vec![StaleLockEntry {
                bucket: "b".into(),
                uuid: "id".into(),
                locked_since_nanos: 0,
                age_seconds: 1,
            }],
        });
        assert_eq!(app.locks.locks.len(), 1);

        app.update(Event::MetricsLoaded {
            alias: "a".into(),
            result: Ok("# HELP\n".into()),
        });
        app.update(Event::MetricsLoaded {
            alias: "a".into(),
            result: Err("bad".into()),
        });
        assert!(app.metrics_view.error.is_some());

        app.update(Event::TraceEventArrived {
            alias: "a".into(),
            event: TraceEvent {
                request_id: "r".into(),
                timestamp_ns: 0,
                method: "GET".into(),
                path: "/".into(),
                status: 200,
                latency_ms: 1.0,
                req_bytes: None,
                resp_bytes: None,
                remote_addr: None,
            },
        });
        app.update(Event::TraceStreamEnded {
            alias: "a".into(),
            error: Some("ended".into()),
        });
        assert!(!app.events_view.streaming);
    }

    #[tokio::test]
    async fn update_object_stat() {
        let (mut app, _rx) = test_app();
        app.update(Event::ObjectStatFetched {
            path: "a/b/k".into(),
            result: Ok(head_full()),
        });
        match &app.mode {
            Mode::ObjectStat { lines, .. } => {
                assert!(lines.iter().any(|l| l.contains("KEM:")));
                assert!(lines.iter().any(|l| l.contains("Label")));
            }
            _ => panic!("expected stat popup"),
        }

        app.update(Event::ObjectStatFetched {
            path: "a/b/k".into(),
            result: Err("missing".into()),
        });
        assert!(matches!(app.mode, Mode::Error(_)));
    }

    #[tokio::test]
    async fn trigger_refresh_levels() {
        let (mut app, _rx) = test_app();
        app.remote.level = RemoteLevel::Buckets { alias: "a".into() };
        app.trigger_refresh();
        let (mut app, _rx) = test_app();
        app.remote.level = RemoteLevel::Objects {
            alias: "a".into(),
            bucket: "b".into(),
            prefix: None,
        };
        app.trigger_refresh();
        tokio::time::sleep(Duration::from_millis(60)).await;
    }

    #[tokio::test]
    async fn fetch_helpers_require_active_alias() {
        // With an active alias set, fetch_* run their sync prelude then spawn.
        let (mut app, _rx) = test_app();
        app.active_alias = Some("a".into());
        app.fetch_users();
        app.fetch_locks();
        app.fetch_metrics();
        app.start_trace_stream();
        assert!(app.events_view.streaming);
        // give spawned tasks a chance to run their (failing) bodies
        tokio::time::sleep(Duration::from_millis(80)).await;
    }
}
