use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::mpsc::UnboundedSender;
use y2q_client::ListOptions;

use crate::client_builder::client_from_profile;
use crate::config::{CliConfig, default_tokens_path};
use crate::output::{fmt_bytes, fmt_ns};
use crate::progress::{CountingReader, CountingWriter, ProgressReporter};
use crate::token::TokenStore;

use super::actions::Action;
use super::admin::{LocksView, RebuildView, UsersView};
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
    pub active_alias: Option<String>,
    pub event_tx: UnboundedSender<Event>,
    pub config: CliConfig,
    pub should_quit: bool,
}

impl App {
    pub fn new(config: CliConfig, event_tx: UnboundedSender<Event>) -> Self {
        let aliases: Vec<String> = config.profiles.keys().cloned().collect();
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
                Action::None
            }
            Event::TransferDone { id, result } => {
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
                Action::None
            }
            Event::RemoteFetched {
                alias,
                path,
                result,
            } => {
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
            Event::ObjectStatFetched { path, result } => {
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
                Action::None
            }
            _ => Action::None,
        }
    }

    fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> Action {
        use crossterm::event::KeyCode;

        if let Mode::Input {
            ref value,
            ref action,
            ..
        } = self.mode.clone()
        {
            return match key.code {
                KeyCode::Esc => {
                    self.mode = match action {
                        InputAction::AddUserUsername { .. }
                        | InputAction::AddUserPassword { .. } => Mode::Admin(AdminTab::Users),
                        _ => Mode::Browse,
                    };
                    Action::None
                }
                KeyCode::Enter => {
                    let value = value.clone();
                    let action = action.clone();
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
            };
        }

        if let Mode::Confirm(ref action) = self.mode.clone() {
            let mode_after = match action {
                ConfirmAction::DeleteUser { .. } => Mode::Admin(AdminTab::Users),
                _ => Mode::Browse,
            };
            return match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.execute_confirm(action.clone());
                    self.mode = mode_after;
                    Action::ConfirmYes
                }
                _ => {
                    self.mode = mode_after;
                    Action::ConfirmNo
                }
            };
        }

        if let Mode::Error(_) = self.mode {
            self.mode = Mode::Browse;
            return Action::None;
        }

        if let Mode::ObjectStat { .. } = self.mode {
            self.mode = Mode::Browse;
            return Action::None;
        }

        if let Mode::Admin(ref tab) = self.mode.clone() {
            return match key.code {
                KeyCode::Char('q') | KeyCode::Esc => {
                    self.mode = Mode::Browse;
                    Action::None
                }
                KeyCode::Tab => {
                    let next = tab.next();
                    match &next {
                        AdminTab::Users => self.fetch_users(),
                        AdminTab::Locks => self.fetch_locks(),
                        _ => {}
                    }
                    self.mode = Mode::Admin(next);
                    Action::NextTab
                }
                KeyCode::BackTab => {
                    let prev = tab.prev();
                    match &prev {
                        AdminTab::Users => self.fetch_users(),
                        AdminTab::Locks => self.fetch_locks(),
                        _ => {}
                    }
                    self.mode = Mode::Admin(prev);
                    Action::PrevTab
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    match tab {
                        AdminTab::Locks => self.locks.nav_up(),
                        AdminTab::Users => self.users_view.nav_up(),
                        _ => {}
                    }
                    Action::NavigateUp
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    match tab {
                        AdminTab::Locks => self.locks.nav_down(),
                        AdminTab::Users => self.users_view.nav_down(),
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
                        && let Some(user) =
                            self.users_view.users.get(self.users_view.selected).cloned()
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
            };
        }

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
                    .profiles
                    .get(&alias)
                    .ok_or_else(|| format!("unknown alias `{alias}`"))?;
                let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                let token = store
                    .token_for(&alias)
                    .ok_or_else(|| "not authenticated".to_string())?;
                let client =
                    client_from_profile(profile, Some(token)).map_err(|e| e.to_string())?;
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
                    .profiles
                    .get(&alias)
                    .ok_or_else(|| format!("unknown alias `{alias}`"))?;
                let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                let token = store
                    .token_for(&alias)
                    .ok_or_else(|| "not authenticated".to_string())?;
                let client =
                    client_from_profile(profile, Some(token)).map_err(|e| e.to_string())?;
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
                                .profiles
                                .get(&alias)
                                .ok_or_else(|| "unknown alias".to_string())?;
                            let store =
                                TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                            let token = store
                                .token_for(&alias)
                                .ok_or_else(|| "unauthenticated".to_string())?;
                            let client = client_from_profile(profile, Some(token))
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
                                .profiles
                                .get(&alias)
                                .ok_or_else(|| "unknown alias".to_string())?;
                            let store =
                                TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                            let token = store
                                .token_for(&alias)
                                .ok_or_else(|| "unauthenticated".to_string())?;
                            let client = client_from_profile(profile, Some(token))
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
        use super::pane::remote::RemoteEntry;
        if let FocusedPane::Remote = self.focused
            && let Some(RemoteEntry::Object(m)) = self.remote.selected_entry().cloned()
        {
            let alias = self.active_alias.clone().unwrap_or_default();
            self.mode = Mode::Confirm(ConfirmAction::DeleteRemote {
                alias,
                bucket: m.bucket.clone(),
                key: m.key.clone(),
            });
        }
    }

    fn execute_confirm(&mut self, action: ConfirmAction) {
        match action {
            ConfirmAction::DeleteRemote { alias, bucket, key } => {
                let config = self.config.clone();
                let tokens_path = default_tokens_path().unwrap_or_default();
                tokio::spawn(async move {
                    let _ = async {
                        let profile = config.profiles.get(&alias)?;
                        let store = TokenStore::load(&tokens_path).ok()?;
                        let token = store.token_for(&alias)?;
                        let client = client_from_profile(profile, Some(token)).ok()?;
                        client.delete(&bucket, &key).await.ok()
                    }
                    .await;
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
                            .profiles
                            .get(&alias_clone)
                            .ok_or_else(|| "unknown alias".to_string())?;
                        let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                        let token = store
                            .token_for(&alias_clone)
                            .ok_or_else(|| "not authenticated".to_string())?;
                        let client =
                            client_from_profile(profile, Some(token)).map_err(|e| e.to_string())?;
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
                    .profiles
                    .get(&alias)
                    .ok_or_else(|| format!("unknown alias `{alias}`"))?;
                let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                let token = store
                    .token_for(&alias)
                    .ok_or_else(|| "not authenticated".to_string())?;
                let client =
                    client_from_profile(profile, Some(token)).map_err(|e| e.to_string())?;
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
                    .profiles
                    .get(&alias)
                    .ok_or_else(|| format!("unknown alias `{alias}`"))?;
                let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                let token = store
                    .token_for(&alias)
                    .ok_or_else(|| "not authenticated".to_string())?;
                let client =
                    client_from_profile(profile, Some(token)).map_err(|e| e.to_string())?;
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
                    .profiles
                    .get(&alias)
                    .ok_or_else(|| format!("unknown alias `{alias}`"))?;
                let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                let token = store
                    .token_for(&alias)
                    .ok_or_else(|| "not authenticated".to_string())?;
                let client =
                    client_from_profile(profile, Some(token)).map_err(|e| e.to_string())?;
                client.locks_list("5m").await.map_err(|e| e.to_string())
            }
            .await;
            if let Ok(locks) = result {
                let _ = tx.send(super::events::Event::LocksLoaded { alias, locks });
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
        use super::pane::remote::{RemoteEntry, RemoteLevel};
        match action {
            InputAction::CreateBucket { alias } => {
                let bucket = value.trim().to_owned();
                if bucket.is_empty() {
                    return;
                }
                self.remote.level = RemoteLevel::Objects {
                    alias,
                    bucket,
                    prefix: None,
                };
                self.remote.entries = vec![RemoteEntry::Back];
                self.remote.selected = 0;
                self.remote.scroll = 0;
                self.remote.loading = false;
                // Switch to local so the user can immediately select a file and press 'c'.
                // The bucket is only created on the backend once a file is uploaded to it.
                self.focused = FocusedPane::Local;
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
                            .profiles
                            .get(&alias_clone)
                            .ok_or_else(|| "unknown alias".to_string())?;
                        let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                        let token = store
                            .token_for(&alias_clone)
                            .ok_or_else(|| "not authenticated".to_string())?;
                        let client =
                            client_from_profile(profile, Some(token)).map_err(|e| e.to_string())?;
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
