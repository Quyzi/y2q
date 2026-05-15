use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc::UnboundedSender;
use y2q_client::{ClientConfig, ListOptions, Y2qClient};

use crate::config::{CliConfig, default_tokens_path};
use crate::token::TokenStore;

use super::actions::Action;
use super::admin::{LocksView, RebuildView, UsersView};
use super::events::{Event, RemoteFetchPath, RemoteFetchResult};
use super::pane::{LocalPane, RemotePane};
use super::state::{AdminTab, ConfirmAction, FocusedPane, InputAction, Mode};
use super::widgets::throbber::LoadingIndicator;
use super::widgets::transfer_bar::{TransferEntry, TransferStatus};

static TRANSFER_ID: AtomicU64 = AtomicU64::new(1);

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
            Event::TransferUpdate { id, bytes_done, speed_bps } => {
                if let Some(entry) = self.transfers.iter_mut().find(|e| e.id == id) {
                    entry.bytes_done = bytes_done;
                    if entry.speed_samples.len() >= 60 {
                        entry.speed_samples.pop_front();
                    }
                    entry.speed_samples.push_back(speed_bps);
                    entry.status = TransferStatus::Running;
                }
                Action::None
            }
            Event::TransferDone { id, result } => {
                if let Some(entry) = self.transfers.iter_mut().find(|e| e.id == id) {
                    entry.status = match result {
                        Ok(n) => { entry.bytes_done = n; TransferStatus::Done }
                        Err(e) => TransferStatus::Failed(e),
                    };
                }
                Action::None
            }
            Event::RemoteFetched { alias, path, result } => {
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
            Event::RebuildStatus { state, percent, reason, .. } => {
                self.rebuild = RebuildView { state, percent, reason };
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
            _ => Action::None,
        }
    }

    fn handle_key(&mut self, key: crossterm::event::KeyEvent) -> Action {
        use crossterm::event::KeyCode;

        if let Mode::Input { ref value, ref action, .. } = self.mode.clone() {
            return match key.code {
                KeyCode::Esc => {
                    self.mode = Mode::Browse;
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
            return match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.execute_confirm(action.clone());
                    self.mode = Mode::Browse;
                    Action::ConfirmYes
                }
                _ => {
                    self.mode = Mode::Browse;
                    Action::ConfirmNo
                }
            };
        }

        if let Mode::Error(_) = self.mode {
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
                    self.mode = Mode::Admin(tab.next());
                    Action::NextTab
                }
                KeyCode::BackTab => {
                    self.mode = Mode::Admin(tab.prev());
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
                    FocusedPane::Local => { self.local.enter(); }
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
                        RemoteEntry::Dir(_) | RemoteEntry::Object(_) => {}
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
                let profile = config.profiles.get(&alias)
                    .ok_or_else(|| format!("unknown alias `{alias}`"))?;
                let store = TokenStore::load(&tokens_path)
                    .map_err(|e| e.to_string())?;
                let token = store.token_for(&alias)
                    .ok_or_else(|| "not authenticated".to_string())?;
                let client = Y2qClient::new(ClientConfig {
                    base_url: profile.url.clone(),
                    token: Some(token),
                }).map_err(|e| e.to_string())?;
                client.list_buckets().await.map_err(|e| e.to_string())
            }.await;
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
                let profile = config.profiles.get(&alias)
                    .ok_or_else(|| format!("unknown alias `{alias}`"))?;
                let store = TokenStore::load(&tokens_path)
                    .map_err(|e| e.to_string())?;
                let token = store.token_for(&alias)
                    .ok_or_else(|| "not authenticated".to_string())?;
                let client = Y2qClient::new(ClientConfig {
                    base_url: profile.url.clone(),
                    token: Some(token),
                }).map_err(|e| e.to_string())?;
                let opts = ListOptions { prefix: prefix.clone(), after: None, limit: Some(500) };
                client.list_objects(&bucket, &opts).await.map_err(|e| e.to_string())
            }.await;
            let fetch_path = RemoteFetchPath::Objects { bucket: bucket_clone, prefix };
            let payload = match result {
                Ok(page) => RemoteFetchResult::Objects(page.items, page.next),
                Err(e) => RemoteFetchResult::Error(e),
            };
            let _ = tx.send(Event::RemoteFetched { alias, path: fetch_path, result: payload });
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
                if let RemoteLevel::Objects { ref alias, ref bucket, .. } = self.remote.level.clone() {
                    let alias = alias.clone();
                    let bucket = bucket.clone();
                    let key = local_path.file_name()
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
                            let profile = config.profiles.get(&alias)
                                .ok_or_else(|| "unknown alias".to_string())?;
                            let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                            let token = store.token_for(&alias).ok_or_else(|| "unauthenticated".to_string())?;
                            let client = Y2qClient::new(ClientConfig {
                                base_url: profile.url.clone(),
                                token: Some(token),
                            }).map_err(|e| e.to_string())?;
                            let file = tokio::fs::File::open(&local_path).await.map_err(|e| e.to_string())?;
                            let meta = file.metadata().await.map_err(|e| e.to_string())?;
                            let len = meta.len();
                            client.put_from_reader(&bucket, &key, file, Some(len), &Default::default(), None)
                                .await.map_err(|e| e.to_string())?;
                            Ok::<u64, String>(len)
                        }.await;
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
                    let local_dst = self.local.cwd.join(
                        key.rsplit('/').next().unwrap_or(&key)
                    );
                    let id = TRANSFER_ID.fetch_add(1, Ordering::Relaxed);
                    let label = format!("{alias}/{bucket}/{key} → {}", local_dst.display());
                    let size = Some(m.size);
                    self.push_transfer(TransferEntry::new(id, label, size));
                    let tx = self.event_tx.clone();
                    let config = self.config.clone();
                    let tokens_path = default_tokens_path().unwrap_or_default();
                    tokio::spawn(async move {
                        let result = async {
                            let profile = config.profiles.get(&alias)
                                .ok_or_else(|| "unknown alias".to_string())?;
                            let store = TokenStore::load(&tokens_path).map_err(|e| e.to_string())?;
                            let token = store.token_for(&alias).ok_or_else(|| "unauthenticated".to_string())?;
                            let client = Y2qClient::new(ClientConfig {
                                base_url: profile.url.clone(),
                                token: Some(token),
                            }).map_err(|e| e.to_string())?;
                            let mut file = tokio::fs::File::create(&local_dst).await.map_err(|e| e.to_string())?;
                            let n = client.get_to_writer(&bucket, &key, &mut file).await.map_err(|e| e.to_string())?;
                            Ok::<u64, String>(n)
                        }.await;
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
                        let client = Y2qClient::new(ClientConfig {
                            base_url: profile.url.clone(),
                            token: Some(token),
                        }).ok()?;
                        client.delete(&bucket, &key).await.ok()
                    }.await;
                });
            }
            ConfirmAction::DeleteUser { alias, username } => {
                let config = self.config.clone();
                let tokens_path = default_tokens_path().unwrap_or_default();
                tokio::spawn(async move {
                    let _ = async {
                        let profile = config.profiles.get(&alias)?;
                        let store = TokenStore::load(&tokens_path).ok()?;
                        let token = store.token_for(&alias)?;
                        let client = Y2qClient::new(ClientConfig {
                            base_url: profile.url.clone(),
                            token: Some(token),
                        }).ok()?;
                        client.delete_user(&username).await.ok()
                    }.await;
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
            RemoteLevel::Objects { ref alias, ref bucket, ref prefix } => {
                let alias = alias.clone();
                let bucket = bucket.clone();
                let prefix = prefix.clone();
                self.remote_throbber.start();
                self.fetch_objects(alias, bucket, prefix);
            }
            _ => {}
        }
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
                action: InputAction::CreateBucket { alias: alias.clone() },
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
        }
    }
}
