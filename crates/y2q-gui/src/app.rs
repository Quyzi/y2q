use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, RwLock};

use indexmap::IndexMap;
use y2q_client::Y2qClient;
use y2q_config::{Alias, CliConfig, TokenEntry, TokenStore};
use y2q_mount_core::path::MountMode;

use crate::events::GuiEvent;
use crate::mount_backend::{self, MountHandle};
use crate::tray;

enum MountStatus {
    Unmounted,
    Mounting,
    Mounted {
        mountpoint: String,
        handle: MountHandle,
    },
    Unmounting,
    Error(String),
}

struct AliasRow {
    alias: Alias,
    bucket: String,
    mountpoint: String,
    status: MountStatus,
}

struct AliasDraft {
    /// `Some(original_name)` when editing an existing alias (name field is
    /// then locked); `None` when adding a new one.
    editing: Option<String>,
    name: String,
    url: String,
    username: String,
    insecure: bool,
    ca_cert_path: String,
    client_cert_path: String,
    client_key_path: String,
}

impl AliasDraft {
    fn empty() -> Self {
        Self {
            editing: None,
            name: String::new(),
            url: String::new(),
            username: String::new(),
            insecure: false,
            ca_cert_path: String::new(),
            client_cert_path: String::new(),
            client_key_path: String::new(),
        }
    }

    fn from_existing(name: &str, alias: &Alias) -> Self {
        Self {
            editing: Some(name.to_owned()),
            name: name.to_owned(),
            url: alias.url.clone(),
            username: alias.username.clone(),
            insecure: alias.insecure,
            ca_cert_path: alias.ca_cert_path.clone().unwrap_or_default(),
            client_cert_path: alias.client_cert_path.clone().unwrap_or_default(),
            client_key_path: alias.client_key_path.clone().unwrap_or_default(),
        }
    }
}

struct LoginPrompt {
    alias: String,
    username: String,
    password: String,
    error: Option<String>,
    mountpoint: String,
    bucket: String,
    /// Set once the username field has claimed initial keyboard focus, so we
    /// don't keep stealing focus back from the password field every frame.
    focused: bool,
}

fn default_mountpoint(alias_name: &str) -> String {
    directories::UserDirs::new()
        .map(|u| u.home_dir().join("y2q").join(alias_name))
        .unwrap_or_else(|| PathBuf::from(format!("./y2q-{alias_name}")))
        .display()
        .to_string()
}

pub struct GuiApp {
    rt: tokio::runtime::Handle,
    tx: Sender<GuiEvent>,
    rx: Receiver<GuiEvent>,
    config_path: PathBuf,
    tokens_path: PathBuf,
    config: CliConfig,
    rows: IndexMap<String, AliasRow>,
    add_draft: Option<AliasDraft>,
    pending_remove: Option<String>,
    login_prompt: Option<LoginPrompt>,
    error_banner: Option<String>,
    should_quit: bool,
    /// The alias-manager window is a destroy/recreate immediate viewport
    /// rather than something we hide in place — on this Wayland/KDE stack
    /// (and plausibly others) `ViewportCommand::Visible`/`Minimized` don't
    /// reliably hide a window or, worse, `Minimized` stops the event loop
    /// from ticking at all, so a tray click could never restore it. Closing
    /// the child viewport (by not calling `show_viewport_immediate` for it)
    /// and recreating it later is the one thing verified to work.
    show_window: bool,
    tray: tray::TrayManager,
}

impl GuiApp {
    pub fn new(cc: &eframe::CreationContext<'_>, rt: tokio::runtime::Handle) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();

        let config_path =
            y2q_config::default_config_path().unwrap_or_else(|_| PathBuf::from("config.toml"));
        let tokens_path =
            y2q_config::default_tokens_path().unwrap_or_else(|_| PathBuf::from("tokens.toml"));
        let config = CliConfig::load(&config_path).unwrap_or_default();

        let mut rows = IndexMap::new();
        for (name, alias) in &config.aliases {
            rows.insert(
                name.clone(),
                AliasRow {
                    alias: alias.clone(),
                    bucket: String::new(),
                    mountpoint: default_mountpoint(name),
                    status: MountStatus::Unmounted,
                },
            );
        }

        let tray = tray::TrayManager::new(&rows.keys().cloned().collect::<Vec<_>>());
        let _ = &cc.egui_ctx;

        Self {
            rt,
            tx,
            rx,
            config_path,
            tokens_path,
            config,
            rows,
            add_draft: None,
            pending_remove: None,
            login_prompt: None,
            error_banner: None,
            should_quit: false,
            show_window: true,
            tray,
        }
    }

    fn apply_event(&mut self, ev: GuiEvent) {
        match ev {
            GuiEvent::Login { alias, result } => match result {
                Ok(()) => {
                    if let Some(lp) = &self.login_prompt
                        && lp.alias == alias
                    {
                        self.login_prompt = None;
                    }
                    if let Some(row) = self.rows.get_mut(&alias) {
                        row.status = MountStatus::Mounting;
                    }
                }
                Err(msg) => {
                    if let Some(lp) = &mut self.login_prompt
                        && lp.alias == alias
                    {
                        lp.error = Some(msg);
                    }
                }
            },
            GuiEvent::Mount { alias, result } => match result {
                Ok((mountpoint, handle)) => {
                    if let Some(row) = self.rows.get_mut(&alias) {
                        row.status = MountStatus::Mounted { mountpoint, handle };
                    }
                }
                Err(msg) => {
                    let not_logged_in = msg.contains("not logged in");
                    if not_logged_in && let Some(row) = self.rows.get(&alias) {
                        self.login_prompt = Some(LoginPrompt {
                            alias: alias.clone(),
                            username: row.alias.username.clone(),
                            password: String::new(),
                            error: None,
                            mountpoint: row.mountpoint.clone(),
                            bucket: row.bucket.clone(),
                            focused: false,
                        });
                    }
                    if let Some(row) = self.rows.get_mut(&alias) {
                        row.status = if not_logged_in {
                            MountStatus::Unmounted
                        } else {
                            MountStatus::Error(msg)
                        };
                    }
                }
            },
            GuiEvent::Unmount { alias, result } => {
                if let Some(row) = self.rows.get_mut(&alias) {
                    row.status = match result {
                        Ok(()) => MountStatus::Unmounted,
                        Err(msg) => MountStatus::Error(msg),
                    };
                }
            }
        }
    }

    fn spawn_mount(
        &self,
        ctx: egui::Context,
        alias_name: String,
        mountpoint: String,
        bucket: String,
    ) {
        let tx = self.tx.clone();
        let rt = self.rt.clone();
        let config_path = self.config_path.clone();
        self.rt.spawn(async move {
            let resolved = y2q_mount_core::client::resolve_client(Some(&config_path), &alias_name);
            let (client, expires_at) = match resolved {
                Ok(v) => v,
                Err(e) => {
                    let _ = tx.send(GuiEvent::Mount {
                        alias: alias_name,
                        result: Err(e.to_string()),
                    });
                    ctx.request_repaint();
                    return;
                }
            };
            y2q_mount_core::client::spawn_token_refresh(rt.clone(), client.clone(), expires_at);
            do_mount(&tx, &ctx, rt, alias_name, mountpoint, bucket, client).await;
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_login_and_mount(
        &self,
        ctx: egui::Context,
        alias_name: String,
        username: String,
        password: String,
        mountpoint: String,
        bucket: String,
    ) {
        let tx = self.tx.clone();
        let rt = self.rt.clone();
        let config_path = self.config_path.clone();
        let tokens_path = self.tokens_path.clone();
        self.rt.spawn(async move {
            macro_rules! fail {
                ($e:expr) => {{
                    let _ = tx.send(GuiEvent::Login {
                        alias: alias_name.clone(),
                        result: Err($e.to_string()),
                    });
                    ctx.request_repaint();
                    return;
                }};
            }

            let config = match CliConfig::load(&config_path) {
                Ok(c) => c,
                Err(e) => fail!(e),
            };
            let alias = match config.get_alias(&alias_name) {
                Ok(a) => a.clone(),
                Err(e) => fail!(e),
            };
            let mut client = match y2q_mount_core::client::build_client(&alias, None) {
                Ok(c) => c,
                Err(e) => fail!(e),
            };
            let resp = match client.login(&username, &password, None).await {
                Ok(r) => r,
                Err(e) => fail!(e),
            };

            let mut store = match TokenStore::load(&tokens_path) {
                Ok(s) => s,
                Err(e) => fail!(e),
            };
            store.set(
                &alias_name,
                TokenEntry {
                    token: resp.token.clone(),
                    expires_at: resp.expires_at,
                    username: resp.username,
                },
            );
            if let Err(e) = store.save(&tokens_path) {
                fail!(e);
            }

            let _ = tx.send(GuiEvent::Login {
                alias: alias_name.clone(),
                result: Ok(()),
            });
            ctx.request_repaint();

            client.set_token(resp.token);
            let client = Arc::new(RwLock::new(client));
            y2q_mount_core::client::spawn_token_refresh(
                rt.clone(),
                client.clone(),
                resp.expires_at,
            );
            do_mount(&tx, &ctx, rt, alias_name, mountpoint, bucket, client).await;
        });
    }

    fn spawn_unmount(&self, ctx: egui::Context, alias_name: String, mut handle: MountHandle) {
        let tx = self.tx.clone();
        self.rt.spawn_blocking(move || {
            let result = mount_backend::unmount(&mut handle);
            let _ = tx.send(GuiEvent::Unmount {
                alias: alias_name,
                result,
            });
            ctx.request_repaint();
        });
    }

    fn unmount_all_blocking(&mut self) {
        for row in self.rows.values_mut() {
            if let MountStatus::Mounted { handle, .. } = &mut row.status {
                let _ = mount_backend::unmount(handle);
            }
            row.status = MountStatus::Unmounted;
        }
    }

    fn save_config(&self) {
        if let Err(e) = self.config.save(&self.config_path) {
            tracing::error!("save config: {e}");
        }
    }

    fn rebuild_tray_menu(&self) {
        let names: Vec<String> = self.rows.keys().cloned().collect();
        self.tray.rebuild_menu(&names);
    }

    /// Shared by the row's Mount button and the tray's Quick Connect submenu.
    fn trigger_mount(&mut self, ctx: egui::Context, name: String) {
        let Some(row) = self.rows.get_mut(&name) else {
            return;
        };
        if !matches!(row.status, MountStatus::Unmounted | MountStatus::Error(_)) {
            return;
        }
        row.status = MountStatus::Mounting;
        let mountpoint = row.mountpoint.clone();
        let bucket = row.bucket.clone();
        self.spawn_mount(ctx, name, mountpoint, bucket);
    }

    /// Clears every alias's cached session token, forcing a fresh login on
    /// the next mount. Does not touch anything currently mounted.
    fn clear_all_logins(&mut self) {
        let mut store = match TokenStore::load(&self.tokens_path) {
            Ok(s) => s,
            Err(e) => {
                self.error_banner = Some(format!("clear logins: {e}"));
                return;
            }
        };
        for name in self.rows.keys() {
            store.clear(name);
        }
        if let Err(e) = store.save(&self.tokens_path) {
            self.error_banner = Some(format!("clear logins: {e}"));
        }
    }
}

async fn do_mount(
    tx: &Sender<GuiEvent>,
    ctx: &egui::Context,
    rt: tokio::runtime::Handle,
    alias_name: String,
    mountpoint: String,
    bucket: String,
    client: Arc<RwLock<Y2qClient>>,
) {
    let mode = if bucket.trim().is_empty() {
        MountMode::Multi
    } else {
        MountMode::Single(bucket.trim().to_owned())
    };
    let mp = mountpoint.clone();
    let rt2 = rt.clone();
    let result =
        tokio::task::spawn_blocking(move || mount_backend::mount(client, rt2, &mp, false, mode))
            .await;
    let result = match result {
        Ok(Ok(handle)) => Ok((mountpoint, handle)),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(e.to_string()),
    };
    let _ = tx.send(GuiEvent::Mount {
        alias: alias_name,
        result,
    });
    ctx.request_repaint();
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Keep ticking at ~4Hz even when the window is closed (minimized to
        // tray) or otherwise idle — tray icon clicks arrive on a channel
        // outside egui/winit's own event stream, so without a periodic
        // repaint this loop (and the tray-menu poll below) would just stop
        // running once nothing else requests a frame, making the tray menu
        // (and a subsequent Quit) appear to do nothing.
        ctx.request_repaint_after(std::time::Duration::from_millis(250));
        self.tray.pump();

        while let Ok(ev) = self.rx.try_recv() {
            self.apply_event(ev);
        }

        while let Ok(event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            let id = event.id.0.as_str();
            if id == tray::OPEN_ID {
                self.show_window = true;
            } else if id == tray::QUIT_ID {
                self.should_quit = true;
            } else if id == tray::CLEAR_LOGINS_ID {
                self.clear_all_logins();
            } else if let Some(name) = id.strip_prefix(tray::CONNECT_PREFIX) {
                self.show_window = true;
                self.trigger_mount(ctx.clone(), name.to_owned());
            }
        }
        // Left-click isn't emitted on Linux (libappindicator forces a
        // menu-only interaction there) — drain it anyway for other OSes;
        // the menu above is the primary interaction path everywhere.
        while tray_icon::TrayIconEvent::receiver().try_recv().is_ok() {}

        if self.should_quit {
            self.unmount_all_blocking();
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        // The alias-manager window is its own immediate viewport, created
        // fresh each time `show_window` flips true and torn down the moment
        // we stop calling `show_viewport_immediate` for it — see the
        // `show_window` field doc for why (destroy/recreate is the one
        // hide/restore mechanism verified to actually work here).
        if self.show_window {
            let close_requested = ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of("y2q-main"),
                egui::ViewportBuilder::default()
                    .with_title("y2q")
                    .with_inner_size([480.0, 560.0])
                    .with_min_inner_size([360.0, 260.0]),
                |ctx, _class| {
                    self.draw_window(ctx);
                    ctx.input(|i| i.viewport().close_requested())
                },
            );
            if close_requested {
                self.show_window = false;
            }
        }
    }
}

impl GuiApp {
    fn draw_window(&mut self, ctx: &egui::Context) {
        if let Some(msg) = self.error_banner.clone() {
            egui::TopBottomPanel::top("error_banner").show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::LIGHT_RED, &msg);
                    if ui.button("Dismiss").clicked() {
                        self.error_banner = None;
                    }
                });
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("y2q — Alias Manager");
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                if ui.button("+ Add alias").clicked() {
                    self.add_draft.get_or_insert_with(AliasDraft::empty);
                }
                if ui.button("Log out all").clicked() {
                    self.clear_all_logins();
                }
            });

            if let Some(draft) = &mut self.add_draft {
                let mut save = false;
                let mut cancel = false;
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.strong(if draft.editing.is_some() {
                        "Edit alias"
                    } else {
                        "Add alias"
                    });
                    egui::Grid::new("add_alias_grid")
                        .num_columns(2)
                        .show(ui, |ui| {
                            ui.label("Name");
                            ui.add_enabled(
                                draft.editing.is_none(),
                                egui::TextEdit::singleline(&mut draft.name),
                            );
                            ui.end_row();
                            ui.label("Server URL");
                            ui.text_edit_singleline(&mut draft.url);
                            ui.end_row();
                            ui.label("Username");
                            ui.text_edit_singleline(&mut draft.username);
                            ui.end_row();
                            ui.label("Skip TLS verification");
                            ui.checkbox(&mut draft.insecure, "");
                            ui.end_row();
                            ui.label("CA cert (optional)");
                            ui.horizontal(|ui| {
                                ui.text_edit_singleline(&mut draft.ca_cert_path);
                                if ui.button("Browse…").clicked()
                                    && let Some(p) = rfd::FileDialog::new().pick_file()
                                {
                                    draft.ca_cert_path = p.display().to_string();
                                }
                            });
                            ui.end_row();
                            ui.label("Client cert (optional)");
                            ui.horizontal(|ui| {
                                ui.text_edit_singleline(&mut draft.client_cert_path);
                                if ui.button("Browse…").clicked()
                                    && let Some(p) = rfd::FileDialog::new().pick_file()
                                {
                                    draft.client_cert_path = p.display().to_string();
                                }
                            });
                            ui.end_row();
                            ui.label("Client key (optional)");
                            ui.horizontal(|ui| {
                                ui.text_edit_singleline(&mut draft.client_key_path);
                                if ui.button("Browse…").clicked()
                                    && let Some(p) = rfd::FileDialog::new().pick_file()
                                {
                                    draft.client_key_path = p.display().to_string();
                                }
                            });
                            ui.end_row();
                        });
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            save = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                    });
                });

                if save {
                    let name = draft.name.trim().to_owned();
                    if name.is_empty() || draft.url.trim().is_empty() {
                        self.error_banner = Some("Alias name and server URL are required".into());
                    } else if draft.editing.is_none() && self.rows.contains_key(&name) {
                        self.error_banner = Some(format!("Alias `{name}` already exists"));
                    } else {
                        let alias = Alias {
                            url: draft.url.trim().to_owned(),
                            username: draft.username.trim().to_owned(),
                            password: None,
                            insecure: draft.insecure,
                            ca_cert_path: none_if_empty(&draft.ca_cert_path),
                            client_cert_path: none_if_empty(&draft.client_cert_path),
                            client_key_path: none_if_empty(&draft.client_key_path),
                        };
                        self.config.add_alias(name.clone(), alias.clone());
                        self.save_config();
                        match self.rows.get_mut(&name) {
                            Some(row) => row.alias = alias,
                            None => {
                                self.rows.insert(
                                    name.clone(),
                                    AliasRow {
                                        alias,
                                        bucket: String::new(),
                                        mountpoint: default_mountpoint(&name),
                                        status: MountStatus::Unmounted,
                                    },
                                );
                                self.rebuild_tray_menu();
                            }
                        }
                        self.add_draft = None;
                    }
                } else if cancel {
                    self.add_draft = None;
                }
            }

            ui.separator();

            let mut to_edit: Option<String> = None;
            let mut to_mount: Option<String> = None;
            let mut to_unmount: Option<String> = None;
            let mut to_open: Option<String> = None;

            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (name, row) in &mut self.rows {
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.strong(name);
                                ui.label(format!("({})", row.alias.url));
                                if ui.small_button("Edit").clicked() {
                                    to_edit = Some(name.clone());
                                }
                                if ui.small_button("Remove").clicked() {
                                    self.pending_remove = Some(name.clone());
                                }
                            });
                            ui.horizontal(|ui| {
                                ui.label("Bucket (blank = all):");
                                ui.text_edit_singleline(&mut row.bucket);
                            });
                            ui.horizontal(|ui| {
                                ui.label("Mount at:");
                                ui.text_edit_singleline(&mut row.mountpoint);
                                if ui.button("Browse…").clicked()
                                    && let Some(p) = rfd::FileDialog::new().pick_folder()
                                {
                                    row.mountpoint = p.display().to_string();
                                }
                            });
                            ui.horizontal(|ui| match &row.status {
                                MountStatus::Unmounted => {
                                    if ui.button("Mount").clicked() {
                                        to_mount = Some(name.clone());
                                    }
                                    ui.label("not mounted");
                                }
                                MountStatus::Mounting => {
                                    ui.add_enabled(false, egui::Button::new("Mount"));
                                    ui.label("mounting…");
                                }
                                MountStatus::Mounted { mountpoint, .. } => {
                                    if ui.button("Unmount").clicked() {
                                        to_unmount = Some(name.clone());
                                    }
                                    ui.label(format!("mounted at {mountpoint}"));
                                    if ui.button("Open").clicked() {
                                        to_open = Some(mountpoint.clone());
                                    }
                                }
                                MountStatus::Unmounting => {
                                    ui.add_enabled(false, egui::Button::new("Unmount"));
                                    ui.label("unmounting…");
                                }
                                MountStatus::Error(msg) => {
                                    if ui.button("Mount").clicked() {
                                        to_mount = Some(name.clone());
                                    }
                                    ui.colored_label(egui::Color32::LIGHT_RED, msg);
                                }
                            });
                        });
                    }
                });

            if let Some(name) = to_mount {
                self.trigger_mount(ctx.clone(), name);
            }
            if let Some(name) = to_unmount
                && let Some(row) = self.rows.get_mut(&name)
            {
                let prev = std::mem::replace(&mut row.status, MountStatus::Unmounting);
                if let MountStatus::Mounted { handle, .. } = prev {
                    self.spawn_unmount(ctx.clone(), name, handle);
                }
            }
            if let Some(mountpoint) = to_open
                && let Err(e) = opener::open(&mountpoint)
            {
                self.error_banner = Some(format!("open {mountpoint}: {e}"));
            }
            if let Some(name) = to_edit
                && let Some(row) = self.rows.get(&name)
            {
                self.add_draft = Some(AliasDraft::from_existing(&name, &row.alias));
            }
        });

        if let Some(name) = self.pending_remove.clone() {
            let mut confirmed = false;
            let mut cancelled = false;
            egui::Window::new("Remove alias?")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!(
                        "Remove `{name}`? This deletes it from your config; it does not affect the server."
                    ));
                    ui.horizontal(|ui| {
                        if ui.button("Remove").clicked() {
                            confirmed = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancelled = true;
                        }
                    });
                });
            if confirmed {
                self.rows.shift_remove(&name);
                self.config.remove_alias(&name);
                self.save_config();
                self.rebuild_tray_menu();
                self.pending_remove = None;
            } else if cancelled {
                self.pending_remove = None;
            }
        }

        let mut close_prompt = false;
        let mut submit_login: Option<(String, String, String, String, String)> = None;
        if let Some(lp) = &mut self.login_prompt {
            egui::Window::new(format!("Log in to {}", lp.alias))
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    let mut enter_pressed = false;
                    egui::Grid::new("login_grid").num_columns(2).show(ui, |ui| {
                        ui.label("Username");
                        let username_resp = ui.text_edit_singleline(&mut lp.username);
                        if !lp.focused {
                            username_resp.request_focus();
                            lp.focused = true;
                        }
                        enter_pressed |= username_resp.lost_focus()
                            && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        ui.end_row();
                        ui.label("Password");
                        let password_resp =
                            ui.add(egui::TextEdit::singleline(&mut lp.password).password(true));
                        enter_pressed |= password_resp.lost_focus()
                            && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        ui.end_row();
                    });
                    if let Some(err) = &lp.error {
                        ui.colored_label(egui::Color32::LIGHT_RED, err);
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Log in & Mount").clicked() || enter_pressed {
                            submit_login = Some((
                                lp.alias.clone(),
                                lp.username.clone(),
                                lp.password.clone(),
                                lp.mountpoint.clone(),
                                lp.bucket.clone(),
                            ));
                        }
                        if ui.button("Cancel").clicked() {
                            close_prompt = true;
                        }
                    });
                });
        }
        if close_prompt {
            self.login_prompt = None;
        }
        if let Some((alias, username, password, mountpoint, bucket)) = submit_login {
            self.spawn_login_and_mount(ctx.clone(), alias, username, password, mountpoint, bucket);
        }
    }
}

fn none_if_empty(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
}
