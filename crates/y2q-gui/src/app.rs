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
            name: String::new(),
            url: String::new(),
            username: String::new(),
            insecure: false,
            ca_cert_path: String::new(),
            client_cert_path: String::new(),
            client_key_path: String::new(),
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
    login_prompt: Option<LoginPrompt>,
    error_banner: Option<String>,
    should_quit: bool,
    // Kept alive for the app's lifetime on Windows/macOS. On Linux the tray
    // icon lives on its own GTK thread instead (see tray::spawn) and this
    // stays None.
    _tray: Option<tray_icon::TrayIcon>,
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

        #[cfg(not(any(
            target_os = "linux",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        )))]
        let tray = Some(tray::build());
        #[cfg(any(
            target_os = "linux",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        let tray = None;
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
            login_prompt: None,
            error_banner: None,
            should_quit: false,
            _tray: tray,
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
        while let Ok(ev) = self.rx.try_recv() {
            self.apply_event(ev);
        }

        while let Ok(event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            if event.id == tray::OPEN_ID {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            } else if event.id == tray::QUIT_ID {
                self.should_quit = true;
            }
        }
        // Left-click isn't emitted on Linux (libappindicator forces a
        // menu-only interaction there) — drain it anyway for other OSes;
        // the menu above is the primary interaction path everywhere.
        while tray_icon::TrayIconEvent::receiver().try_recv().is_ok() {}

        if self.should_quit {
            self.unmount_all_blocking();
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        } else if ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

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

            if ui.button("+ Add alias").clicked() {
                self.add_draft.get_or_insert_with(AliasDraft::empty);
            }

            if let Some(draft) = &mut self.add_draft {
                let mut save = false;
                let mut cancel = false;
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    egui::Grid::new("add_alias_grid")
                        .num_columns(2)
                        .show(ui, |ui| {
                            ui.label("Name");
                            ui.text_edit_singleline(&mut draft.name);
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
                    if draft.name.trim().is_empty() || draft.url.trim().is_empty() {
                        self.error_banner = Some("Alias name and server URL are required".into());
                    } else {
                        let name = draft.name.trim().to_owned();
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
                        self.rows.insert(
                            name.clone(),
                            AliasRow {
                                alias,
                                bucket: String::new(),
                                mountpoint: default_mountpoint(&name),
                                status: MountStatus::Unmounted,
                            },
                        );
                        self.add_draft = None;
                    }
                } else if cancel {
                    self.add_draft = None;
                }
            }

            ui.separator();

            let mut to_remove: Option<String> = None;
            let mut to_mount: Option<String> = None;
            let mut to_unmount: Option<String> = None;
            let mut to_open: Option<String> = None;

            egui::ScrollArea::vertical().show(ui, |ui| {
                for (name, row) in &mut self.rows {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.strong(name);
                            ui.label(format!("({})", row.alias.url));
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
                        ui.horizontal(|ui| {
                            match &row.status {
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
                            }
                            if ui.button("Remove").clicked() {
                                to_remove = Some(name.clone());
                            }
                        });
                    });
                }
            });

            if let Some(name) = to_mount
                && let Some(row) = self.rows.get_mut(&name)
            {
                row.status = MountStatus::Mounting;
                let mountpoint = row.mountpoint.clone();
                let bucket = row.bucket.clone();
                self.spawn_mount(ctx.clone(), name, mountpoint, bucket);
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
            if let Some(name) = to_remove {
                self.rows.shift_remove(&name);
                self.config.remove_alias(&name);
                self.save_config();
            }
        });

        let mut close_prompt = false;
        let mut submit_login: Option<(String, String, String, String, String)> = None;
        if let Some(lp) = &mut self.login_prompt {
            egui::Window::new(format!("Log in to {}", lp.alias))
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    egui::Grid::new("login_grid").num_columns(2).show(ui, |ui| {
                        ui.label("Username");
                        ui.text_edit_singleline(&mut lp.username);
                        ui.end_row();
                        ui.label("Password");
                        ui.add(egui::TextEdit::singleline(&mut lp.password).password(true));
                        ui.end_row();
                    });
                    if let Some(err) = &lp.error {
                        ui.colored_label(egui::Color32::LIGHT_RED, err);
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Log in & Mount").clicked() {
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
