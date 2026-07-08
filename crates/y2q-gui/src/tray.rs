//! Tray icon + context menu. Built and owned on the same thread as the rest
//! of `GuiApp` (the main/UI thread) — tray-icon's menu types are `Rc`-based
//! and not `Send`, so unlike an earlier version of this module there is no
//! separate GTK thread to hand a handle across.
//!
//! Menu item ids are the contract with `app.rs`'s `MenuEvent` poll: static
//! ids for the fixed items, `CONNECT_PREFIX` + alias name for the dynamic
//! per-alias "Quick Connect" entries.
use tray_icon::menu::{Menu, MenuItem, Submenu};
use tray_icon::{TrayIcon, TrayIconBuilder};

pub const OPEN_ID: &str = "open";
pub const QUIT_ID: &str = "quit";
pub const CLEAR_LOGINS_ID: &str = "clear_logins";
pub const CONNECT_PREFIX: &str = "connect:";

fn build_menu(aliases: &[String]) -> Menu {
    let menu = Menu::new();
    let _ = menu.append(&MenuItem::with_id(OPEN_ID, "Open y2q", true, None));

    let connect_submenu = Submenu::new("Quick Connect", !aliases.is_empty());
    for name in aliases {
        let item = MenuItem::with_id(format!("{CONNECT_PREFIX}{name}"), name, true, None);
        let _ = connect_submenu.append(&item);
    }
    let _ = menu.append(&connect_submenu);

    let _ = menu.append(&MenuItem::with_id(
        CLEAR_LOGINS_ID,
        "Clear all logins",
        true,
        None,
    ));
    let _ = menu.append(&MenuItem::with_id(QUIT_ID, "Quit", true, None));
    menu
}

pub struct TrayManager {
    tray: TrayIcon,
}

impl TrayManager {
    /// Must be called on the main/UI thread — same thread `pump`/`rebuild_menu`
    /// and the rest of `GuiApp` run on.
    pub fn new(aliases: &[String]) -> Self {
        #[cfg(any(
            target_os = "linux",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        gtk::init().expect("gtk init");

        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(build_menu(aliases)))
            .with_icon(crate::assets::tray_icon())
            .with_tooltip("y2q")
            .build()
            .expect("build tray icon");
        Self { tray }
    }

    /// Rebuild the menu (e.g. after an alias is added/removed/renamed).
    pub fn rebuild_menu(&self, aliases: &[String]) {
        self.tray.set_menu(Some(Box::new(build_menu(aliases))));
    }

    /// Drain pending GTK/GLib events. eframe's winit event loop doesn't run
    /// one on Linux, so tray-icon's libappindicator backend needs someone
    /// else pumping it — call this once per egui frame. No-op elsewhere.
    #[cfg(any(
        target_os = "linux",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    pub fn pump(&self) {
        let ctx = glib::MainContext::default();
        while ctx.pending() {
            ctx.iteration(false);
        }
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    )))]
    pub fn pump(&self) {}
}
