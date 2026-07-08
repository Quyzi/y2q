//! Tray icon + context menu. The two menu item ids below are the only
//! contract between this module and `app.rs`'s event loop — both the
//! Linux-thread-owned menu and the inline Windows/macOS menu use the same
//! ids, so `App::update` can react to `MenuEvent`s uniformly regardless of
//! which thread built the menu that produced them.
use tray_icon::TrayIconBuilder;
use tray_icon::menu::{Menu, MenuItem};

pub const OPEN_ID: &str = "open";
pub const QUIT_ID: &str = "quit";

fn build_icon() -> tray_icon::Icon {
    // Small solid-color placeholder icon — no bundled image asset yet.
    const SIZE: u32 = 32;
    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for _ in 0..(SIZE * SIZE) {
        rgba.extend_from_slice(&[92, 74, 214, 255]);
    }
    tray_icon::Icon::from_rgba(rgba, SIZE, SIZE).expect("fixed-size icon buffer is always valid")
}

fn build_menu() -> Menu {
    let menu = Menu::new();
    let open_item = MenuItem::with_id(OPEN_ID, "Open y2q", true, None);
    let quit_item = MenuItem::with_id(QUIT_ID, "Quit", true, None);
    let _ = menu.append(&open_item);
    let _ = menu.append(&quit_item);
    menu
}

#[cfg(any(
    target_os = "linux",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
pub fn spawn() {
    // eframe uses winit, which doesn't run a GTK main loop on Linux, but
    // tray-icon's Linux backend (libappindicator) needs one — so it gets its
    // own dedicated thread, entirely separate from egui's event loop.
    std::thread::spawn(|| {
        gtk::init().expect("gtk init");
        let menu = build_menu();
        let _tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_icon(build_icon())
            .with_tooltip("y2q")
            .build()
            .expect("build tray icon");
        gtk::main();
    });
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
)))]
pub fn build() -> tray_icon::TrayIcon {
    TrayIconBuilder::new()
        .with_menu(Box::new(build_menu()))
        .with_icon(build_icon())
        .with_tooltip("y2q")
        .build()
        .expect("build tray icon")
}
