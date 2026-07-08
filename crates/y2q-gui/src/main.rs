mod app;
mod assets;
mod events;
mod mount_backend;
mod tray;

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let rt = tokio::runtime::Runtime::new().expect("start tokio runtime");
    let handle = rt.handle().clone();

    // The root viewport is a persistent controller, not the user-facing
    // window — the actual alias-manager UI is a child viewport GuiApp
    // creates/destroys on demand (see app.rs's `show_window`), since
    // hiding/minimizing an existing window turned out not to be reliable on
    // every platform. Made as unobtrusive as the ViewportBuilder API allows;
    // on some Wayland compositors it may still show as a barely-visible
    // sliver since programmatic hide isn't fully honored there.
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_icon(assets::window_icon())
            .with_app_id("y2q")
            .with_visible(false)
            .with_inner_size([1.0, 1.0])
            .with_decorations(false)
            .with_transparent(true)
            .with_taskbar(false)
            .with_mouse_passthrough(true)
            .with_active(false),
        ..Default::default()
    };

    eframe::run_native(
        "y2q",
        options,
        Box::new(move |cc| Ok(Box::new(app::GuiApp::new(cc, handle)))),
    )
}
