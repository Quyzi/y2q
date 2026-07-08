mod app;
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

    #[cfg(any(
        target_os = "linux",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    tray::spawn();

    let rt = tokio::runtime::Runtime::new().expect("start tokio runtime");
    let handle = rt.handle().clone();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([480.0, 560.0])
            .with_min_inner_size([360.0, 260.0]),
        ..Default::default()
    };

    eframe::run_native(
        "y2q",
        options,
        Box::new(move |cc| Ok(Box::new(app::GuiApp::new(cc, handle)))),
    )
}
