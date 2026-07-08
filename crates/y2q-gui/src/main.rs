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

    eframe::run_native(
        "y2q",
        eframe::NativeOptions::default(),
        Box::new(move |cc| Ok(Box::new(app::GuiApp::new(cc, handle)))),
    )
}
