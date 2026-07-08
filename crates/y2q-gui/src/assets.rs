//! Bundled logo, used as both the window icon and the tray icon.

use std::sync::{Arc, OnceLock};

static LOGO_JPEG: &[u8] = include_bytes!("../../../assets/logo.jpeg");

fn decode() -> image::RgbaImage {
    image::load_from_memory(LOGO_JPEG)
        .expect("assets/logo.jpeg is a valid image")
        .into_rgba8()
}

/// Full-resolution RGBA, suitable for a window/taskbar icon. Cached — this
/// is rebuilt into a `ViewportBuilder` every frame the window is shown, so
/// decoding on every call would burn CPU for no reason.
pub fn window_icon() -> Arc<egui::IconData> {
    static ICON: OnceLock<Arc<egui::IconData>> = OnceLock::new();
    ICON.get_or_init(|| {
        let img = decode();
        Arc::new(egui::IconData {
            width: img.width(),
            height: img.height(),
            rgba: img.into_raw(),
        })
    })
    .clone()
}

/// Downscaled RGBA, suitable for a tray icon (which is rendered tiny —
/// shipping the full-resolution buffer would just waste memory/CPU on
/// every platform's tray backend re-scaling it themselves). Only built once
/// per `TrayManager::new()`, so no caching needed here.
pub fn tray_icon() -> tray_icon::Icon {
    const SIZE: u32 = 64;
    let img = image::imageops::resize(&decode(), SIZE, SIZE, image::imageops::FilterType::Lanczos3);
    tray_icon::Icon::from_rgba(img.into_raw(), SIZE, SIZE).expect("fixed-size icon buffer is valid")
}
