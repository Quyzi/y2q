//! Authority provisioning: operator-key generation and (with `devices`)
//! device-registry creation through the same library path as
//! `y2q admin device init`.
//!
//! The emergency-code viewer (`CodesWriter`) is reached only through registry
//! creation, which exists only with the `devices` feature; without it that code
//! is intentionally unused.
#![cfg_attr(not(feature = "devices"), allow(dead_code))]

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rand::Rng;
use zeroize::Zeroizing;

use y2q_core::crypto::node_key::{extract_node_key, load_node_key_file};

use super::sys;

/// Write a fresh 32-byte node key to `path` as standard base64 plus a newline
/// (the format of `y2q admin gen-node-key`).
///
/// Created with `create_new` at mode `0400` (never wider, never overwrites),
/// fsynced, chowned when `owner` is given, then read back through
/// [`load_node_key_file`] and compared. The key is never printed.
pub fn generate_key_file(path: &Path, owner: Option<(u32, u32)>) -> Result<(), String> {
    let mut raw = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(&mut *raw);
    let mut text = Zeroizing::new(STANDARD.encode(*raw));
    text.push('\n');

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    // Undo a restrictive-umask surprise in the other direction too: exactly 0400.
    sys::fchmod(&file, 0o400).map_err(|e| format!("chmod {}: {e}", path.display()))?;
    if let Some((uid, gid)) = owner {
        sys::fchown(&file, Some(uid), Some(gid))
            .map_err(|e| format!("chown {}: {e}", path.display()))?;
    }
    drop(file);

    let back = load_node_key_file(&path.to_string_lossy())
        .map_err(|e| format!("read back {}: {e}", path.display()))?;
    if *back != *extract_node_key(&raw[..]) {
        return Err(format!(
            "{} does not read back as the generated key; delete it and retry",
            path.display()
        ));
    }
    Ok(())
}

// --- emergency code sheet ------------------------------------------------------

/// Capacity of the code-sheet buffer. The real sheet is about 780 bytes; a fixed
/// capacity means the buffer never reallocates (and so never leaves an
/// unzeroized copy behind).
const SHEET_CAPACITY: usize = 2048;

type Display = Box<dyn FnMut(&[u8]) -> io::Result<()>>;

/// One-shot `Write` sink for `emergency::init_registry`'s code sheet.
///
/// Bytes collect in a fixed-capacity zeroizing buffer. The first `flush()` —
/// `print_codes` flushes once, before any disk write — hands the sheet to the
/// display function (the alternate-screen viewer) and returns only when the
/// operator confirmed. A display failure aborts registry creation before a
/// registry exists. Later `flush()` calls are no-ops; `write` after the first
/// flush is an error.
pub struct CodesWriter {
    buf: Zeroizing<Vec<u8>>,
    shown: bool,
    display: Display,
}

impl CodesWriter {
    pub fn new() -> Self {
        Self::with_display(Box::new(show_on_terminal))
    }

    pub fn with_display(display: Display) -> Self {
        Self {
            buf: Zeroizing::new(Vec::with_capacity(SHEET_CAPACITY)),
            shown: false,
            display,
        }
    }
}

impl Write for CodesWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.shown {
            return Err(io::Error::other("code sheet already shown"));
        }
        if self.buf.len() + data.len() > SHEET_CAPACITY {
            return Err(io::Error::other("code sheet larger than its buffer"));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.shown {
            return Ok(());
        }
        (self.display)(&self.buf)?;
        self.shown = true;
        Ok(())
    }
}

/// Split `line` into slices of at most `width` columns, breaking at spaces
/// where possible. Slices borrow `line`: no copy of the secret text is made.
fn wrap_slices(line: &str, width: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = line;
    while rest.chars().count() > width {
        let cut = rest
            .char_indices()
            .nth(width)
            .map_or(rest.len(), |(i, _)| i);
        let head = &rest[..cut];
        // Already at a word boundary: keep the whole head line.
        let at = if rest[cut..].starts_with(' ') {
            cut
        } else {
            head.rfind(' ').filter(|i| *i > 0).unwrap_or(cut)
        };
        out.push(&rest[..at]);
        rest = rest[at..].trim_start_matches(' ');
    }
    out.push(rest);
    out
}

const MIN_COLS: u16 = 56;
const READ_DELAY: std::time::Duration = std::time::Duration::from_secs(3);

/// Show the sheet on the alternate screen; wipe it afterwards.
fn show_on_terminal(sheet: &[u8]) -> io::Result<()> {
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;
    use ratatui::style::{Color, Modifier, Style};
    use std::time::{Duration, Instant};

    use super::term::{self, Input, Tui};
    use ratatui::crossterm::event::{KeyCode, KeyEventKind};

    let text = Zeroizing::new(
        std::str::from_utf8(sheet)
            .map_err(|_| io::Error::other("code sheet is not UTF-8"))?
            .to_owned(),
    );
    sys::tcflush_stdin();
    let mut tui = Tui::enter()?;
    let mut shown_at: Option<Instant> = None;
    let bold = Style::default().add_modifier(Modifier::BOLD);
    let red = Style::default().fg(Color::Red);
    loop {
        let (cols, rows) = tui.size()?;
        let width = usize::from(cols.saturating_sub(2)).max(1);
        let lines: Vec<&str> = text.lines().flat_map(|l| wrap_slices(l, width)).collect();
        let need = u16::try_from(lines.len() + 3).unwrap_or(u16::MAX);
        let fits = cols >= MIN_COLS && rows >= need;
        if fits && shown_at.is_none() {
            shown_at = Some(Instant::now());
        }
        let wait = shown_at
            .map(|t| READ_DELAY.saturating_sub(t.elapsed()))
            .unwrap_or(READ_DELAY);
        tui.draw(|f| {
            let area: Rect = f.area();
            let buf: &mut Buffer = f.buffer_mut();
            if !fits {
                buf.set_string(
                    0,
                    0,
                    format!("enlarge the terminal (need {MIN_COLS}x{need})"),
                    red,
                );
                return;
            }
            for (i, l) in lines.iter().enumerate() {
                let style = if i == 0 { bold } else { Style::default() };
                buf.set_string(1, u16::try_from(i).unwrap_or(0), l, style);
            }
            let footer = if wait.is_zero() {
                "Press Enter to continue".to_owned()
            } else {
                format!(
                    "Press Enter to continue (available in {} s)",
                    wait.as_secs() + 1
                )
            };
            buf.set_string(1, area.height.saturating_sub(1), footer, bold);
        })?;
        match term::read_input(Some(Duration::from_millis(250)))? {
            Input::Key(k)
                if k.kind == KeyEventKind::Press
                    && k.code == KeyCode::Enter
                    && fits
                    && shown_at.is_some_and(|t| t.elapsed() >= READ_DELAY) =>
            {
                break;
            }
            _ => {}
        }
    }
    // Overwrite the frame, erase the screen (and scrollback only on terminals
    // where setup's own output could sit there), then hand the terminal back.
    tui.draw(|_| {})?;
    tui.clear_screen_and_scrollback(term::term_needs_scrollback_wipe())?;
    tui.leave()?;
    drop(tui);
    Ok(())
}

// --- device registry -----------------------------------------------------------

#[cfg(feature = "devices")]
pub struct SetupPins;

#[cfg(feature = "devices")]
impl y2q_core::crypto::devices::PinProvider for SetupPins {
    fn pin(&self, label: &str) -> Result<Zeroizing<String>, y2q_core::crypto::CryptoError> {
        rpassword::prompt_password(format!("PIN for away device '{label}': "))
            .map(Zeroizing::new)
            .map_err(|e| y2q_core::crypto::CryptoError::DeviceBackend(format!("pin prompt: {e}")))
    }
}

/// What registry creation did, for the summary.
#[cfg(feature = "devices")]
pub struct RegistryOutcome {
    pub registry_path: std::path::PathBuf,
    pub device_label: String,
    pub device_id: String,
}

/// Why registry creation stopped, and whether `devices.json` now exists (then
/// the codes shown are valid).
#[cfg(feature = "devices")]
pub struct RegistryFailure {
    pub message: String,
    pub registry_exists: bool,
}

/// Create the registry. The caller has already run `harden_process`; the two
/// locks are taken here and held across the call. A running daemon surfaces as
/// the flock error.
#[cfg(feature = "devices")]
pub fn create_registry(
    keystore_dir: &Path,
    n: &super::answers::NewRegistryAnswers,
    tcti: &str,
    now: u64,
) -> Result<RegistryOutcome, RegistryFailure> {
    use super::answers::FirstKind;
    use y2q_core::crypto::devices::provision::{self, FirstDevice, InitRequest};
    use y2q_core::crypto::devices::registry;
    use y2q_core::crypto::keystore;

    let fail = |message: String| RegistryFailure {
        message,
        registry_exists: registry::exists(keystore_dir),
    };
    let adopt = match n.adopt_key_file.as_deref().filter(|f| !f.is_empty()) {
        Some(file) => {
            Some(load_node_key_file(file).map_err(|e| fail(format!("node key file {file}: {e}")))?)
        }
        None => None,
    };
    let _lock = keystore::acquire_lock(keystore_dir).map_err(|e| {
        fail(format!(
            "{e}; stop the daemon first — registry creation needs exclusive access to the keystore"
        ))
    })?;
    let _reg_lock = registry::lock_registry(keystore_dir).map_err(|e| fail(e.to_string()))?;
    let first = match n.first {
        FirstKind::Tpm => FirstDevice::Tpm {
            label: n.label.clone().filter(|l| !l.is_empty()),
            tcti,
            pcrs: &n.pcrs,
        },
        FirstKind::Fido2 => FirstDevice::Fido2 {
            label: n.label.clone().filter(|l| !l.is_empty()),
            uv_required: n.uv_required,
            hid_path: n.hid_path.as_deref().filter(|p| !p.is_empty()),
        },
    };
    let mut writer = CodesWriter::new();
    let report = provision::init(
        &InitRequest {
            dir: keystore_dir,
            first,
            away_grant_seconds: n.away_grant_seconds,
            adopt: adopt.as_deref(),
        },
        &SetupPins,
        now,
        &mut writer,
    )
    .map_err(|e| fail(e.to_string()))?;
    Ok(RegistryOutcome {
        registry_path: report.registry_path,
        device_label: report.device_label,
        device_id: report.device_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn generated_key_is_0400_45_bytes_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        generate_key_file(&path, None).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o7777, 0o400);
        assert_eq!(meta.len(), 45);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.ends_with('\n'));
        let raw = STANDARD.decode(text.trim()).unwrap();
        assert_eq!(raw.len(), 32);
        let loaded = load_node_key_file(path.to_str().unwrap()).unwrap();
        assert_eq!(*loaded, *extract_node_key(&raw));
    }

    #[test]
    fn generation_never_overwrites_or_follows_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        std::fs::write(&path, "keep").unwrap();
        assert!(generate_key_file(&path, None).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path().join("target"), &link).unwrap();
        assert!(generate_key_file(&link, None).is_err());
        assert!(!dir.path().join("target").exists());
    }

    #[test]
    fn generated_keys_differ() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        generate_key_file(&a, None).unwrap();
        generate_key_file(&b, None).unwrap();
        assert_ne!(
            std::fs::read_to_string(a).unwrap(),
            std::fs::read_to_string(b).unwrap()
        );
    }

    #[test]
    fn codes_writer_rejects_overflow_and_write_after_flush() {
        let shown = std::rc::Rc::new(std::cell::RefCell::new(Vec::<u8>::new()));
        let sink = shown.clone();
        let mut w = CodesWriter::with_display(Box::new(move |b| {
            sink.borrow_mut().extend_from_slice(b);
            Ok(())
        }));
        w.write_all(b"line one\n").unwrap();
        assert!(w.write_all(&vec![b'x'; SHEET_CAPACITY]).is_err());
        w.flush().unwrap();
        assert_eq!(&shown.borrow()[..], b"line one\n");
        // Second flush is a no-op: nothing is shown twice.
        w.flush().unwrap();
        assert_eq!(shown.borrow().len(), 9);
        assert!(w.write_all(b"late").is_err());
    }

    #[test]
    fn codes_writer_display_failure_propagates_and_can_retry_nothing() {
        let mut w = CodesWriter::with_display(Box::new(|_| Err(io::Error::other("no tty"))));
        w.write_all(b"codes").unwrap();
        assert!(w.flush().is_err());
    }

    #[test]
    fn wrap_slices_breaks_on_spaces_and_borrows() {
        let line = "aaaa bbbb cccc dddd";
        let parts = wrap_slices(line, 9);
        assert_eq!(parts, ["aaaa bbbb", "cccc dddd"]);
        assert_eq!(wrap_slices("short", 20), ["short"]);
        let long = "x".repeat(25);
        assert_eq!(wrap_slices(&long, 10).len(), 3);
    }
}
