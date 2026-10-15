//! Terminal guard and keyboard input for the setup TUI.
//!
//! [`Tui`] owns raw mode and the alternate screen and gives both back on
//! `leave`, on drop and, through a chained panic hook, on panic. No mouse
//! capture: the operator keeps native selection and paste.

use std::io::{self, Stdout, Write};
use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::cursor::Show;
pub use ratatui::crossterm::event::KeyEvent;
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

/// True while some [`Tui`] has the terminal in raw mode on the alternate
/// screen. The panic hook restores the terminal only then, so a panic after
/// the screen was handed back does not emit stray escape sequences.
static ACTIVE: AtomicBool = AtomicBool::new(false);
static HOOK: Once = Once::new();

/// Chain a panic hook that restores the terminal before the previous hook
/// prints its message (which would otherwise land on the alternate screen).
fn install_panic_hook() {
    HOOK.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if ACTIVE.swap(false, Ordering::SeqCst) {
                let _ = restore();
            }
            prev(info);
        }));
    });
}

/// Give the terminal back: leave raw mode, leave the alternate screen, show
/// the cursor. Attempts every step and reports the first error.
fn restore() -> io::Result<()> {
    let raw = disable_raw_mode();
    let screen = execute!(io::stdout(), LeaveAlternateScreen, Show);
    raw.and(screen)
}

/// Raw-mode alternate-screen terminal. Dropping it restores the terminal.
pub struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    active: bool,
}

impl Tui {
    /// Enter raw mode and the alternate screen.
    pub fn enter() -> io::Result<Tui> {
        install_panic_hook();
        enable_raw_mode()?;
        ACTIVE.store(true, Ordering::SeqCst);
        let terminal = execute!(io::stdout(), EnterAlternateScreen)
            .and_then(|()| Terminal::new(CrosstermBackend::new(io::stdout())));
        match terminal {
            Ok(terminal) => Ok(Tui {
                terminal,
                active: true,
            }),
            Err(e) => {
                ACTIVE.store(false, Ordering::SeqCst);
                let _ = restore();
                Err(e)
            }
        }
    }

    /// Restore the terminal. Idempotent.
    pub fn leave(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        ACTIVE.store(false, Ordering::SeqCst);
        restore()
    }

    /// Render one frame.
    pub fn draw<F: FnOnce(&mut Frame)>(&mut self, f: F) -> io::Result<()> {
        self.terminal.draw(f).map(|_| ())
    }

    /// Send `ESC[2J` (and `ESC[3J`, which erases the scrollback, only when
    /// `wipe_scrollback`) and home the cursor. Used after showing one-time
    /// secrets; the caller draws a blank frame first so ratatui's own buffer no
    /// longer holds them. Deliberately not `Terminal::clear`, which asks the
    /// terminal for the cursor position and fails when no reply arrives.
    pub fn clear_screen_and_scrollback(&mut self, wipe_scrollback: bool) -> io::Result<()> {
        let out = self.terminal.backend_mut();
        out.write_all(b"\x1b[2J")?;
        if wipe_scrollback {
            out.write_all(b"\x1b[3J")?;
        }
        out.write_all(b"\x1b[H")?;
        out.flush()
    }

    /// Terminal size as `(columns, rows)`.
    pub fn size(&self) -> io::Result<(u16, u16)> {
        let size = self.terminal.size()?;
        Ok((size.width, size.height))
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = self.leave();
    }
}

/// One thing the wizard can wake up for.
#[derive(Debug)]
pub enum Input {
    Key(KeyEvent),
    Resize,
    Timeout,
}

/// Block for the next event. `timeout = None` waits forever. Only key
/// presses are returned (repeat and release events are skipped); a resize is
/// [`Input::Resize`]; mouse, focus and paste events are ignored.
pub fn read_input(timeout: Option<Duration>) -> io::Result<Input> {
    let deadline = timeout.map(|t| Instant::now() + t);
    loop {
        if let Some(deadline) = deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if !event::poll(remaining)? {
                return Ok(Input::Timeout);
            }
        }
        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => return Ok(Input::Key(key)),
            Event::Resize(..) => return Ok(Input::Resize),
            _ => {}
        }
    }
}

/// Whether `TERM` names a terminal (`linux` console, `dumb`) where clearing
/// the screen alone leaves secrets recoverable from scrollback that setup
/// itself drew, so `ESC[3J` is also needed.
pub fn term_needs_scrollback_wipe() -> bool {
    scrollback_wipe_for(std::env::var("TERM").ok().as_deref())
}

fn scrollback_wipe_for(term: Option<&str>) -> bool {
    matches!(term, Some("linux" | "dumb"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrollback_wipe_only_for_linux_and_dumb() {
        assert!(scrollback_wipe_for(Some("linux")));
        assert!(scrollback_wipe_for(Some("dumb")));
        assert!(!scrollback_wipe_for(Some("xterm-256color")));
        assert!(!scrollback_wipe_for(Some("linux-16color")));
        assert!(!scrollback_wipe_for(Some("")));
        assert!(!scrollback_wipe_for(None));
    }
}
