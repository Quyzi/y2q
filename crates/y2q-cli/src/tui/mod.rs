mod actions;
mod admin;
mod app;
mod events;
mod pane;
mod state;
pub mod theme;
mod ui;
mod widgets;

use std::io::stdout;
use std::time::Duration;

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, EventStream},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use futures::StreamExt;
use ratatui::{Terminal, backend::CrosstermBackend};
use tokio::sync::mpsc;
use tokio::time::interval;

use crate::config::CliConfig;
use crate::error::CliError;

use self::app::App;
use self::events::Event;

pub async fn run_tui(config: CliConfig) -> Result<(), CliError> {
    // Ensure terminal is restored on panic
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
        prev_hook(info);
    }));

    enable_raw_mode().map_err(CliError::Io)?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture).map_err(CliError::Io)?;

    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend).map_err(CliError::Io)?;

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();
    let mut app = App::new(config, event_tx.clone());

    // Event pump: forwards crossterm events + tick/render pulses into the channel
    let pump_tx = event_tx;
    tokio::spawn(async move {
        let mut stream = EventStream::new();
        let mut tick = interval(Duration::from_millis(250));
        let mut render_tick = interval(Duration::from_millis(16)); // ~60 fps

        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let _ = pump_tx.send(Event::Tick);
                }
                _ = render_tick.tick() => {
                    let _ = pump_tx.send(Event::Render);
                }
                maybe = stream.next() => {
                    let Some(Ok(ev)) = maybe else { break };
                    use crossterm::event::Event as CEvent;
                    let mapped = match ev {
                        CEvent::Key(k)       => Event::Key(k),
                        CEvent::Mouse(m)     => Event::Mouse(m),
                        CEvent::Resize(w, h) => Event::Resize(w, h),
                        CEvent::FocusGained  => Event::FocusGained,
                        CEvent::FocusLost    => Event::FocusLost,
                        _                    => continue,
                    };
                    let _ = pump_tx.send(mapped);
                }
            }
        }
    });

    loop {
        let Some(event) = event_rx.recv().await else {
            break;
        };
        let is_render = matches!(event, Event::Render);
        app.update(event);
        if app.should_quit {
            break;
        }
        if is_render {
            terminal
                .draw(|frame| ui::render(frame, &mut app))
                .map_err(CliError::Io)?;
        }
    }

    // Restore terminal state
    disable_raw_mode().map_err(CliError::Io)?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .map_err(CliError::Io)?;
    terminal.show_cursor().map_err(CliError::Io)?;

    Ok(())
}
