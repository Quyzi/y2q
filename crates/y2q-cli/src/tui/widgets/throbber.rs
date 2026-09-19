use ratatui::style::Style;
use ratatui::text::{Line, Span};

const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Spinner state that only advances while an async op is in flight.
#[derive(Debug, Default)]
pub struct LoadingIndicator {
    frame: usize,
    pub active: bool,
}

impl LoadingIndicator {
    pub fn start(&mut self) {
        self.active = true;
        self.frame = 0;
    }

    pub fn stop(&mut self) {
        self.active = false;
    }

    pub fn tick(&mut self) {
        if self.active {
            self.frame = (self.frame + 1) % FRAMES.len();
        }
    }

    /// Renderable spinner + label for the current frame.
    pub fn line(&self, label: &str, style: Style) -> Line<'static> {
        Line::from(vec![
            Span::styled(FRAMES[self.frame], style),
            Span::styled(label.to_owned(), style),
        ])
    }
}
