use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

use crate::tui::theme::*;

/// Approximate rendered width (columns) of the bar for a given binding set.
pub fn width(bindings: &[(&str, &str)]) -> usize {
    // " ▓ " lead, per entry " {key} " + " {desc}", " ▸ " separators.
    let mut w = 3;
    for (i, (key, desc)) in bindings.iter().enumerate() {
        if i > 0 {
            w += 3;
        }
        w += key.chars().count() + 2 + desc.chars().count() + 1;
    }
    w
}

pub fn render(frame: &mut Frame, area: Rect, bindings: &[(&str, &str)]) {
    let mut spans: Vec<Span<'_>> = vec![Span::styled(" ▓ ", Style::default().fg(DIM_TEXT))];
    for (i, (key, desc)) in bindings.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" ▸ ", Style::default().fg(DIM_TEXT)));
        }
        spans.push(Span::styled(
            format!(" {key} "),
            Style::default()
                .fg(NEON_CYAN)
                .bg(DIM_BORDER)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!(" {desc}"),
            Style::default().fg(NORMAL_TEXT),
        ));
    }
    // Wrap so a long bar spills onto the reserved second row instead of clipping.
    frame.render_widget(
        Paragraph::new(Line::from(spans)).wrap(Wrap { trim: true }),
        area,
    );
}
