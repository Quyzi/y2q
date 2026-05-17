use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::tui::theme::*;

pub fn render(frame: &mut Frame, area: Rect, bindings: &[(&str, &str)]) {
    let mut spans: Vec<Span<'_>> = vec![Span::styled(
        " ▓ ",
        Style::default().fg(DIM_TEXT),
    )];
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
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}
