use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
};

use crate::tui::theme::*;

pub fn render(frame: &mut Frame, area: Rect, message: &str) {
    let dialog_w = (message.len() as u16 + 6)
        .max(34)
        .min(area.width.saturating_sub(4));
    let dialog_h = 5u16;
    let x = area.x + (area.width.saturating_sub(dialog_w)) / 2;
    let y = area.y + (area.height.saturating_sub(dialog_h)) / 2;
    let dialog_area = Rect {
        x,
        y,
        width: dialog_w,
        height: dialog_h,
    };

    frame.render_widget(Clear, dialog_area);
    let block = Block::default()
        .title(Span::styled(
            " ⚠ CONFIRM ",
            Style::default()
                .fg(NEON_YELLOW)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(NEON_YELLOW));

    let text = vec![
        Line::from(Span::styled(message, Style::default().fg(NORMAL_TEXT))),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " [y] YES ",
                Style::default().fg(NEON_GREEN).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  ", Style::default()),
            Span::styled(
                " [n] NO ",
                Style::default().fg(ERROR_RED).add_modifier(Modifier::BOLD),
            ),
        ]),
    ];
    let para = Paragraph::new(text)
        .block(block)
        .alignment(Alignment::Center);
    frame.render_widget(para, dialog_area);
}
