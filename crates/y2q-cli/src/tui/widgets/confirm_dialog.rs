use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
};

pub fn render(frame: &mut Frame, area: Rect, message: &str) {
    let dialog_w = (message.len() as u16 + 6)
        .max(30)
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
        .title(" Confirm ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let text = vec![
        Line::from(Span::raw(message)),
        Line::from(""),
        Line::from(vec![
            Span::styled("[y] Yes  ", Style::default().fg(Color::Green)),
            Span::styled("[n] No", Style::default().fg(Color::Red)),
        ]),
    ];
    let para = Paragraph::new(text)
        .block(block)
        .alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(para, dialog_area);
}
