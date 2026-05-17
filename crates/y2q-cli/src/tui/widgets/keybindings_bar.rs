use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

pub fn render(frame: &mut Frame, area: Rect, bindings: &[(&str, &str)]) {
    let spans: Vec<Span<'_>> = bindings
        .iter()
        .flat_map(|(key, desc)| {
            [
                Span::styled(
                    format!(" {key}"),
                    Style::default().fg(Color::Cyan).bg(Color::DarkGray),
                ),
                Span::styled(format!(":{desc} "), Style::default().fg(Color::Gray)),
            ]
        })
        .collect();
    let para = Paragraph::new(Line::from(spans));
    frame.render_widget(para, area);
}
