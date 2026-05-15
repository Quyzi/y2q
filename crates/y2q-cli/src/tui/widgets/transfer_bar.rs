use std::collections::VecDeque;

use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph, Sparkline},
    Frame,
};

use crate::output::{fmt_bytes, fmt_speed};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferStatus {
    Queued,
    Running,
    Done,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct TransferEntry {
    pub id: u64,
    pub label: String,
    pub total_bytes: Option<u64>,
    pub bytes_done: u64,
    pub speed_samples: VecDeque<u64>,
    pub status: TransferStatus,
}

impl TransferEntry {
    pub fn new(id: u64, label: String, total_bytes: Option<u64>) -> Self {
        Self {
            id,
            label,
            total_bytes,
            bytes_done: 0,
            speed_samples: VecDeque::with_capacity(60),
            status: TransferStatus::Queued,
        }
    }

    pub fn current_speed(&self) -> u64 {
        self.speed_samples.back().copied().unwrap_or(0)
    }

    pub fn ratio(&self) -> f64 {
        match self.total_bytes {
            Some(total) if total > 0 => (self.bytes_done as f64 / total as f64).min(1.0),
            _ => 0.0,
        }
    }
}

pub fn render(frame: &mut Frame, area: Rect, entries: &[TransferEntry]) {
    let block = Block::default()
        .title(" Transfers ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    frame.render_widget(block, area);
    let inner = Rect {
        x: area.x + 1,
        y: area.y + 1,
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    };
    if inner.height == 0 || inner.width == 0 {
        return;
    }

    let active = entries.iter().find(|e| e.status == TransferStatus::Running);
    let queue = entries.iter().filter(|e| e.status != TransferStatus::Running).take(3);

    if let Some(entry) = active {
        let gauge_area = Rect { height: 1, ..inner };
        let spark_area = Rect { y: inner.y + 1, height: 1.min(inner.height.saturating_sub(1)), ..inner };

        let pct = (entry.ratio() * 100.0) as u16;
        let label = format!(
            " {} — {} / {}  {}",
            entry.label,
            fmt_bytes(entry.bytes_done),
            entry.total_bytes.map(fmt_bytes).unwrap_or_else(|| "?".into()),
            fmt_speed(entry.current_speed()),
        );
        let gauge = Gauge::default()
            .gauge_style(Style::default().fg(Color::Cyan).bg(Color::DarkGray))
            .percent(pct)
            .label(label);
        frame.render_widget(gauge, gauge_area);

        if spark_area.height > 0 && !entry.speed_samples.is_empty() {
            let max = entry.speed_samples.iter().copied().max().unwrap_or(1);
            let data: Vec<u64> = entry.speed_samples.iter().map(|&s| s * 8 / max.max(1)).collect();
            let sparkline = Sparkline::default()
                .data(&data)
                .style(Style::default().fg(Color::Green));
            frame.render_widget(sparkline, spark_area);
        }
    }

    let queue_start = inner.y + if active.is_some() { 2 } else { 0 };
    for (i, entry) in queue.enumerate() {
        let row = queue_start + i as u16;
        if row >= inner.y + inner.height {
            break;
        }
        let area = Rect { y: row, height: 1, ..inner };
        let (icon, color) = match &entry.status {
            TransferStatus::Queued => ("▶ queued", Color::Yellow),
            TransferStatus::Done => ("✓ done  ", Color::Green),
            TransferStatus::Failed(e) => {
                let text = format!("✗ failed: {e}");
                let para =
                    Paragraph::new(Line::from(vec![Span::styled(text, Style::default().fg(Color::Red))]));
                frame.render_widget(para, area);
                continue;
            }
            TransferStatus::Running => continue,
        };
        let text = format!("{icon}  {}", entry.label);
        let para = Paragraph::new(Line::from(vec![Span::styled(
            text,
            Style::default().fg(color),
        )]));
        frame.render_widget(para, area);
    }
}
