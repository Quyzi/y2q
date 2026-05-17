use std::collections::VecDeque;
use std::time::{Duration, Instant};

use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph, Sparkline},
};

use crate::output::{fmt_bytes, fmt_speed};
use crate::tui::theme::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferStatus {
    Queued,
    Running,
    Done {
        bytes: u64,
        elapsed: Duration,
        avg_bps: u64,
    },
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
    pub started_at: Option<Instant>,
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
            started_at: None,
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

/// Particle positions (offset from fill head, char glyph).
const PARTICLES: &[(usize, char)] = &[(1, '·'), (3, '∘'), (5, '·'), (8, '⋅'), (11, '·')];

/// Build a particle-animated progress bar as colored ratatui spans.
/// `bar_w` is inner character width (between the brackets).
/// `frame` is an animation counter (use speed_samples.len()).
fn particle_bar_spans(bar_w: usize, ratio: f64, frame: usize) -> Vec<Span<'static>> {
    let fill = ((ratio * bar_w as f64) as usize).min(bar_w);
    let remaining = bar_w.saturating_sub(fill);
    let mut spans = Vec::with_capacity(4);

    if fill > 1 {
        spans.push(Span::styled(
            "█".repeat(fill - 1),
            Style::default().fg(NEON_CYAN),
        ));
    }
    if fill > 0 {
        spans.push(Span::styled(
            "▶",
            Style::default().fg(NEON_PINK).add_modifier(Modifier::BOLD),
        ));
    }
    if remaining > 0 {
        let mut empty: Vec<char> = vec!['░'; remaining];
        for &(base_off, ch) in PARTICLES {
            let pos = (base_off + frame / 2) % remaining.max(1);
            empty[pos] = ch;
        }
        spans.push(Span::styled(
            empty.into_iter().collect::<String>(),
            Style::default().fg(NEON_YELLOW),
        ));
    }
    spans
}

pub fn render(frame: &mut Frame, area: Rect, entries: &[TransferEntry]) {
    let block = Block::default()
        .title(Span::styled(
            " ◆ TRANSFERS ◆ ",
            Style::default().fg(NEON_PINK).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(NEON_PINK));
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
    let queue = entries
        .iter()
        .filter(|e| e.status != TransferStatus::Running)
        .take(3);

    if let Some(entry) = active {
        let bar_row = Rect { height: 1, ..inner };
        let spark_area = Rect {
            y: inner.y + 1,
            height: 1.min(inner.height.saturating_sub(1)),
            ..inner
        };

        let pct = (entry.ratio() * 100.0) as u16;
        let info = format!(
            "  {}  {}  {}",
            entry.label,
            fmt_bytes(entry.bytes_done),
            fmt_speed(entry.current_speed()),
        );
        let info_w = info.chars().count() as u16;
        // [bar] pct%  info
        let bar_w = inner
            .width
            .saturating_sub(info_w)
            .saturating_sub(7) // brackets + " NNN% "
            as usize;

        let anim_frame = entry.speed_samples.len();
        let mut spans = vec![Span::styled("[", Style::default().fg(DIM_BORDER))];
        spans.extend(particle_bar_spans(bar_w, entry.ratio(), anim_frame));
        spans.push(Span::styled("]", Style::default().fg(DIM_BORDER)));
        spans.push(Span::styled(
            format!(" {pct:3}%"),
            Style::default().fg(NEON_GREEN).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(info, Style::default().fg(NORMAL_TEXT)));

        frame.render_widget(Paragraph::new(Line::from(spans)), bar_row);

        if spark_area.height > 0 && !entry.speed_samples.is_empty() {
            let max = entry.speed_samples.iter().copied().max().unwrap_or(1);
            let data: Vec<u64> = entry
                .speed_samples
                .iter()
                .map(|&s| s * 8 / max.max(1))
                .collect();
            let sparkline = Sparkline::default()
                .data(&data)
                .style(Style::default().fg(NEON_PURPLE));
            frame.render_widget(sparkline, spark_area);
        }
    }

    let queue_start = inner.y + if active.is_some() { 2 } else { 0 };
    for (i, entry) in queue.enumerate() {
        let row = queue_start + i as u16;
        if row >= inner.y + inner.height {
            break;
        }
        let row_area = Rect {
            y: row,
            height: 1,
            ..inner
        };
        match &entry.status {
            TransferStatus::Queued => {
                frame.render_widget(
                    Paragraph::new(Line::from(Span::styled(
                        format!("▷ queued  {}", entry.label),
                        Style::default().fg(NEON_YELLOW),
                    ))),
                    row_area,
                );
            }
            TransferStatus::Done {
                bytes,
                elapsed,
                avg_bps,
            } => {
                let secs = elapsed.as_secs_f64();
                let dur_str = if secs < 60.0 {
                    format!("{secs:.1}s")
                } else {
                    format!("{}m{:.0}s", secs as u64 / 60, secs % 60.0)
                };
                let spans = vec![
                    Span::styled(
                        "✓ ",
                        Style::default().fg(NEON_GREEN).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(entry.label.clone(), Style::default().fg(NORMAL_TEXT)),
                    Span::styled("  ", Style::default()),
                    Span::styled(fmt_bytes(*bytes), Style::default().fg(NEON_CYAN)),
                    Span::styled("  in  ", Style::default().fg(DIM_TEXT)),
                    Span::styled(dur_str, Style::default().fg(NEON_YELLOW)),
                    Span::styled("  avg  ", Style::default().fg(DIM_TEXT)),
                    Span::styled(fmt_speed(*avg_bps), Style::default().fg(NEON_GREEN)),
                ];
                frame.render_widget(Paragraph::new(Line::from(spans)), row_area);
            }
            TransferStatus::Failed(e) => {
                frame.render_widget(
                    Paragraph::new(Line::from(Span::styled(
                        format!("✗ failed: {e}"),
                        Style::default().fg(ERROR_RED),
                    ))),
                    row_area,
                );
            }
            TransferStatus::Running => {}
        };
    }
}
