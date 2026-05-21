use std::collections::VecDeque;
use std::io::Write;

use crossterm::{
    cursor, execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
    terminal::{Clear, ClearType},
};

use crate::output::fmt_bytes;
use crate::progress::ProgressReporter;

const NEON_PINK: Color = Color::Rgb {
    r: 255,
    g: 20,
    b: 147,
};
const NEON_CYAN: Color = Color::Rgb {
    r: 0,
    g: 255,
    b: 255,
};
const NEON_GREEN: Color = Color::Rgb {
    r: 57,
    g: 255,
    b: 20,
};
const NEON_YELLOW: Color = Color::Rgb {
    r: 255,
    g: 215,
    b: 0,
};
const NEON_PURPLE: Color = Color::Rgb {
    r: 188,
    g: 0,
    b: 255,
};
const DIM: Color = Color::Rgb {
    r: 50,
    g: 50,
    b: 80,
};
const NORMAL: Color = Color::Rgb {
    r: 200,
    g: 210,
    b: 255,
};

/// Particle offsets from fill head (offset, glyph).
const PARTICLES: &[(usize, &str)] = &[(1, "·"), (3, "∘"), (5, "·"), (8, "⋅"), (11, "·")];

pub struct TuiProgressReporter {
    label: String,
    total: Option<u64>,
    samples: VecDeque<u64>,
}

impl TuiProgressReporter {
    pub fn new() -> Self {
        Self {
            label: String::new(),
            total: None,
            samples: VecDeque::with_capacity(60),
        }
    }

    fn render(&self, bytes_done: u64, speed_bps: u64) {
        let mut stderr = std::io::stderr();
        let term_width = crossterm::terminal::size()
            .map(|(w, _)| w as usize)
            .unwrap_or(80)
            .max(30);

        let bar_width: usize = 28;
        let fill = if let Some(total) = self.total {
            (bytes_done as f64 / total.max(1) as f64 * bar_width as f64) as usize
        } else {
            0
        };
        let remaining = bar_width.saturating_sub(fill);
        let frame = self.samples.len();

        let pct_str = self
            .total
            .map(|t| format!(" {:3}%", bytes_done * 100 / t.max(1)))
            .unwrap_or_default();
        let done_str = fmt_bytes(bytes_done);
        let speed_str = fmt_bytes(speed_bps);

        // Build particle empty zone
        let mut empty_chars: Vec<&str> = vec!["░"; remaining];
        if remaining > 0 {
            for &(base_off, ch) in PARTICLES {
                let pos = (base_off + frame / 2) % remaining;
                empty_chars[pos] = ch;
            }
        }

        // Budget sparkline width to whatever fits after the rest of the line.
        let label_str = format!("{}: ", self.label);
        let stats_str = format!("  {done_str}  {speed_str}/s  ");
        let fixed_visible = label_str.chars().count()
            + 1 // "["
            + bar_width
            + 1 // "]"
            + pct_str.chars().count()
            + stats_str.chars().count();
        let spark_budget = term_width.saturating_sub(fixed_visible + 1);
        let spark_take = spark_budget.min(20);
        let sparkline: String = self
            .samples
            .iter()
            .rev()
            .take(spark_take)
            .rev()
            .map(|&s| {
                let max = self.samples.iter().copied().max().unwrap_or(1);
                let idx = (s as f64 / max as f64 * 7.0) as usize;
                ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"][idx.min(7)]
            })
            .collect();

        let _ = execute!(
            stderr,
            cursor::MoveToColumn(0),
            Clear(ClearType::UntilNewLine),
        );

        // Label
        let _ = execute!(
            stderr,
            SetForegroundColor(NEON_PINK),
            Print(&label_str),
            ResetColor,
        );

        // Opening bracket
        let _ = execute!(stderr, SetForegroundColor(DIM), Print("["), ResetColor);

        // Solid fill
        if fill > 1 {
            let _ = execute!(
                stderr,
                SetForegroundColor(NEON_CYAN),
                Print("█".repeat(fill - 1)),
                ResetColor,
            );
        }

        // Leading edge
        if fill > 0 {
            let _ = execute!(
                stderr,
                SetForegroundColor(NEON_PINK),
                Print("▶"),
                ResetColor,
            );
        }

        // Particle zone
        if remaining > 0 {
            let _ = execute!(stderr, SetForegroundColor(NEON_YELLOW));
            for ch in &empty_chars {
                let _ = execute!(stderr, Print(ch));
            }
            let _ = execute!(stderr, ResetColor);
        }

        // Closing bracket + stats
        let _ = execute!(
            stderr,
            SetForegroundColor(DIM),
            Print("]"),
            ResetColor,
            SetForegroundColor(NEON_GREEN),
            Print(&pct_str),
            ResetColor,
            SetForegroundColor(NORMAL),
            Print(&stats_str),
            ResetColor,
            SetForegroundColor(NEON_PURPLE),
            Print(&sparkline),
            ResetColor,
        );

        let _ = stderr.flush();
    }
}

impl ProgressReporter for TuiProgressReporter {
    fn start(&mut self, label: &str, total_bytes: Option<u64>) {
        self.label = label.to_owned();
        self.total = total_bytes;
        let mut stderr = std::io::stderr();
        let _ = execute!(
            stderr,
            SetForegroundColor(NEON_PINK),
            Print(format!("{label}: ")),
            ResetColor,
            SetForegroundColor(NEON_CYAN),
            Print("initialising…"),
            ResetColor,
        );
        let _ = stderr.flush();
    }

    fn update(&mut self, bytes_done: u64, speed_bps: u64) {
        if self.samples.len() >= 60 {
            self.samples.pop_front();
        }
        self.samples.push_back(speed_bps);
        self.render(bytes_done, speed_bps);
    }

    fn finish(&mut self, bytes_done: u64) {
        let speed = self.samples.back().copied().unwrap_or(0);
        self.render(bytes_done, speed);
        let mut stderr = std::io::stderr();
        let _ = execute!(
            stderr,
            Print("  "),
            SetForegroundColor(NEON_GREEN),
            Print("✓ done"),
            ResetColor,
        );
        eprintln!();
    }
}
