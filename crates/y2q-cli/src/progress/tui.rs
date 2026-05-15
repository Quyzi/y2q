use std::collections::VecDeque;
use std::io::Write;

use crossterm::{
    cursor, execute,
    style::{Color, Print, SetForegroundColor},
    terminal::{Clear, ClearType},
};

use crate::output::fmt_bytes;
use crate::progress::ProgressReporter;

pub struct TuiProgressReporter {
    label: String,
    total: Option<u64>,
    samples: VecDeque<u64>,
}

impl TuiProgressReporter {
    pub fn new() -> Self {
        Self { label: String::new(), total: None, samples: VecDeque::with_capacity(60) }
    }

    fn render(&self, bytes_done: u64, speed_bps: u64) {
        let mut stderr = std::io::stderr();

        let bar_width: usize = 30;
        let filled = if let Some(total) = self.total {
            (bytes_done as f64 / total.max(1) as f64 * bar_width as f64) as usize
        } else {
            0
        };
        let bar: String = format!(
            "[{}{}]",
            "█".repeat(filled),
            "░".repeat(bar_width - filled)
        );

        let pct = self.total.map(|t| format!(" {:3}%", bytes_done * 100 / t.max(1))).unwrap_or_default();
        let done_str = fmt_bytes(bytes_done);
        let speed_str = fmt_bytes(speed_bps);

        let sparkline: String = self
            .samples
            .iter()
            .rev()
            .take(20)
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
            Clear(ClearType::CurrentLine),
            SetForegroundColor(Color::Cyan),
            Print(format!("{}: ", self.label)),
            SetForegroundColor(Color::Reset),
            Print(format!("{bar}{pct}  {done_str}  {speed_str}/s  {sparkline}")),
        );
        let _ = stderr.flush();
    }
}

impl ProgressReporter for TuiProgressReporter {
    fn start(&mut self, label: &str, total_bytes: Option<u64>) {
        self.label = label.to_owned();
        self.total = total_bytes;
        eprint!("\r{label}  starting...");
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
        eprintln!();
    }
}
