use crate::output::fmt_bytes;
use crate::progress::ProgressReporter;

pub struct PlainProgressReporter {
    label: String,
    total: Option<u64>,
}

impl PlainProgressReporter {
    pub fn new() -> Self {
        Self {
            label: String::new(),
            total: None,
        }
    }
}

impl ProgressReporter for PlainProgressReporter {
    fn start(&mut self, label: &str, total_bytes: Option<u64>) {
        self.label = label.to_owned();
        self.total = total_bytes;
        eprint!("\r{label}  0 B");
    }

    fn update(&mut self, bytes_done: u64, speed_bps: u64) {
        let done = fmt_bytes(bytes_done);
        let speed = fmt_bytes(speed_bps);
        if let Some(total) = self.total {
            let pct = bytes_done * 100 / total.max(1);
            eprint!(
                "\r{}  {done} / {}  {pct}%  {speed}/s",
                self.label,
                fmt_bytes(total)
            );
        } else {
            eprint!("\r{}  {done}  {speed}/s", self.label);
        }
    }

    fn finish(&mut self, bytes_done: u64) {
        eprintln!("\r{}  {}  done", self.label, fmt_bytes(bytes_done));
    }
}
