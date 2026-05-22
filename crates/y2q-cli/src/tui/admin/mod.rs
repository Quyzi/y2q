pub mod users;

use std::collections::VecDeque;

use y2q_client::{StaleLockEntry, TraceEvent};

pub use users::UsersView;

/// Parsed Prometheus scrape, reduced to printable `name value` lines.
#[derive(Debug, Default)]
pub struct MetricsView {
    pub lines: Vec<String>,
    pub scroll: usize,
    pub loading: bool,
    pub error: Option<String>,
}

impl MetricsView {
    /// Keep only non-comment, non-empty sample lines (drop `# HELP`/`# TYPE`).
    pub fn set_raw(&mut self, raw: &str) {
        self.lines = raw
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_owned())
            .collect();
        self.loading = false;
        self.error = None;
        self.scroll = self.scroll.min(self.lines.len().saturating_sub(1));
    }

    pub fn nav_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }
    pub fn nav_down(&mut self) {
        if self.scroll + 1 < self.lines.len() {
            self.scroll += 1;
        }
    }
}

/// Rolling buffer of live trace events for the Events admin tab.
#[derive(Debug, Default)]
pub struct EventsView {
    pub events: VecDeque<TraceEvent>,
    pub streaming: bool,
    pub error: Option<String>,
}

impl EventsView {
    pub fn push(&mut self, event: TraceEvent) {
        if self.events.len() >= 200 {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }
}

#[derive(Debug, Default)]
pub struct RebuildView {
    pub state: String,
    pub percent: Option<u8>,
    pub reason: Option<String>,
}

#[derive(Debug, Default)]
pub struct LocksView {
    pub locks: Vec<StaleLockEntry>,
    pub selected: usize,
    pub loading: bool,
}

impl LocksView {
    pub fn nav_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }
    pub fn nav_down(&mut self) {
        if self.selected + 1 < self.locks.len() {
            self.selected += 1;
        }
    }
    #[allow(dead_code)]
    pub fn selected_lock(&self) -> Option<&StaleLockEntry> {
        self.locks.get(self.selected)
    }
}
