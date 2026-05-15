pub mod users;

use y2q_client::StaleLockEntry;

pub use users::UsersView;

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
