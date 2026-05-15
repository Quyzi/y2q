use y2q_client::UserView;

#[derive(Debug, Default)]
pub struct UsersView {
    pub users: Vec<UserView>,
    pub selected: usize,
    pub loading: bool,
}

impl UsersView {
    pub fn set_users(&mut self, users: Vec<UserView>) {
        self.users = users;
        self.loading = false;
        self.selected = self.selected.min(self.users.len().saturating_sub(1));
    }

    pub fn nav_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn nav_down(&mut self) {
        if self.selected + 1 < self.users.len() {
            self.selected += 1;
        }
    }

    #[allow(dead_code)]
    pub fn selected_username(&self) -> Option<&str> {
        self.users.get(self.selected).map(|u| u.username.as_str())
    }
}
