use std::path::PathBuf;

use directories::BaseDirs;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum LocalEntry {
    Dir(String),
    File { name: String, size: u64 },
}

impl LocalEntry {
    pub fn name(&self) -> &str {
        match self {
            Self::Dir(n) => n,
            Self::File { name, .. } => name,
        }
    }

    #[allow(dead_code)]
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Dir(_))
    }
}

#[derive(Debug)]
pub struct LocalPane {
    pub cwd: PathBuf,
    pub entries: Vec<LocalEntry>,
    pub selected: usize,
    pub scroll: usize,
}

impl LocalPane {
    pub fn new() -> Self {
        let cwd = BaseDirs::new()
            .map(|d| d.home_dir().to_owned())
            .unwrap_or_else(|| PathBuf::from("/"));
        let mut pane = Self { cwd, entries: vec![], selected: 0, scroll: 0 };
        pane.refresh();
        pane
    }

    pub fn refresh(&mut self) {
        self.entries.clear();
        self.entries.push(LocalEntry::Dir("..".into()));
        if let Ok(rd) = std::fs::read_dir(&self.cwd) {
            let mut dirs = vec![];
            let mut files = vec![];
            for entry in rd.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let ft = entry.file_type().ok();
                if ft.as_ref().map(|t| t.is_dir()).unwrap_or(false) {
                    dirs.push(LocalEntry::Dir(name));
                } else {
                    let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    files.push(LocalEntry::File { name, size });
                }
            }
            dirs.sort_by(|a, b| a.name().cmp(b.name()));
            files.sort_by(|a, b| a.name().cmp(b.name()));
            self.entries.extend(dirs);
            self.entries.extend(files);
        }
        self.selected = self.selected.min(self.entries.len().saturating_sub(1));
    }

    pub fn selected_entry(&self) -> Option<&LocalEntry> {
        self.entries.get(self.selected)
    }

    pub fn selected_path(&self) -> Option<PathBuf> {
        self.selected_entry().map(|e| self.cwd.join(e.name()))
    }

    pub fn enter(&mut self) {
        if let Some(entry) = self.selected_entry().cloned() {
            match entry {
                LocalEntry::Dir(ref name) => {
                    let new_cwd = if name == ".." {
                        self.cwd.parent().map(|p| p.to_owned()).unwrap_or_else(|| self.cwd.clone())
                    } else {
                        self.cwd.join(name)
                    };
                    self.cwd = new_cwd;
                    self.selected = 0;
                    self.scroll = 0;
                    self.refresh();
                }
                LocalEntry::File { .. } => {}
            }
        }
    }

    pub fn nav_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
            if self.selected < self.scroll {
                self.scroll = self.selected;
            }
        }
    }

    pub fn nav_down(&mut self, visible_rows: usize) {
        if self.selected + 1 < self.entries.len() {
            self.selected += 1;
            if self.selected >= self.scroll + visible_rows {
                self.scroll = self.selected - visible_rows + 1;
            }
        }
    }
}
