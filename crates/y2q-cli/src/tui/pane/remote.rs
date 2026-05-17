use y2q_client::MetadataView;

#[derive(Debug, Clone)]
pub enum RemoteLevel {
    Aliases,
    Buckets {
        alias: String,
    },
    Objects {
        alias: String,
        bucket: String,
        prefix: Option<String>,
    },
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum RemoteEntry {
    Alias(String),
    Bucket(String),
    Dir(String),
    Object(Box<MetadataView>),
    Back,
}

impl RemoteEntry {
    pub fn display_name(&self) -> String {
        match self {
            Self::Alias(a) => format!("{a}/"),
            Self::Bucket(b) => format!("{b}/"),
            Self::Dir(d) => format!("{d}/"),
            Self::Object(m) => m.key.clone(),
            Self::Back => "..".into(),
        }
    }

    #[allow(dead_code)]
    pub fn is_dir_like(&self) -> bool {
        matches!(
            self,
            Self::Alias(_) | Self::Bucket(_) | Self::Dir(_) | Self::Back
        )
    }
}

#[derive(Debug)]
pub struct RemotePane {
    pub level: RemoteLevel,
    pub entries: Vec<RemoteEntry>,
    pub selected: usize,
    pub scroll: usize,
    pub loading: bool,
    pub aliases: Vec<String>,
}

impl RemotePane {
    pub fn new(aliases: Vec<String>) -> Self {
        let entries: Vec<RemoteEntry> = aliases
            .iter()
            .map(|a| RemoteEntry::Alias(a.clone()))
            .collect();
        Self {
            level: RemoteLevel::Aliases,
            entries,
            selected: 0,
            scroll: 0,
            loading: false,
            aliases,
        }
    }

    pub fn selected_entry(&self) -> Option<&RemoteEntry> {
        self.entries.get(self.selected)
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

    pub fn go_back(&mut self) {
        match &self.level.clone() {
            RemoteLevel::Aliases => {}
            RemoteLevel::Buckets { .. } => {
                self.level = RemoteLevel::Aliases;
                self.entries = self
                    .aliases
                    .iter()
                    .map(|a| RemoteEntry::Alias(a.clone()))
                    .collect();
                self.selected = 0;
                self.scroll = 0;
            }
            RemoteLevel::Objects { alias, .. } => {
                self.level = RemoteLevel::Buckets {
                    alias: alias.clone(),
                };
                self.entries = vec![RemoteEntry::Back];
                self.loading = true;
                self.selected = 0;
                self.scroll = 0;
            }
        }
    }

    pub fn set_buckets(&mut self, alias: &str, buckets: Vec<String>) {
        self.loading = false;
        self.level = RemoteLevel::Buckets {
            alias: alias.to_owned(),
        };
        let mut entries = vec![RemoteEntry::Back];
        entries.extend(buckets.into_iter().map(RemoteEntry::Bucket));
        self.entries = entries;
        self.selected = 0;
        self.scroll = 0;
    }

    pub fn set_objects(&mut self, alias: &str, bucket: &str, items: Vec<MetadataView>) {
        self.loading = false;
        self.level = RemoteLevel::Objects {
            alias: alias.to_owned(),
            bucket: bucket.to_owned(),
            prefix: None,
        };
        let mut entries = vec![RemoteEntry::Back];
        entries.extend(items.into_iter().map(|m| RemoteEntry::Object(Box::new(m))));
        self.entries = entries;
        self.selected = 0;
        self.scroll = 0;
    }

    pub fn title(&self) -> String {
        match &self.level {
            RemoteLevel::Aliases => "Remote".into(),
            RemoteLevel::Buckets { alias } => format!("Remote ({alias})"),
            RemoteLevel::Objects { alias, bucket, .. } => {
                format!("Remote ({alias}/{bucket})")
            }
        }
    }
}
