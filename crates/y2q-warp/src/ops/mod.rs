pub mod delete;
pub mod get;
pub mod list;
pub mod put;
pub mod stat;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpKind {
    Put,
    Get,
    Delete,
    Stat,
    List,
}

impl OpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Put => "PUT",
            Self::Get => "GET",
            Self::Delete => "DELETE",
            Self::Stat => "STAT",
            Self::List => "LIST",
        }
    }
}

impl std::fmt::Display for OpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
