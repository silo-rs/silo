use std::io;

use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("not inside a git repository")]
    NotGitRepo,

    #[error("silo bind library not found (run `silo doctor` to diagnose, or set SILO_BIND_LIB)")]
    BindLibNotFound,

    #[error("{context}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },

    #[error("command failed: {command}")]
    CommandFailed { command: String },
}

impl Error {
    pub(crate) fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
