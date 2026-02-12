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

    #[error("file pattern error: {message}")]
    Pattern { message: String },
}

impl Error {
    pub(crate) fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

impl From<glob::GlobError> for Error {
    fn from(e: glob::GlobError) -> Self {
        Self::Pattern {
            message: e.to_string(),
        }
    }
}

impl From<glob::PatternError> for Error {
    fn from(e: glob::PatternError) -> Self {
        Self::Pattern {
            message: e.to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
