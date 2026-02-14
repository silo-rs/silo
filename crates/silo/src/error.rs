use std::io;

use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum Error {
    #[error("not inside a git repository")]
    NotGitRepo,

    #[error("{context}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },

    #[error("command failed: {command}")]
    CommandFailed { command: String },

    #[error("ip override {0} is not in 127.0.0.0/8")]
    InvalidIpOverride(std::net::Ipv4Addr),

    #[error("hosts validation: {0}")]
    HostsValidation(String),

    #[error("{0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),
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
