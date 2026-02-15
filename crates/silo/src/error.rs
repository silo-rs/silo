use std::borrow::Cow;
use std::io;

use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
#[error("{context}")]
pub struct IoError {
    pub context: Cow<'static, str>,
    #[source]
    pub source: io::Error,
}

impl IoError {
    pub(crate) fn new(context: impl Into<Cow<'static, str>>, source: io::Error) -> Self {
        Self {
            context: context.into(),
            source,
        }
    }
}

#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum ResolveError {
    #[error("not inside a git repository")]
    NotGitRepo,

    #[error("ip override {0} is not in 127.0.0.0/8")]
    InvalidIpOverride(std::net::Ipv4Addr),

    #[error(transparent)]
    Io(#[from] IoError),
}

impl ResolveError {
    pub(crate) fn io(context: impl Into<Cow<'static, str>>, source: io::Error) -> Self {
        Self::Io(IoError::new(context, source))
    }
}

#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum SessionError {
    #[error(
        "IP collision: {ip} is already assigned to `{existing}` but this session \
             needs it for `{new}`. Use `silo run --ip <addr>` to assign a different address."
    )]
    IpCollision {
        ip: std::net::Ipv4Addr,
        existing: String,
        new: String,
    },

    #[error("hosts validation: {0}")]
    HostsValidation(String),

    #[error("command failed: {command}")]
    CommandFailed { command: String },

    #[error("{0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error(transparent)]
    Io(#[from] IoError),
}

impl SessionError {
    pub(crate) fn io(context: impl Into<Cow<'static, str>>, source: io::Error) -> Self {
        Self::Io(IoError::new(context, source))
    }
}
