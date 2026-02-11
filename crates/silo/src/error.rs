use std::net::Ipv4Addr;
use std::path::PathBuf;
use thiserror::Error;

use crate::state::Instance;

#[derive(Debug, Error)]
pub enum SiloError {
    #[error("silo.toml not found in {0} or any parent directory")]
    ConfigNotFound(PathBuf),

    #[error("silo.toml already exists at {0}")]
    ConfigAlreadyExists(PathBuf),

    #[error("instance '{0}' already exists")]
    InstanceAlreadyExists(String),

    #[error("invalid instance name '{0}': {1}")]
    InvalidInstanceName(String, &'static str),

    #[error("instance '{0}' not found")]
    InstanceNotFound(String),

    #[error("no available IPs in range {0}")]
    IpRangeExhausted(String),

    #[error("invalid CIDR range '{0}': {1}")]
    InvalidCidrRange(String, String),

    #[error("IP {0} is outside the 127.0.0.0/8 loopback range")]
    IpNotLoopback(Ipv4Addr),

    #[error("not inside a git repository")]
    NotGitRepo,

    #[error("hook failed: `{0}` exited with code {1}")]
    HookFailed(String, i32),

    #[error("instance '{0}' is ambiguous — exists in multiple repos")]
    AmbiguousInstance(String, Vec<Instance>),

    #[error("not inside a silo instance; specify a name or cd into one")]
    NotInInstance,
}
