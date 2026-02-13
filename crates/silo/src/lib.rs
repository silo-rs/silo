#![forbid(unsafe_code)]

pub mod context;
pub mod error;
pub(crate) mod resolve;
pub mod session;

pub mod hosts;
pub mod ip;

#[cfg(target_os = "macos")]
pub mod shebang;

pub use context::Context;
pub use error::Error;
pub use resolve::{compute_ip, sanitize_name};
pub use session::{ActivateOptions, BackendSession, NoopBackend, PreloadBackend, Session};
