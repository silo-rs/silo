#![forbid(unsafe_code)]

pub mod error;
pub(crate) mod resolve;
pub mod session;

pub(crate) mod hosts;
pub(crate) mod ip;
pub(crate) mod render;

#[cfg(target_os = "macos")]
pub mod shebang;

pub use error::Error;
pub use session::Session;
