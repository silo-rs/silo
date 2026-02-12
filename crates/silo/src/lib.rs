#![forbid(unsafe_code)]

pub mod error;
pub(crate) mod resolve;
pub mod session;

pub mod hosts;
pub mod ip;
pub(crate) mod render;

#[cfg(target_os = "macos")]
pub mod shebang;

pub use error::Error;
pub use session::Session;
