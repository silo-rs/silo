#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod hosts;
pub mod ip;
pub mod render;
pub mod resolve;
#[cfg(target_os = "macos")]
pub mod shebang;
