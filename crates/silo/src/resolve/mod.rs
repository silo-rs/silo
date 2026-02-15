mod git;
mod hash;
mod sanitize;

use std::net::Ipv4Addr;
use std::path::Path;

use tracing::debug;

use crate::context::Context;
use crate::error::{Error, Result};

pub use hash::compute_ip;
pub use sanitize::sanitize_name;

pub fn resolve(
    cwd: &Path,
    name_override: Option<&str>,
    ip_override: Option<Ipv4Addr>,
) -> Result<Context> {
    let git_root = git::find_git_root(cwd)?;
    let canonical = git_root.canonicalize().unwrap_or_else(|_| git_root.clone());

    let name = match name_override {
        Some(n) => sanitize::sanitize_name(n),
        None => {
            let branch = git::get_branch_name(&git_root)?;
            sanitize::sanitize_name(&branch)
        }
    };

    let ip = match ip_override {
        Some(ip) => {
            if ip.octets()[0] != 127 {
                return Err(Error::InvalidIpOverride(ip));
            }
            ip
        }
        None => hash::compute_ip(&canonical, &name),
    };

    let project_name = sanitize::sanitize_name(&git::main_repo_name(&git_root));
    let hostname = format!("{}.{}.silo", name, project_name);

    debug!(%ip, %name, %hostname, dir = %git_root.display(), "resolved silo context");

    Ok(Context {
        name,
        ip,
        dir: git_root,
        hostname,
    })
}
