use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{Error, Result};
use crate::resolve;

/// Pure-computation project context: resolved name, IP, hostname, and directory.
///
/// Creating a `Context` performs zero side effects — no network changes,
/// no file writes, no privilege escalation. It locates the git root,
/// derives the branch name, and computes the deterministic loopback IP.
///
/// Use [`Session::activate`] to apply side effects (IP alias, `/etc/hosts`, etc.)
/// based on a resolved context.
///
/// # Examples
///
/// ```no_run
/// use silo::Context;
///
/// let ctx = Context::for_dir("/path/to/repo".as_ref(), None, None)?;
/// println!("{} → {} ({})", ctx.name(), ctx.ip(), ctx.hostname());
/// # Ok::<(), silo::Error>(())
/// ```
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct Context {
    pub(crate) name: String,
    pub(crate) ip: Ipv4Addr,
    pub(crate) dir: PathBuf,
    pub(crate) hostname: String,
}

impl Context {
    /// Resolve context for the current working directory.
    pub fn current(name: Option<&str>, ip: Option<Ipv4Addr>) -> Result<Self> {
        let cwd = std::env::current_dir().map_err(|e| Error::io("failed to get cwd", e))?;
        let cwd = cwd.canonicalize().unwrap_or(cwd);
        Self::for_dir(&cwd, name, ip)
    }

    /// Resolve context for an explicit directory.
    ///
    /// Walks up from `dir` to find the git root, reads the branch name
    /// (or uses `name` if provided), and computes the deterministic IP.
    /// If `ip` is provided, it overrides the computed IP (must be in `127.0.0.0/8`).
    pub fn for_dir(dir: &Path, name: Option<&str>, ip: Option<Ipv4Addr>) -> Result<Self> {
        resolve::resolve(dir, name, ip)
    }

    /// The deterministic loopback IP (`127.x.y.z`) for this project.
    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    /// The resolved session name (sanitized branch name or override).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The hostname (`{name}.{project}.silo`) for service discovery.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// The git root directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Environment variables: `SILO_IP`, `SILO_NAME`, `SILO_DIR`, `SILO_HOST`.
    ///
    /// Does **not** include `DYLD_INSERT_LIBRARIES` / `LD_PRELOAD`.
    /// Use [`Session::env`] for the full set including the bind library.
    pub fn env_vars(&self) -> HashMap<String, String> {
        HashMap::from([
            ("SILO_IP".into(), self.ip.to_string()),
            ("SILO_NAME".into(), self.name.clone()),
            ("SILO_DIR".into(), self.dir.display().to_string()),
            ("SILO_HOST".into(), self.hostname.clone()),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_for_git_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        let ctx = Context::for_dir(dir.path(), Some("test"), None).unwrap();
        assert_eq!(ctx.name(), "test");
        assert_eq!(ctx.dir(), dir.path());
        assert_eq!(ctx.ip().octets()[0], 127);
        assert!(ctx.hostname().ends_with(".silo"));
    }

    #[test]
    fn context_not_git_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Context::for_dir(dir.path(), None, None).is_err());
    }

    #[test]
    fn context_clone() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        let ctx = Context::for_dir(dir.path(), Some("main"), None).unwrap();
        let cloned = ctx.clone();
        assert_eq!(ctx.ip(), cloned.ip());
        assert_eq!(ctx.name(), cloned.name());
        assert_eq!(ctx.hostname(), cloned.hostname());
    }

    #[test]
    fn context_env_vars() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        let ctx = Context::for_dir(dir.path(), Some("feat"), None).unwrap();
        let vars = ctx.env_vars();
        assert_eq!(vars.len(), 4);
        assert!(vars.contains_key("SILO_IP"));
        assert!(vars.contains_key("SILO_NAME"));
        assert!(vars.contains_key("SILO_DIR"));
        assert!(vars.contains_key("SILO_HOST"));
        assert_eq!(vars["SILO_NAME"], "feat");
    }

    #[test]
    fn context_debug() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        let ctx = Context::for_dir(dir.path(), Some("main"), None).unwrap();
        let debug = format!("{:?}", ctx);
        assert!(debug.contains("Context"));
    }
}
