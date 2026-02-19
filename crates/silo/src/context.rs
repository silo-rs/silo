use std::borrow::Cow;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::ResolveError;
use crate::resolve;

#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct Context {
    pub(crate) name: String,
    pub(crate) ip: Ipv4Addr,
    pub(crate) dir: PathBuf,
    pub(crate) hostname: String,
}

impl Context {
    pub fn current(name: Option<&str>, ip: Option<Ipv4Addr>) -> Result<Self, ResolveError> {
        let cwd = std::env::current_dir().map_err(|e| ResolveError::io("failed to get cwd", e))?;
        let cwd = cwd
            .canonicalize()
            .map_err(|e| ResolveError::io("failed to canonicalize cwd", e))?;
        Self::for_dir(&cwd, name, ip)
    }

    pub fn for_dir(
        dir: &Path,
        name: Option<&str>,
        ip: Option<Ipv4Addr>,
    ) -> Result<Self, ResolveError> {
        resolve::resolve(dir, name, ip)
    }

    pub const fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn env_vars(&self) -> [(&'static str, Cow<'_, str>); 4] {
        [
            ("SILO_IP", Cow::Owned(self.ip.to_string())),
            ("SILO_NAME", Cow::Borrowed(&self.name)),
            ("SILO_DIR", Cow::Owned(self.dir.display().to_string())),
            ("SILO_HOST", Cow::Borrowed(&self.hostname)),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git_init(dir: &std::path::Path) {
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("git init failed");
    }

    #[test]
    fn context_for_git_dir() {
        let dir = tempfile::tempdir().unwrap();
        git_init(dir.path());
        let ctx = Context::for_dir(dir.path(), Some("test"), None).unwrap();
        assert_eq!(ctx.name(), "test");
        assert_eq!(
            ctx.dir().canonicalize().unwrap(),
            dir.path().canonicalize().unwrap()
        );
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
        git_init(dir.path());
        let ctx = Context::for_dir(dir.path(), Some("main"), None).unwrap();
        let cloned = ctx.clone();
        assert_eq!(ctx.ip(), cloned.ip());
        assert_eq!(ctx.name(), cloned.name());
        assert_eq!(ctx.hostname(), cloned.hostname());
    }

    #[test]
    fn context_env_vars() {
        let dir = tempfile::tempdir().unwrap();
        git_init(dir.path());
        let ctx = Context::for_dir(dir.path(), Some("feat"), None).unwrap();
        let vars = ctx.env_vars();
        assert_eq!(vars.len(), 4);
        let keys: Vec<&str> = vars.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"SILO_IP"));
        assert!(keys.contains(&"SILO_NAME"));
        assert!(keys.contains(&"SILO_DIR"));
        assert!(keys.contains(&"SILO_HOST"));
        let name_val = vars.iter().find(|(k, _)| *k == "SILO_NAME").unwrap();
        assert_eq!(name_val.1.as_ref(), "feat");
    }

    #[test]
    fn context_debug() {
        let dir = tempfile::tempdir().unwrap();
        git_init(dir.path());
        let ctx = Context::for_dir(dir.path(), Some("main"), None).unwrap();
        let debug = format!("{:?}", ctx);
        assert!(debug.contains("Context"));
    }

    #[test]
    fn context_ip_override() {
        let dir = tempfile::tempdir().unwrap();
        git_init(dir.path());
        let ip = Ipv4Addr::new(127, 5, 5, 5);
        let ctx = Context::for_dir(dir.path(), Some("test"), Some(ip)).unwrap();
        assert_eq!(ctx.ip(), ip);
    }

    #[test]
    fn context_ip_override_non_loopback_rejected() {
        let dir = tempfile::tempdir().unwrap();
        git_init(dir.path());
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        assert!(Context::for_dir(dir.path(), Some("test"), Some(ip)).is_err());
    }

    #[test]
    fn context_ip_override_localhost_rejected() {
        let dir = tempfile::tempdir().unwrap();
        git_init(dir.path());
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        assert!(Context::for_dir(dir.path(), Some("test"), Some(ip)).is_err());
    }

    #[test]
    fn context_hostname_ends_with_silo() {
        let dir = tempfile::tempdir().unwrap();
        git_init(dir.path());
        let ctx = Context::for_dir(dir.path(), Some("my-branch"), None).unwrap();
        assert!(ctx.hostname().ends_with(".silo"));
        assert!(ctx.hostname().starts_with("my-branch."));
    }

    #[test]
    fn context_deterministic_ip() {
        let dir = tempfile::tempdir().unwrap();
        git_init(dir.path());
        let a = Context::for_dir(dir.path(), Some("main"), None).unwrap();
        let b = Context::for_dir(dir.path(), Some("main"), None).unwrap();
        assert_eq!(a.ip(), b.ip());
    }

    #[test]
    fn context_different_names_different_ips() {
        let dir = tempfile::tempdir().unwrap();
        git_init(dir.path());
        let a = Context::for_dir(dir.path(), Some("main"), None).unwrap();
        let b = Context::for_dir(dir.path(), Some("develop"), None).unwrap();
        assert_ne!(a.ip(), b.ip());
    }
}
