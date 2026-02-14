use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{Error, Result};
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
    pub fn current(name: Option<&str>, ip: Option<Ipv4Addr>) -> Result<Self> {
        let cwd = std::env::current_dir().map_err(|e| Error::io("failed to get cwd", e))?;
        let cwd = cwd.canonicalize().unwrap_or(cwd);
        Self::for_dir(&cwd, name, ip)
    }

    pub fn for_dir(dir: &Path, name: Option<&str>, ip: Option<Ipv4Addr>) -> Result<Self> {
        resolve::resolve(dir, name, ip)
    }

    pub fn ip(&self) -> Ipv4Addr {
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
