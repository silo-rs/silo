use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::context::Context;
use crate::error::{ResolveError, SessionError};
use crate::{hosts, ip};

pub trait BackendSession: Send {
    fn prepare(&self, cmd: &mut Command) -> Result<(), SessionError>;
    fn name(&self) -> &str;
}

pub struct PreloadBackend {
    lib_path: PathBuf,
}

impl PreloadBackend {
    pub const fn new(lib_path: PathBuf) -> Self {
        Self { lib_path }
    }

    pub fn lib_path(&self) -> &Path {
        &self.lib_path
    }
}

impl BackendSession for PreloadBackend {
    fn prepare(&self, cmd: &mut Command) -> Result<(), SessionError> {
        #[cfg(target_os = "macos")]
        let key = "DYLD_INSERT_LIBRARIES";
        #[cfg(target_os = "linux")]
        let key = "LD_PRELOAD";

        let val = std::env::var(key).map_or_else(
            |_| self.lib_path.display().to_string(),
            |existing| format!("{}:{}", self.lib_path.display(), existing),
        );
        cmd.env(key, val);
        Ok(())
    }

    fn name(&self) -> &str {
        "preload"
    }
}

pub struct NoopBackend;

impl BackendSession for NoopBackend {
    fn prepare(&self, _cmd: &mut Command) -> Result<(), SessionError> {
        Ok(())
    }

    fn name(&self) -> &str {
        "none"
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ActivateOptions {
    pub ip_alias: bool,
    pub hosts_entry: bool,
}

impl Default for ActivateOptions {
    fn default() -> Self {
        Self {
            ip_alias: true,
            hosts_entry: true,
        }
    }
}

pub struct Session {
    ctx: Context,
    backend: Box<dyn BackendSession>,
}

impl Session {
    pub fn ip_for(dir: &Path, name: Option<&str>) -> Result<Ipv4Addr, ResolveError> {
        let ctx = Context::for_dir(dir, name, None)?;
        Ok(ctx.ip())
    }

    pub fn activate(
        ctx: Context,
        opts: ActivateOptions,
        backend: Box<dyn BackendSession>,
    ) -> Result<Self, SessionError> {
        if opts.ip_alias {
            ip::add_alias(ctx.ip())?;
        }
        if opts.hosts_entry {
            hosts::check_collision(ctx.ip(), ctx.hostname())?;
            if let Err(e) = hosts::ensure_entry(ctx.ip(), ctx.hostname(), ctx.dir()) {
                tracing::warn!("failed to update /etc/hosts: {e} (run `silo doctor` to diagnose)");
            }
        }
        Ok(Self { ctx, backend })
    }

    pub fn prepare(&self, cmd: &mut Command) -> Result<(), SessionError> {
        for (key, val) in self.ctx.env_vars() {
            cmd.env(key, val);
        }
        self.backend.prepare(cmd)
    }

    pub const fn context(&self) -> &Context {
        &self.ctx
    }

    pub fn backend_name(&self) -> &str {
        self.backend.name()
    }

    pub const fn ip(&self) -> Ipv4Addr {
        self.ctx.ip()
    }

    pub fn name(&self) -> &str {
        self.ctx.name()
    }

    pub fn hostname(&self) -> &str {
        self.ctx.hostname()
    }

    pub fn dir(&self) -> &Path {
        self.ctx.dir()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preload_backend_sets_env() {
        let backend = PreloadBackend::new(PathBuf::from("/tmp/libsilo_bind.dylib"));
        let mut cmd = Command::new("true");
        backend.prepare(&mut cmd).unwrap();

        let envs: Vec<_> = cmd.get_envs().collect();
        #[cfg(target_os = "macos")]
        let key = "DYLD_INSERT_LIBRARIES";
        #[cfg(target_os = "linux")]
        let key = "LD_PRELOAD";

        let found = envs.iter().find(|(k, _)| k == &key);
        assert!(found.is_some(), "expected {key} to be set");
        let val = found.unwrap().1.unwrap().to_str().unwrap();
        assert!(val.contains("libsilo_bind"));
    }

    #[test]
    fn preload_backend_prepend_format() {
        let backend = PreloadBackend::new(PathBuf::from("/tmp/libsilo_bind.so"));
        let mut cmd = Command::new("true");
        backend.prepare(&mut cmd).unwrap();

        #[cfg(target_os = "macos")]
        let key = "DYLD_INSERT_LIBRARIES";
        #[cfg(target_os = "linux")]
        let key = "LD_PRELOAD";

        let envs: Vec<_> = cmd.get_envs().collect();
        let found = envs.iter().find(|(k, _)| k == &key);
        let val = found.unwrap().1.unwrap().to_str().unwrap();
        assert!(
            val.contains("/tmp/libsilo_bind.so"),
            "expected lib path in env, got: {val}"
        );
    }

    #[test]
    fn noop_backend_name() {
        assert_eq!(NoopBackend.name(), "none");
    }

    #[test]
    fn preload_backend_name() {
        let backend = PreloadBackend::new(PathBuf::from("/tmp/lib.so"));
        assert_eq!(backend.name(), "preload");
    }

    #[test]
    fn preload_backend_lib_path() {
        let path = PathBuf::from("/usr/local/lib/libsilo_bind.dylib");
        let backend = PreloadBackend::new(path.clone());
        assert_eq!(backend.lib_path(), path);
    }
}
