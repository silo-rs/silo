use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::warn;

use crate::context::Context;
use crate::error::Result;
use crate::{hosts, ip};

pub trait BackendSession: Send {
    fn prepare(&self, cmd: &mut Command) -> Result<()>;
    fn name(&self) -> &str;
}

/// `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` backend.
pub struct PreloadBackend {
    lib_path: PathBuf,
}

impl PreloadBackend {
    pub fn new(lib_path: PathBuf) -> Self {
        Self { lib_path }
    }

    pub fn lib_path(&self) -> &Path {
        &self.lib_path
    }
}

impl BackendSession for PreloadBackend {
    fn prepare(&self, cmd: &mut Command) -> Result<()> {
        #[cfg(target_os = "macos")]
        let key = "DYLD_INSERT_LIBRARIES";
        #[cfg(target_os = "linux")]
        let key = "LD_PRELOAD";

        let val = match std::env::var(key) {
            Ok(existing) => format!("{}:{}", self.lib_path.display(), existing),
            Err(_) => self.lib_path.display().to_string(),
        };
        cmd.env(key, val);
        Ok(())
    }

    fn name(&self) -> &str {
        "preload"
    }
}

pub struct NoopBackend;

impl BackendSession for NoopBackend {
    fn prepare(&self, _cmd: &mut Command) -> Result<()> {
        Ok(())
    }

    fn name(&self) -> &str {
        "none"
    }
}

/// Controls which side effects [`Session::activate`] performs.
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
    pub fn ip_for(dir: &Path, name: Option<&str>) -> Result<Ipv4Addr> {
        let ctx = Context::for_dir(dir, name, None)?;
        Ok(ctx.ip())
    }

    pub fn activate(
        ctx: Context,
        opts: ActivateOptions,
        backend: Box<dyn BackendSession>,
    ) -> Result<Self> {
        if opts.ip_alias {
            ip::add_alias(ctx.ip())?;
        }
        if opts.hosts_entry
            && let Err(e) = hosts::ensure_entry(ctx.ip(), ctx.hostname(), ctx.dir())
        {
            warn!("failed to update /etc/hosts: {e} (run `silo doctor` to diagnose)");
        }
        Ok(Self { ctx, backend })
    }

    pub fn prepare(&self, cmd: &mut Command) -> Result<()> {
        for (key, val) in self.ctx.env_vars() {
            cmd.env(key, val);
        }
        self.backend.prepare(cmd)
    }

    pub fn context(&self) -> &Context {
        &self.ctx
    }

    pub fn backend_name(&self) -> &str {
        self.backend.name()
    }

    pub fn ip(&self) -> Ipv4Addr {
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
