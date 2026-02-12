use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::warn;

use crate::error::{Error, Result};
use crate::{hosts, ip, render, resolve};

pub struct Session {
    ctx: resolve::SiloContext,
    bind_lib_path: PathBuf,
}

impl Session {
    /// Compute the deterministic IP for a directory without any side effects.
    pub fn ip_for(dir: &Path, name: Option<&str>) -> Result<Ipv4Addr> {
        let ctx = resolve::resolve(dir, name)?;
        Ok(ctx.ip)
    }

    /// Create a session from the current working directory.
    pub fn new(name: Option<&str>) -> Result<Self> {
        let cwd = std::env::current_dir().map_err(|e| Error::io("failed to get cwd", e))?;
        let cwd = cwd.canonicalize().unwrap_or(cwd);
        Self::in_dir(&cwd, name)
    }

    /// Create a session for an explicit directory.
    pub fn in_dir(dir: &Path, name: Option<&str>) -> Result<Self> {
        let ctx = resolve::resolve(dir, name)?;
        ip::add_alias(ctx.ip)?;
        if let Err(e) = hosts::ensure_entry(ctx.ip, &ctx.hostname) {
            warn!("failed to update /etc/hosts: {e} (run `silo doctor` to diagnose)");
        }
        if let Err(e) = render::apply_silo_env(&ctx.dir, &ctx.env_vars()) {
            warn!("failed to apply .silo env files: {e}");
        }
        let bind_lib_path = find_bind_lib()?;
        Ok(Self { ctx, bind_lib_path })
    }

    /// All environment variables needed to run a command under this session,
    /// including DYLD_INSERT_LIBRARIES / LD_PRELOAD.
    pub fn env(&self) -> HashMap<String, String> {
        let mut env = self.ctx.env_vars();
        let (key, val) = self.injection_env();
        env.insert(key.into(), val);
        env
    }

    /// Apply this session's environment to a command.
    pub fn apply(&self, cmd: &mut Command) {
        for (key, val) in self.env() {
            cmd.env(key, val);
        }
    }

    fn injection_env(&self) -> (&'static str, String) {
        #[cfg(target_os = "macos")]
        let key = "DYLD_INSERT_LIBRARIES";
        #[cfg(target_os = "linux")]
        let key = "LD_PRELOAD";

        let val = match std::env::var(key) {
            Ok(existing) => format!("{}:{}", self.bind_lib_path.display(), existing),
            Err(_) => self.bind_lib_path.display().to_string(),
        };
        (key, val)
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.ctx.ip
    }

    pub fn name(&self) -> &str {
        &self.ctx.name
    }

    pub fn hostname(&self) -> &str {
        &self.ctx.hostname
    }

    pub fn dir(&self) -> &Path {
        &self.ctx.dir
    }
}

fn find_bind_lib() -> std::result::Result<PathBuf, Error> {
    if let Ok(path) = std::env::var("SILO_BIND_LIB") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }

    let lib_dir = dirs::home_dir()
        .ok_or(Error::BindLibNotFound)?
        .join(".silo")
        .join("lib");

    let lib_path = lib_dir.join(lib_name());
    if lib_path.exists() {
        Ok(lib_path)
    } else {
        Err(Error::BindLibNotFound)
    }
}

fn lib_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "libsilo_bind.dylib"
    } else {
        "libsilo_bind.so"
    }
}
