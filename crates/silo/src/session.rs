use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::warn;

use crate::context::Context;
use crate::error::{Error, Result};
use crate::{hosts, ip, render};

/// Controls which side effects [`Session::activate`] performs.
///
/// All options default to `true`, matching the behavior of
/// [`Session::new`] and [`Session::in_dir`].
#[derive(Debug, Clone)]
pub struct ActivateOptions {
    /// Add a loopback alias for the resolved IP (requires sudo).
    pub ip_alias: bool,
    /// Add/update an entry in `/etc/hosts` (requires sudo).
    pub hosts_entry: bool,
    /// Render `.silo` template files into their target env files.
    pub silo_env: bool,
    /// Locate the bind library (required for [`Session::env`] and
    /// [`Session::apply`] to include `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES`).
    pub bind_lib: bool,
}

impl Default for ActivateOptions {
    fn default() -> Self {
        Self::all()
    }
}

impl ActivateOptions {
    /// All side effects enabled.
    pub fn all() -> Self {
        Self {
            ip_alias: true,
            hosts_entry: true,
            silo_env: true,
            bind_lib: true,
        }
    }

    /// No side effects — just wrap a [`Context`] into a [`Session`].
    pub fn none() -> Self {
        Self {
            ip_alias: false,
            hosts_entry: false,
            silo_env: false,
            bind_lib: false,
        }
    }
}

pub struct Session {
    ctx: Context,
    bind_lib_path: Option<PathBuf>,
}

impl Session {
    /// Compute the deterministic IP for a directory without any side effects.
    pub fn ip_for(dir: &Path, name: Option<&str>) -> Result<Ipv4Addr> {
        let ctx = Context::for_dir(dir, name)?;
        Ok(ctx.ip())
    }

    /// Create a session from the current working directory.
    ///
    /// Equivalent to resolving a [`Context`] and calling
    /// [`activate`](Self::activate) with [`ActivateOptions::all`].
    pub fn new(name: Option<&str>) -> Result<Self> {
        let ctx = Context::current(name)?;
        Self::activate(ctx, ActivateOptions::all())
    }

    /// Create a session for an explicit directory.
    ///
    /// Equivalent to resolving a [`Context`] and calling
    /// [`activate`](Self::activate) with [`ActivateOptions::all`].
    pub fn in_dir(dir: &Path, name: Option<&str>) -> Result<Self> {
        let ctx = Context::for_dir(dir, name)?;
        Self::activate(ctx, ActivateOptions::all())
    }

    /// Create a session from a pre-resolved [`Context`], performing only
    /// the side effects specified in `opts`.
    ///
    /// # Bind library
    ///
    /// If `opts.bind_lib` is `false`, the bind library is not located.
    /// [`Session::env`] and [`Session::apply`] will still work but will
    /// not include `DYLD_INSERT_LIBRARIES` / `LD_PRELOAD`.
    pub fn activate(ctx: Context, opts: ActivateOptions) -> Result<Self> {
        if opts.ip_alias {
            ip::add_alias(ctx.ip())?;
        }
        if opts.hosts_entry {
            if let Err(e) = hosts::ensure_entry(ctx.ip(), ctx.hostname()) {
                warn!("failed to update /etc/hosts: {e} (run `silo doctor` to diagnose)");
            }
        }
        if opts.silo_env {
            if let Err(e) = render::apply_silo_env(ctx.dir(), &ctx.env_vars()) {
                warn!("failed to apply .silo env files: {e}");
            }
        }
        let bind_lib_path = if opts.bind_lib {
            Some(find_bind_lib()?)
        } else {
            None
        };
        Ok(Self { ctx, bind_lib_path })
    }

    /// Access the underlying pure-computation context.
    pub fn context(&self) -> &Context {
        &self.ctx
    }

    /// All environment variables needed to run a command under this session.
    ///
    /// Includes `SILO_IP`, `SILO_NAME`, `SILO_DIR`, `SILO_HOST`, and
    /// `DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` (if the bind library was located).
    pub fn env(&self) -> HashMap<String, String> {
        let mut env = self.ctx.env_vars();
        if let Some((key, val)) = self.injection_env() {
            env.insert(key.into(), val);
        }
        env
    }

    /// Apply this session's environment to a command.
    pub fn apply(&self, cmd: &mut Command) {
        for (key, val) in self.env() {
            cmd.env(key, val);
        }
    }

    fn injection_env(&self) -> Option<(&'static str, String)> {
        let bind_lib_path = self.bind_lib_path.as_ref()?;

        #[cfg(target_os = "macos")]
        let key = "DYLD_INSERT_LIBRARIES";
        #[cfg(target_os = "linux")]
        let key = "LD_PRELOAD";

        let val = match std::env::var(key) {
            Ok(existing) => format!("{}:{}", bind_lib_path.display(), existing),
            Err(_) => bind_lib_path.display().to_string(),
        };
        Some((key, val))
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
