use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::warn;

use crate::context::Context;
use crate::error::Result;
use crate::{hosts, ip};

/// Backend-specific session state that manages syscall interception lifecycle.
///
/// Implementors handle the mechanics of intercepting socket syscalls for a
/// child process — whether via `LD_PRELOAD`, eBPF cgroup programs, or any
/// future mechanism.
///
/// The [`Session`] owns the backend and calls [`prepare`](BackendSession::prepare)
/// before `exec()`.  When the `Session` is dropped, the backend is dropped too,
/// allowing cleanup (e.g. removing a cgroup or BPF map entry).
pub trait BackendSession: Send {
    /// Prepare a command for execution under this backend.
    ///
    /// Called once, right before `exec()`.  Implementations should perform any
    /// backend-specific setup such as setting environment variables or moving
    /// the current process into a cgroup.
    fn prepare(&self, cmd: &mut Command) -> Result<()>;

    /// Short identifier for display (e.g. `"preload"`, `"ebpf"`, `"none"`).
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Built-in backends
// ---------------------------------------------------------------------------

/// `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` backend.
///
/// Sets the appropriate environment variable so the dynamic linker loads the
/// silo-bind shared library into the child process.
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

/// No-op backend — environment-only mode with no syscall interception.
pub struct NoopBackend;

impl BackendSession for NoopBackend {
    fn prepare(&self, _cmd: &mut Command) -> Result<()> {
        Ok(())
    }

    fn name(&self) -> &str {
        "none"
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Controls which side effects [`Session::activate`] performs.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ActivateOptions {
    /// Add a loopback alias for the resolved IP (requires sudo).
    pub ip_alias: bool,
    /// Add/update an entry in `/etc/hosts` (requires sudo).
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
    /// Compute the deterministic IP for a directory without any side effects.
    pub fn ip_for(dir: &Path, name: Option<&str>) -> Result<Ipv4Addr> {
        let ctx = Context::for_dir(dir, name, None)?;
        Ok(ctx.ip())
    }

    /// Create a session from a pre-resolved [`Context`], performing only
    /// the side effects specified in `opts`.
    ///
    /// The `backend` is owned by the session and will be dropped when the
    /// session is dropped.
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

    /// Prepare a command for execution under this session.
    ///
    /// Sets `SILO_IP`, `SILO_NAME`, `SILO_DIR`, `SILO_HOST` environment
    /// variables and then delegates to the backend for any additional setup
    /// (e.g. `LD_PRELOAD` or cgroup membership).
    pub fn prepare(&self, cmd: &mut Command) -> Result<()> {
        for (key, val) in self.ctx.env_vars() {
            cmd.env(key, val);
        }
        self.backend.prepare(cmd)
    }

    /// Access the underlying pure-computation context.
    pub fn context(&self) -> &Context {
        &self.ctx
    }

    /// Short name of the active backend (e.g. `"preload"`, `"ebpf"`, `"none"`).
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
