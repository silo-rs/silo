use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use colored::Colorize;
use eyre::Context;

use crate::ui;
use silo::Session;

pub fn run(name: Option<&str>, command: &[String], quiet: bool) -> eyre::Result<()> {
    if std::env::var("SILO_IP").is_ok() {
        eprintln!(
            "{} already inside a silo session (SILO_IP is set)",
            "warning:".yellow().bold(),
        );
    }

    let ctx = silo::Context::current(name)?;

    // Select backend: eBPF on Linux if available, otherwise LD_PRELOAD
    #[cfg(target_os = "linux")]
    let (backend, ebpf_session) = {
        let backend = crate::ebpf::select_backend();
        let ebpf_session = match &backend {
            silo::Backend::Ebpf => {
                let session_id = format!("{}-{}", ctx.name(), ctx.ip());
                Some(
                    crate::ebpf::EbpfSession::new(&session_id, ctx.ip())
                        .context("failed to set up eBPF session")?,
                )
            }
            _ => None,
        };
        (backend, ebpf_session)
    };

    #[cfg(not(target_os = "linux"))]
    let backend = {
        let bind_lib_path = find_bind_lib()?;
        silo::Backend::LdPreload {
            lib_path: bind_lib_path,
        }
    };

    let session = Session::activate(
        ctx,
        silo::ActivateOptions {
            backend,
            ..Default::default()
        },
    )?;

    let quiet = quiet || std::env::var("SILO_QUIET").is_ok();

    if !quiet {
        let backend_tag = match session.backend() {
            silo::Backend::LdPreload { .. } => "preload",
            #[cfg(target_os = "linux")]
            silo::Backend::Ebpf => "ebpf",
            silo::Backend::None => "none",
        };
        eprintln!(
            "{} {} {} {}",
            ui::accent("silo"),
            "●".green(),
            ui::accent(session.name()).bold(),
            format!("[{backend_tag}]").dimmed(),
        );
        eprintln!(
            "     {} {} {}",
            session.ip().to_string().dimmed(),
            "·".dimmed(),
            session.hostname().dimmed(),
        );
    }

    #[cfg(target_os = "linux")]
    return exec_with_interception(&session, &command[0], &command[1..], ebpf_session.as_ref());

    #[cfg(not(target_os = "linux"))]
    exec_with_interception(&session, &command[0], &command[1..])
}

#[cfg(not(target_os = "linux"))]
pub fn exec_with_interception(
    session: &Session,
    program: &str,
    args: &[String],
) -> eyre::Result<()> {
    #[cfg(target_os = "macos")]
    let (program, args) = silo::shebang::resolve_program(program, args);

    #[cfg(target_os = "macos")]
    if silo::shebang::is_sip_protected(std::path::Path::new(&program)) {
        eprintln!(
            "{} running SIP-protected binary: {}",
            "warning:".yellow().bold(),
            program.dimmed(),
        );
        eprintln!(
            "  {}",
            "bind interception may not work (DYLD_INSERT_LIBRARIES stripped by macOS)".dimmed()
        );
        eprintln!(
            "  {}",
            "install a shell via Homebrew to fix: brew install bash".dimmed()
        );
    }

    let mut cmd = Command::new(&program);
    cmd.args(&args);
    session.apply(&mut cmd);

    let err = cmd.exec();
    Err(err).context(format!("failed to exec: {}", program))
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn exec_with_interception(
    session: &Session,
    program: &str,
    args: &[String],
    ebpf_session: Option<&crate::ebpf::EbpfSession>,
) -> eyre::Result<()> {
    let (program, args) = (program.to_string(), args.to_vec());

    let mut cmd = Command::new(&program);
    cmd.args(&args);

    if let Some(ebpf) = ebpf_session {
        // eBPF backend: set SILO_* env vars (but NOT LD_PRELOAD),
        // then move into the cgroup before exec.
        for (key, val) in session.context().env_vars() {
            cmd.env(key, val);
        }
        // Move the current process into the cgroup. After exec(), the new
        // process image inherits the cgroup membership, and all its children
        // will too. No race condition because CommandExt::exec does not fork.
        ebpf.add_pid(std::process::id())?;
    } else {
        // LD_PRELOAD backend: set all env vars including LD_PRELOAD.
        session.apply(&mut cmd);
    }

    let err = cmd.exec();
    Err(err).context(format!("failed to exec: {}", program))
}

#[cfg(target_os = "macos")]
const LIB_NAME: &str = "libsilo_bind.dylib";
#[cfg(target_os = "linux")]
const LIB_NAME: &str = "libsilo_bind.so";

#[cfg(target_os = "macos")]
const EMBEDDED_BIND_LIB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libsilo_bind.dylib"));
#[cfg(target_os = "linux")]
const EMBEDDED_BIND_LIB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libsilo_bind.so"));

pub fn find_bind_lib() -> eyre::Result<PathBuf> {
    if let Ok(path) = std::env::var("SILO_BIND_LIB") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }

    let lib_dir = dirs::home_dir()
        .ok_or_else(|| eyre::eyre!("cannot determine home directory"))?
        .join(".silo")
        .join("lib");

    let lib_path = lib_dir.join(LIB_NAME);
    let stamp_path = lib_dir.join(".silo-bind-stamp");
    let current_stamp = env!("CARGO_PKG_VERSION");

    let needs_extract = !lib_path.exists()
        || std::fs::read_to_string(&stamp_path)
            .map(|s| s.trim() != current_stamp)
            .unwrap_or(true);

    if needs_extract {
        std::fs::create_dir_all(&lib_dir)?;
        std::fs::write(&lib_path, EMBEDDED_BIND_LIB)?;
        std::fs::write(&stamp_path, current_stamp)?;
    }

    Ok(lib_path)
}
