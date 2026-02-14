use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use colored::Colorize;
use eyre::Context;

use crate::ui;
use silo::Session;

pub fn run(
    name: Option<&str>,
    ip: Option<std::net::Ipv4Addr>,
    command: &[String],
    quiet: bool,
    emit_json: bool,
) -> eyre::Result<()> {
    if std::env::var("SILO_IP").is_ok() {
        eprintln!(
            "{} already inside a silo session (SILO_IP is set)",
            "warning:".yellow().bold(),
        );
    }

    crate::sudoers::ensure()?;

    let ctx = silo::Context::current(name, ip)?;
    let backend = make_backend(&ctx)?;

    let session = Session::activate(ctx, silo::ActivateOptions::default(), backend)?;

    verify_session(&session);

    if emit_json {
        let json = serde_json::to_string(session.context()).unwrap_or_else(|_| "{}".into());
        eprintln!("{json}");
    }

    let quiet = quiet || emit_json || std::env::var("SILO_QUIET").is_ok();

    if !quiet {
        eprintln!(
            "{} {} {} {}",
            ui::accent("silo"),
            "●".green(),
            ui::accent(session.name()).bold(),
            format!("[{}]", session.backend_name()).dimmed(),
        );
        eprintln!(
            "     {} {} {}",
            session.ip().to_string().dimmed(),
            "·".dimmed(),
            session.hostname().dimmed(),
        );
    }

    let program = &command[0];
    let args = &command[1..];

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

    let mut cmd = Command::new(program.clone());
    cmd.args(args);
    session.prepare(&mut cmd)?;

    let err = cmd.exec();
    Err(err).context(format!("failed to exec: {}", program))
}

fn make_backend(
    #[allow(unused_variables)] ctx: &silo::Context,
) -> eyre::Result<Box<dyn silo::BackendSession>> {
    #[cfg(target_os = "linux")]
    {
        match crate::ebpf::select_backend() {
            crate::ebpf::SelectedBackend::Ebpf => {
                let session_id = format!("{}-{}", ctx.name(), ctx.ip());
                match crate::ebpf::EbpfSession::new(&session_id, ctx.ip()) {
                    Ok(s) => return Ok(Box::new(s)),
                    Err(e) => {
                        tracing::warn!("eBPF setup failed, falling back to LD_PRELOAD: {e:#}");
                    }
                }
            }
            crate::ebpf::SelectedBackend::Preload(path) => {
                return Ok(Box::new(silo::PreloadBackend::new(path)));
            }
            crate::ebpf::SelectedBackend::None => {
                return Ok(Box::new(silo::NoopBackend));
            }
        }
    }

    let lib_path = find_bind_lib()?;
    Ok(Box::new(silo::PreloadBackend::new(lib_path)))
}

/// Pre-flight checks after session activation. Prints warnings but never blocks execution.
fn verify_session(session: &Session) {
    // Check 1: IP alias exists on loopback
    if let Ok(false) = silo::ip::alias_exists(session.ip()) {
        ui::check_warn("ip alias", "not found on loopback interface");
    }

    // Check 2: Hosts entry + collision detection (single list_entries call)
    if let Ok(entries) = silo::hosts::list_entries() {
        let has_entry = entries
            .iter()
            .any(|e| e.ip == session.ip() && e.hostname == session.hostname());
        if !has_entry {
            ui::check_warn(
                "hosts",
                format!("{} not found in /etc/hosts", session.hostname()),
            );
        }

        for e in &entries {
            if e.ip == session.ip() && e.hostname != session.hostname() {
                ui::check_warn(
                    "hosts",
                    format!(
                        "ip collision — {} is also mapped to {}. fix: silo run --ip 127.x.y.z <cmd>",
                        session.ip(),
                        e.hostname
                    ),
                );
                break;
            }
        }
    }

    // Check 3: Backend::None means no syscall interception
    if session.backend_name() == "none" {
        ui::check_warn("backend", "no interception method available");
    }
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
