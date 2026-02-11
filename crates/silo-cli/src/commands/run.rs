use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use colored::Colorize;
use eyre::Context;

use crate::ui;
use silo::config;
use silo::hooks;
use silo::store::Store;

pub async fn run(
    store: &Store,
    instance: Option<&str>,
    command: &[String],
    quiet: bool,
    no_hooks: bool,
) -> eyre::Result<()> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let cwd = cwd.canonicalize().unwrap_or(cwd);

    let instance = super::resolve_instance_interactive(store, instance, &cwd).await?;

    let quiet = quiet || std::env::var("SILO_QUIET").is_ok();

    if !quiet {
        let host = instance.hostname();
        eprintln!(
            "{} {} {}",
            ui::accent("silo"),
            "●".green(),
            ui::accent(&instance.name).bold(),
        );
        eprintln!(
            "     {} {} {}",
            instance.ip.to_string().dimmed(),
            "·".dimmed(),
            host.dimmed(),
        );
    }

    if !no_hooks
        && let Some(cfg) = config::load_config_from(&instance.repo)?
        && !cfg.hooks.enter.is_empty()
    {
        hooks::run_hooks(
            &cfg.hooks.enter,
            &instance.path,
            &instance.env_vars(),
            "enter",
        )?;
    }

    exec_with_interception(&command[0], &command[1..], &instance.env_vars())
}

pub fn exec_with_interception(
    program: &str,
    args: &[String],
    env_vars: &HashMap<String, String>,
) -> eyre::Result<()> {
    let lib_path = find_bind_lib()?;

    #[cfg(target_os = "macos")]
    let (program, args) = silo::shebang::resolve_program(program, args);

    #[cfg(not(target_os = "macos"))]
    let (program, args) = (program.to_string(), args.to_vec());

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

    for (key, val) in env_vars {
        cmd.env(key, val);
    }

    #[cfg(target_os = "macos")]
    {
        let key = "DYLD_INSERT_LIBRARIES";
        let val = match std::env::var(key) {
            Ok(existing) => format!("{}:{}", lib_path.display(), existing),
            Err(_) => lib_path.display().to_string(),
        };
        cmd.env(key, val);
    }

    #[cfg(target_os = "linux")]
    {
        let key = "LD_PRELOAD";
        let val = match std::env::var(key) {
            Ok(existing) => format!("{}:{}", lib_path.display(), existing),
            Err(_) => lib_path.display().to_string(),
        };
        cmd.env(key, val);
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
