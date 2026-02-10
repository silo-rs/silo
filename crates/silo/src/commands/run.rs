use colored::Colorize;
use eyre::Context;

use crate::ui;
use silo_core::config;
use silo_core::hooks;
use silo_core::store::Store;

pub async fn run(
    store: &Store,
    instance: Option<&str>,
    name: Option<&str>,
    no_hooks: bool,
) -> eyre::Result<()> {
    let (cfg, _) = config::load_config()?;

    let name = match name {
        Some(n) => n.to_string(),
        None => {
            if cfg.run.commands.is_empty() {
                ui::info("no commands defined in silo.toml [run]");
                ui::hint("add commands like: dev = \"npm run dev\"");
                return Ok(());
            }
            eprintln!("  {}", "available commands".bold());
            let mut names: Vec<_> = cfg.run.commands.keys().collect();
            names.sort();
            for name in &names {
                let cmd = &cfg.run.commands[*name];
                eprintln!("    {}  {}", ui::accent(name).bold(), cmd.dimmed());
            }
            eprintln!();
            ui::hint(format!(
                "run {} to execute",
                ui::accent("silo run <name>").bold()
            ));
            return Ok(());
        }
    };

    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let cwd = cwd.canonicalize().unwrap_or(cwd);

    let instance = super::resolve_instance_interactive(store, instance, &cwd).await?;

    if !no_hooks && !cfg.hooks.enter.is_empty() {
        hooks::run_hooks(
            &cfg.hooks.enter,
            &instance.path,
            &instance.env_vars(),
            "enter",
        )?;
    }

    let cmd = cfg
        .run
        .commands
        .get(&name)
        .ok_or_else(|| eyre::eyre!("command '{}' not defined in silo.toml [run]", name))?
        .clone();

    let shell = which::which("sh")
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "sh".to_string());

    super::exec::exec_with_interception(&shell, &["-c".to_string(), cmd], &instance.env_vars())
}
