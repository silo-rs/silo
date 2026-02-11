use colored::Colorize;
use eyre::Context;

use crate::ui;
use silo::config;
use silo::hooks;
use silo::store::Store;

pub async fn run_script(store: &Store, name: &str, no_hooks: bool) -> eyre::Result<()> {
    let (cfg, _) = config::load_config()?;

    let cmd = match cfg.scripts.commands.get(name) {
        Some(cmd) => cmd.clone(),
        None => {
            eprintln!("  {} unknown command '{}'", "✗".red(), name);
            if cfg.scripts.commands.is_empty() {
                eprintln!();
                ui::hint("add commands like: dev = \"npm run dev\" to [scripts] in silo.toml");
            } else {
                eprintln!();
                eprintln!("  {}", "available scripts".bold());
                let mut names: Vec<_> = cfg.scripts.commands.keys().collect();
                names.sort();
                for n in &names {
                    let c = &cfg.scripts.commands[*n];
                    eprintln!("    {}  {}", ui::accent(n).bold(), c.dimmed());
                }
                eprintln!();
                let suggestion = format!("{name} = \"your command\"");
                ui::hint(format!(
                    "add {} to [scripts] in silo.toml",
                    ui::accent(&suggestion).bold()
                ));
            }
            std::process::exit(1);
        }
    };

    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let cwd = cwd.canonicalize().unwrap_or(cwd);

    let instance = super::resolve_instance_interactive(store, None, &cwd).await?;

    if !no_hooks && !cfg.hooks.enter.is_empty() {
        hooks::run_hooks(
            &cfg.hooks.enter,
            &instance.path,
            &instance.env_vars(),
            "enter",
        )?;
    }

    let shell = which::which("sh")
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "sh".to_string());

    super::run::exec_with_interception(&shell, &["-c".to_string(), cmd], &instance.env_vars())
}

pub fn list_scripts(names_only: bool) -> eyre::Result<()> {
    let (cfg, _) = config::load_config()?;

    if names_only {
        let mut names: Vec<_> = cfg.scripts.commands.keys().collect();
        names.sort();
        for name in names {
            println!("{name}");
        }
        return Ok(());
    }

    if cfg.scripts.commands.is_empty() {
        ui::info("no commands defined in silo.toml [scripts]");
        ui::hint("add commands like: dev = \"npm run dev\"");
        return Ok(());
    }

    eprintln!("  {}", "available scripts".bold());
    let mut names: Vec<_> = cfg.scripts.commands.keys().collect();
    names.sort();
    for name in &names {
        let cmd = &cfg.scripts.commands[*name];
        eprintln!("    {}  {}", ui::accent(name).bold(), cmd.dimmed());
    }
    eprintln!();
    ui::hint(format!(
        "run {} to execute",
        ui::accent("silo <name>").bold()
    ));
    Ok(())
}
