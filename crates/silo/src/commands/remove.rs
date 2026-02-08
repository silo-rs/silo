use std::io::{self, Write};

use eyre::Context;
use colored::Colorize;

use silo_core::config;
use silo_core::hooks;
use silo_core::hosts;
use silo_core::ip;
use silo_core::store::Store;
use crate::ui;
use silo_core::worktree;

pub async fn run(store: &Store, name: Option<&str>, force: bool, no_hooks: bool, json: bool) -> eyre::Result<()> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let cwd = cwd.canonicalize().unwrap_or(cwd);

    let instance = super::resolve_instance_interactive(store, name, &cwd).await?;

    if !force && !json {
        eprint!(
            "  remove {} ({})? [y/N] ",
            ui::accent(&instance.name).bold(),
            instance.ip.to_string().dimmed()
        );
        io::stderr().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            ui::info("cancelled");
            return Ok(());
        }
    }

    let cfg = config::load_config_from(&instance.repo)?;

    if !no_hooks {
        if let Some(ref cfg) = cfg {
            if let Err(e) = hooks::run_hooks(
                &cfg.hooks.teardown,
                &instance.path,
                &instance.env_vars(),
                "teardown",
            ) {
                ui::warn(format!("teardown hook failed: {e}"));
            }
        }
    }

    if let Err(e) = ip::remove_alias(instance.ip) {
        ui::warn(format!("failed to remove IP alias: {e}"));
    }

    let host = hosts::hostname(&instance.name, &instance.repo);
    if let Err(e) = hosts::remove_entry(&host) {
        ui::warn(format!("failed to remove hosts entry: {e}"));
    }

    if instance.is_worktree {
        if let Err(e) = worktree::remove_worktree(&instance.repo, &instance.path) {
            ui::warn(format!("failed to remove worktree: {e}"));
        }
        if let Err(e) = worktree::delete_branch(&instance.repo, &instance.name) {
            ui::warn(format!("failed to delete branch: {e}"));
        }
    }

    store.remove(&instance.repo, &instance.name).await?;

    if json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "name": instance.name,
                "ip": instance.ip.to_string(),
                "removed": true,
            }))?
        );
    } else {
        ui::success(format!("{} removed", ui::accent(&instance.name).bold()));
    }

    Ok(())
}
