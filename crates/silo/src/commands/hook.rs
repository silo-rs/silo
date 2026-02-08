use eyre::Context;

use silo_core::config;
use silo_core::hooks;
use silo_core::store::Store;
use crate::ui;

pub async fn run(store: &Store, name: &str, instance: Option<&str>) -> eyre::Result<()> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let cwd = cwd.canonicalize().unwrap_or(cwd);

    let instance = super::resolve_instance_interactive(store, instance, &cwd).await?;
    let cfg = config::load_config_from(&instance.repo)?
        .ok_or_else(|| eyre::eyre!("silo.toml not found in {}", instance.repo.display()))?;

    let hook_list = match name {
        "setup" => &cfg.hooks.setup,
        "enter" => &cfg.hooks.enter,
        "teardown" => &cfg.hooks.teardown,
        _ => eyre::bail!("unknown hook: {name} (available: setup, enter, teardown)"),
    };

    if hook_list.is_empty() {
        ui::info(format!("no {name} hooks configured"));
        return Ok(());
    }

    hooks::run_hooks(hook_list, &instance.path, &instance.env_vars(), name)?;
    ui::success("Hooks completed");

    Ok(())
}
