use eyre::Context;
use colored::Colorize;
use serde_json::json;

use silo_core::ip;
use silo_core::store::Store;
use crate::ui;

pub async fn run(store: &Store, name: Option<&str>, json: bool) -> eyre::Result<()> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let cwd = cwd.canonicalize().unwrap_or(cwd);

    let instance = super::resolve_instance_interactive(store, name, &cwd).await?;
    let active = ip::alias_exists(instance.ip).unwrap_or(false);

    let host = instance.hostname();

    if json {
        let output = json!({
            "name": instance.name,
            "ip": instance.ip.to_string(),
            "host": host,
            "path": instance.path,
            "repo": instance.repo,
            "is_worktree": instance.is_worktree,
            "created_at": instance.created_at,
            "status": if active { "active" } else { "inactive" },
        });
        println!("{}", serde_json::to_string(&output)?);
        return Ok(());
    }

    eprintln!("{}", ui::accent(&instance.name).bold());
    eprintln!("  ip       {}", instance.ip.to_string().dimmed());
    eprintln!("  host     {}", host.dimmed());
    eprintln!("  path     {}", instance.path.display().to_string().dimmed());
    eprintln!("  repo     {}", instance.repo.display().to_string().dimmed());
    eprintln!("  worktree {}", if instance.is_worktree { "yes" } else { "no" });
    eprintln!(
        "  created  {}",
        instance.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string().dimmed()
    );

    if active {
        eprintln!("  status   {} {}", "●".green(), "active".green());
    } else {
        eprintln!("  status   {} {}", "○".dimmed(), "inactive".dimmed());
    }

    Ok(())
}
