use colored::Colorize;
use comfy_table::{ContentArrangement, Table};
use serde_json::json;

use silo_core::config;
use silo_core::ip;
use silo_core::store::Store;
use crate::ui;

pub async fn run(store: &Store, all: bool, json: bool) -> eyre::Result<()> {
    let instances = if all {
        store.list_all().await?
    } else {
        let cwd = std::env::current_dir()
            .ok()
            .and_then(|p| p.canonicalize().ok().or(Some(p)));

        let repo = if let Some(ref cwd) = cwd {
            store
                .find_by_path(cwd)
                .await?
                .map(|inst| inst.repo.clone())
        } else {
            None
        };

        let repo = repo.or_else(|| config::load_config().ok().map(|(_, root)| root));

        match repo {
            Some(repo_root) => store.list_by_repo(&repo_root).await?,
            None => store.list_all().await?,
        }
    };

    let all_ips: Vec<_> = instances.iter().map(|i| i.ip).collect();
    let active = ip::active_ips(&all_ips).unwrap_or_default();

    if json {
        let items: Vec<_> = instances
            .iter()
            .map(|inst| {
                json!({
                    "name": inst.name,
                    "ip": inst.ip.to_string(),
                    "path": inst.path,
                    "repo": inst.repo,
                    "is_worktree": inst.is_worktree,
                    "created_at": inst.created_at,
                    "status": if active.contains(&inst.ip) { "active" } else { "inactive" },
                })
            })
            .collect();
        println!("{}", serde_json::to_string(&items)?);
        return Ok(());
    }

    if instances.is_empty() {
        ui::info("no instances found");
        ui::hint(format!(
            "run {} to create one",
            ui::accent("silo add <name>").bold()
        ));
        return Ok(());
    }

    let mut table = Table::new();
    table.load_preset(comfy_table::presets::NOTHING);
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["name", "ip", "status", "path", "created"]);

    for inst in &instances {
        let status = if active.contains(&inst.ip) {
            format!("{} active", "●".green())
        } else {
            format!("{} inactive", "○".dimmed())
        };

        table.add_row(vec![
            ui::accent(&inst.name).to_string(),
            inst.ip.to_string(),
            status,
            inst.path.display().to_string(),
            inst.created_at.format("%Y-%m-%d %H:%M").to_string(),
        ]);
    }

    println!("{table}");
    Ok(())
}
