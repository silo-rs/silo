use std::collections::HashSet;
use std::io::{self, Write};
use std::path::PathBuf;

use colored::Colorize;

use silo_core::hosts;
use silo_core::ip;
use silo_core::store::Store;
use crate::ui;
use silo_core::worktree;

pub async fn run(store: &Store, yes: bool) -> eyre::Result<()> {
    let all = store.list_all().await?;

    let orphans: Vec<_> = all
        .into_iter()
        .filter(|inst| !inst.path.exists())
        .collect();

    if orphans.is_empty() {
        ui::info("no orphaned instances found");
        return Ok(());
    }

    eprintln!("  found {} orphaned instance(s):", orphans.len());
    for inst in &orphans {
        eprintln!(
            "    {} {} {}",
            ui::accent(&inst.name).bold(),
            inst.ip.to_string().dimmed(),
            inst.path.display().to_string().dimmed()
        );
    }

    if !yes {
        eprintln!();
        eprint!("  remove these instances? [y/N] ");
        io::stderr().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            ui::info("cancelled");
            return Ok(());
        }
    }

    let worktree_repos: HashSet<PathBuf> = orphans
        .iter()
        .filter(|inst| inst.is_worktree)
        .map(|inst| inst.repo.clone())
        .collect();

    for repo in &worktree_repos {
        if let Err(e) = worktree::prune_stale(repo) {
            ui::warn(format!(
                "failed to prune worktrees in {}: {e}",
                repo.display()
            ));
        }
    }

    for inst in &orphans {
        if let Err(e) = ip::remove_alias(inst.ip) {
            ui::warn(format!("failed to remove alias {}: {e}", inst.ip));
        }

        let host = hosts::hostname(&inst.name, &inst.repo);
        if let Err(e) = hosts::remove_entry(&host) {
            ui::warn(format!("failed to remove hosts entry: {e}"));
        }

        if inst.is_worktree {
            if let Err(e) = worktree::delete_branch(&inst.repo, &inst.name) {
                ui::warn(format!("failed to delete branch {}: {e}", inst.name));
            }
        }
    }

    for inst in &orphans {
        store.remove(&inst.repo, &inst.name).await?;
    }

    ui::success(format!("pruned {} instance(s)", orphans.len()));

    Ok(())
}
