use colored::Colorize;

use crate::ui;
use silo_core::hosts;
use silo_core::ip;
use silo_core::store::Store;

pub async fn run(store: &Store) -> eyre::Result<()> {
    let instances = store.list_all().await?;

    if instances.is_empty() {
        ui::info("no instances to activate");
        return Ok(());
    }

    let mut activated = 0;
    let mut already_active = 0;

    for inst in &instances {
        if ip::alias_exists(inst.ip)? {
            already_active += 1;
            continue;
        }

        ip::add_alias(inst.ip)?;
        ui::success(format!("{} {}", inst.ip, inst.name.dimmed()));
        activated += 1;
    }

    let host_entries: Vec<_> = instances
        .iter()
        .map(|inst| (inst.ip, inst.hostname()))
        .collect();
    if !host_entries.is_empty()
        && let Err(e) = hosts::sync_entries(&host_entries)
    {
        ui::warn(format!("failed to sync hosts entries: {e}"));
    }

    if activated == 0 {
        ui::success(format!("all {} instance(s) already active", already_active));
    } else {
        eprintln!();
        ui::success(format!(
            "activated {} alias(es), {} already active",
            activated, already_active
        ));
    }

    Ok(())
}
