pub mod activate;
pub mod add;
pub mod completions;
pub mod default_config;
pub mod dir;
pub mod doctor;
pub mod env;
pub mod exec;
pub mod hook;
pub mod info;
pub mod init;
pub mod list;
pub mod prune;
pub mod remove;
pub mod run;
pub mod shell_init;

use std::io::{self, Write};
use std::path::Path;

use colored::Colorize;

use silo_core::error::SiloError;
use silo_core::state::Instance;
use silo_core::store::Store;
use crate::ui;

pub async fn resolve_instance_interactive(
    store: &Store,
    name: Option<&str>,
    cwd: &Path,
) -> eyre::Result<Instance> {
    match store.resolve_instance(name, cwd).await {
        Ok(inst) => Ok(inst),
        Err(err) => {
            if let Some(SiloError::AmbiguousInstance(_, candidates)) =
                err.downcast_ref::<SiloError>()
            {
                pick_instance(candidates)
            } else {
                Err(err)
            }
        }
    }
}

fn pick_instance(candidates: &[Instance]) -> eyre::Result<Instance> {
    eprintln!("  multiple instances found:");
    for (i, inst) in candidates.iter().enumerate() {
        eprintln!(
            "    {}  {} {}",
            (i + 1).to_string().bold(),
            ui::accent(&inst.name),
            inst.repo.display().to_string().dimmed(),
        );
    }

    eprint!("  select [1-{}]: ", candidates.len());
    io::stderr().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let choice: usize = input
        .trim()
        .parse()
        .ok()
        .filter(|&n| n >= 1 && n <= candidates.len())
        .ok_or_else(|| eyre::eyre!("invalid selection"))?;

    Ok(candidates[choice - 1].clone())
}
