use eyre::Context;

use silo_core::store::Store;

pub async fn run(store: &Store, name: &str) -> eyre::Result<()> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let cwd = cwd.canonicalize().unwrap_or(cwd);

    let instance = super::resolve_instance_interactive(store, Some(name), &cwd).await?;

    println!("{}", instance.path.display());
    Ok(())
}
