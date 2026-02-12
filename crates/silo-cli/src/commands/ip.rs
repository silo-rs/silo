use eyre::Context;

use silo::Session;

pub fn run() -> eyre::Result<()> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let cwd = cwd.canonicalize().unwrap_or(cwd);
    let ip = Session::ip_for(&cwd, None)?;
    println!("{}", ip);
    Ok(())
}
