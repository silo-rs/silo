use eyre::Context;

use silo::resolve;

pub fn run() -> eyre::Result<()> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let cwd = cwd.canonicalize().unwrap_or(cwd);
    let ctx = resolve::resolve(&cwd, None)?;
    println!("{}", ctx.ip);
    Ok(())
}
