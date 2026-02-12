use eyre::Context as _;

pub fn run() -> eyre::Result<()> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let cwd = cwd.canonicalize().unwrap_or(cwd);
    let ctx = silo::Context::for_dir(&cwd, None)?;
    println!("{}", ctx.ip());
    Ok(())
}
