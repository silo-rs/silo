use eyre::Context as _;
use serde::Serialize;

#[derive(Serialize)]
struct IpOutput {
    ip: String,
    name: String,
    hostname: String,
    dir: String,
}

pub fn run(json: bool) -> eyre::Result<()> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let cwd = cwd.canonicalize().unwrap_or(cwd);
    let ctx = silo::Context::for_dir(&cwd, None, None)?;

    if json {
        let output = IpOutput {
            ip: ctx.ip().to_string(),
            name: ctx.name().to_string(),
            hostname: ctx.hostname().to_string(),
            dir: ctx.dir().display().to_string(),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", ctx.ip());
    }

    Ok(())
}
