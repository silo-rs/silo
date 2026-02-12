#![forbid(unsafe_code)]

mod cli;
mod commands;
pub(crate) mod ui;

use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;

const KNOWN_SUBCOMMANDS: &[&str] = &["run", "ip", "status", "doctor", "prune", "help"];

/// If the first positional arg isn't a known subcommand, treat the entire
/// invocation as `silo run <args>`.  This lets users write `silo npm run dev`
/// instead of `silo run npm run dev`.
fn auto_run_args() -> Vec<String> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && !args[1].starts_with('-') && !KNOWN_SUBCOMMANDS.contains(&args[1].as_str())
    {
        let mut new_args = vec![args[0].clone(), "run".into()];
        new_args.extend_from_slice(&args[1..]);
        new_args
    } else {
        args
    }
}
use tracing_subscriber::{EnvFilter, fmt};

fn main() {
    init_tracing();
    color_eyre::install().ok();

    if let Err(err) = run() {
        eprintln!("  {} {}: {:#}", "✗".red(), "error".red(), err);
        eprintln!();
        eprintln!(
            "  {}",
            "Run `silo doctor` to check your environment.".dimmed()
        );
        std::process::exit(1);
    }
}

fn init_tracing() {
    let filter = EnvFilter::builder()
        .with_env_var("SILO_LOG")
        .with_default_directive(tracing::Level::ERROR.into())
        .from_env_lossy();

    fmt::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

fn run() -> eyre::Result<()> {
    let cli = Cli::parse_from(auto_run_args());

    match cli.command {
        Commands::Run {
            name,
            quiet,
            command,
        } => commands::run::run(name.as_deref(), &command, quiet),
        Commands::Ip => commands::ip::run(),
        Commands::Doctor => commands::doctor::run(),
        Commands::Status => commands::status::run(),
        Commands::Prune { all, yes } => commands::prune::run(all, yes),
    }
}
