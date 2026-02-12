#![forbid(unsafe_code)]

mod cli;
mod commands;
pub(crate) mod ui;

use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;
use tracing_subscriber::{EnvFilter, fmt};

fn main() {
    init_tracing();
    color_eyre::install().ok();

    if let Err(err) = run() {
        eprintln!("  {} {}: {:#}", "✗".red(), "error".red(), err);
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
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            name,
            quiet,
            command,
        } => commands::run::run(name.as_deref(), &command, quiet),
        Commands::Ip => commands::ip::run(),
        Commands::Doctor => commands::doctor::run(),
        Commands::Status => commands::status::run(),
    }
}
