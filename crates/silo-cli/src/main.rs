#![deny(unsafe_code)]

mod cli;
mod commands;
#[cfg(target_os = "linux")]
pub(crate) mod ebpf;
pub(crate) mod sudoers;
pub(crate) mod ui;

use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;

const KNOWN_SUBCOMMANDS: &[&str] = &[
    "run",
    "env",
    "ip",
    "ls",
    "doctor",
    "prune",
    "setup-ebpf",
    "teardown-ebpf",
    "help",
];

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
            ip,
            quiet,
            emit_json,
            command,
        } => commands::run::run(name.as_deref(), ip, &command, quiet, emit_json),
        Commands::Env { name, ip, json } => commands::env::run(name.as_deref(), ip, json),
        Commands::Ip { json } => commands::ip::run(json),
        Commands::Doctor { json } => commands::doctor::run(json),
        Commands::Ls { json } => commands::ls::run(json),
        Commands::Prune { all, yes, json } => commands::prune::run(all, yes || json, json),
        #[cfg(target_os = "linux")]
        Commands::SetupEbpf => commands::setup_ebpf::run(),
        #[cfg(target_os = "linux")]
        Commands::TeardownEbpf => commands::teardown_ebpf::run(),
    }
}
