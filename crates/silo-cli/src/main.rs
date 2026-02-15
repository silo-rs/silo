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
    maybe_inject_run(std::env::args().collect())
}

fn maybe_inject_run(args: Vec<String>) -> Vec<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(input: &[&str]) -> Vec<String> {
        input.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn injects_run_for_unknown_command() {
        let result = maybe_inject_run(args(&["silo", "npm", "dev"]));
        assert_eq!(result, args(&["silo", "run", "npm", "dev"]));
    }

    #[test]
    fn preserves_known_subcommand() {
        for sub in KNOWN_SUBCOMMANDS {
            let result = maybe_inject_run(args(&["silo", sub]));
            assert_eq!(
                result,
                args(&["silo", sub]),
                "should not inject run for {sub}"
            );
        }
    }

    #[test]
    fn preserves_flags() {
        let result = maybe_inject_run(args(&["silo", "--help"]));
        assert_eq!(result, args(&["silo", "--help"]));
    }

    #[test]
    fn no_args_passthrough() {
        let result = maybe_inject_run(args(&["silo"]));
        assert_eq!(result, args(&["silo"]));
    }

    #[test]
    fn injects_run_preserves_all_trailing_args() {
        let result = maybe_inject_run(args(&["silo", "node", "server.js", "--port", "3000"]));
        assert_eq!(
            result,
            args(&["silo", "run", "node", "server.js", "--port", "3000"])
        );
    }

    #[test]
    fn unknown_subcommand_like_typo_gets_run_injected() {
        let result = maybe_inject_run(args(&["silo", "doctorx"]));
        assert_eq!(result, args(&["silo", "run", "doctorx"]));
    }
}
