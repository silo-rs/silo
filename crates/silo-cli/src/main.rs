#![deny(unsafe_code)]

mod cli;
mod commands;
#[cfg(target_os = "linux")]
pub(crate) mod ebpf;
pub(crate) mod sudoers;
pub(crate) mod ui;

use clap::{CommandFactory, Parser};
use cli::{Cli, Commands};
use colored::Colorize;

fn known_subcommands() -> Vec<String> {
    let mut names: Vec<String> = Cli::command()
        .get_subcommands()
        .map(|c| c.get_name().to_string())
        .collect();
    names.push("help".to_string());
    names
}

fn auto_run_args() -> Vec<String> {
    maybe_inject_run(std::env::args().collect(), &known_subcommands())
}

fn maybe_inject_run(args: Vec<String>, known: &[String]) -> Vec<String> {
    if args.len() > 1 && !args[1].starts_with('-') && !known.iter().any(|k| k == &args[1]) {
        if let Some(suggestion) = closest_subcommand(&args[1], known) {
            eprintln!(
                "{} did you mean `silo {suggestion}`? Running as `silo run {} ...`",
                "hint:".yellow().bold(),
                args[1],
            );
        }
        let mut new_args = vec![args[0].clone(), "run".into()];
        new_args.extend_from_slice(&args[1..]);
        new_args
    } else {
        args
    }
}

fn closest_subcommand<'a>(input: &str, known: &'a [String]) -> Option<&'a str> {
    let threshold = match input.len() {
        0..=2 => 1,
        _ => 2,
    };
    known
        .iter()
        .filter_map(|k| {
            let d = edit_distance(input, k);
            (d > 0 && d <= threshold).then_some((d, k.as_str()))
        })
        .min_by_key(|(d, _)| *d)
        .map(|(_, name)| name)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a = a.as_bytes();
    let b = b.as_bytes();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        curr[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            curr[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(curr[j] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
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

    fn known() -> Vec<String> {
        known_subcommands()
    }

    #[test]
    fn injects_run_for_unknown_command() {
        let result = maybe_inject_run(args(&["silo", "npm", "dev"]), &known());
        assert_eq!(result, args(&["silo", "run", "npm", "dev"]));
    }

    #[test]
    fn preserves_known_subcommand() {
        let known = known();
        for sub in &known {
            let result = maybe_inject_run(args(&["silo", sub]), &known);
            assert_eq!(
                result,
                args(&["silo", sub]),
                "should not inject run for {sub}"
            );
        }
    }

    #[test]
    fn preserves_flags() {
        let result = maybe_inject_run(args(&["silo", "--help"]), &known());
        assert_eq!(result, args(&["silo", "--help"]));
    }

    #[test]
    fn no_args_passthrough() {
        let result = maybe_inject_run(args(&["silo"]), &known());
        assert_eq!(result, args(&["silo"]));
    }

    #[test]
    fn injects_run_preserves_all_trailing_args() {
        let result = maybe_inject_run(
            args(&["silo", "node", "server.js", "--port", "3000"]),
            &known(),
        );
        assert_eq!(
            result,
            args(&["silo", "run", "node", "server.js", "--port", "3000"])
        );
    }

    #[test]
    fn unknown_subcommand_like_typo_gets_run_injected() {
        let result = maybe_inject_run(args(&["silo", "doctorx"]), &known());
        assert_eq!(result, args(&["silo", "run", "doctorx"]));
    }

    #[test]
    fn known_subcommands_includes_help() {
        let known = known();
        assert!(known.contains(&"help".to_string()));
    }

    #[test]
    fn closest_subcommand_exact_match_returns_none() {
        assert_eq!(closest_subcommand("doctor", &known()), None);
    }

    #[test]
    fn closest_subcommand_one_char_off() {
        assert_eq!(closest_subcommand("doctorx", &known()), Some("doctor"));
    }

    #[test]
    fn closest_subcommand_substitution() {
        assert_eq!(closest_subcommand("docter", &known()), Some("doctor"));
    }

    #[test]
    fn closest_subcommand_too_distant() {
        assert_eq!(closest_subcommand("xyz", &known()), None);
    }

    #[test]
    fn closest_subcommand_completely_unrelated() {
        assert_eq!(closest_subcommand("webpack", &known()), None);
    }

    #[test]
    fn edit_distance_identical() {
        assert_eq!(edit_distance("abc", "abc"), 0);
    }

    #[test]
    fn edit_distance_insertion() {
        assert_eq!(edit_distance("doctor", "doctorx"), 1);
    }

    #[test]
    fn edit_distance_deletion() {
        assert_eq!(edit_distance("doctor", "docto"), 1);
    }

    #[test]
    fn edit_distance_substitution() {
        assert_eq!(edit_distance("doctor", "docter"), 1);
    }

    #[test]
    fn edit_distance_empty() {
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(edit_distance("abc", ""), 3);
        assert_eq!(edit_distance("", ""), 0);
    }
}
