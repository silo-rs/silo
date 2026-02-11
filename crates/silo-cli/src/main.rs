#![forbid(unsafe_code)]

mod cli;
mod commands;
pub(crate) mod ui;

use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;
use silo::store;
use tracing_subscriber::{EnvFilter, fmt};

const KNOWN_SUBCOMMANDS: &[&str] = &[
    "init",
    "add",
    "list",
    "remove",
    "env",
    "info",
    "doctor",
    "prune",
    "run",
    "scripts",
    "hook",
    "activate",
    "dir",
    "shell-init",
    "completions",
    "default-config",
    "help",
];

fn main() {
    init_tracing();
    color_eyre::install().ok();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    if let Err(err) = rt.block_on(run()) {
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

/// Find the first positional arg, skipping global flags.
fn first_positional_arg() -> Option<String> {
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--json" | "--yes" | "-y" => continue,
            s if s.starts_with('-') => return None,
            _ => return Some(arg),
        }
    }
    None
}

async fn run() -> eyre::Result<()> {
    // Two-phase parsing: try config script before clap
    if let Some(candidate) = first_positional_arg()
        && !KNOWN_SUBCOMMANDS.contains(&candidate.as_str())
    {
        let store = store::Store::open_default().await?;
        return commands::scripts::run_script(&store, &candidate, false).await;
    }

    let cli = Cli::parse();
    let json = cli.json;
    let yes = cli.yes;

    match cli.command {
        Commands::Init { ip_range } => return commands::init::run(&ip_range),
        Commands::ShellInit => return commands::shell_init::run(),
        Commands::Completions { shell } => return commands::completions::run(shell),
        Commands::DefaultConfig => return commands::default_config::run(),
        Commands::Scripts { names_only } => return commands::scripts::list_scripts(names_only),
        _ => {}
    }

    let store = store::Store::open_default().await?;

    match cli.command {
        Commands::Add {
            name,
            path,
            branch,
            no_hooks,
        } => {
            commands::add::run(
                &store,
                &name,
                path.as_deref(),
                branch.as_deref(),
                no_hooks,
                json,
            )
            .await
        }
        Commands::List { all } => commands::list::run(&store, all, json).await,
        Commands::Remove { name, no_hooks } => {
            commands::remove::run(&store, name.as_deref(), yes, no_hooks, json).await
        }
        Commands::Env { instance } => commands::env::run(&store, instance.as_deref(), json).await,
        Commands::Info { name } => commands::info::run(&store, name.as_deref(), json).await,
        Commands::Dir { name } => commands::dir::run(&store, &name).await,
        Commands::Doctor => commands::doctor::run(&store).await,
        Commands::Activate => commands::activate::run(&store).await,
        Commands::Prune => commands::prune::run(&store, yes).await,
        Commands::Run {
            instance,
            quiet,
            no_hooks,
            command,
        } => commands::run::run(&store, instance.as_deref(), &command, quiet, no_hooks).await,
        Commands::Hook { name, instance } => {
            commands::hook::run(&store, &name, instance.as_deref()).await
        }
        Commands::Init { .. }
        | Commands::ShellInit
        | Commands::Completions { .. }
        | Commands::DefaultConfig
        | Commands::Scripts { .. } => unreachable!(),
    }
}
