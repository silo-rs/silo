#![forbid(unsafe_code)]

mod cli;
mod commands;
pub(crate) mod ui;

use clap::Parser;
use cli::{Cli, Commands};
use colored::Colorize;
use silo_core::store;
use tracing_subscriber::{fmt, EnvFilter};

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

async fn run() -> eyre::Result<()> {
    let cli = Cli::parse();
    let json = cli.json;

    match cli.command {
        Commands::Init { ip_range } => return commands::init::run(&ip_range),
        Commands::ShellInit => return commands::shell_init::run(),
        Commands::Completions { shell } => return commands::completions::run(shell),
        Commands::DefaultConfig => return commands::default_config::run(),
        _ => {}
    }

    let store = store::Store::open_default().await?;

    match cli.command {
        Commands::Add { name, path, branch, no_hooks } => {
            commands::add::run(&store, &name, path.as_deref(), branch.as_deref(), no_hooks, json).await
        }
        Commands::List { all } => commands::list::run(&store, all, json).await,
        Commands::Remove { name, force, no_hooks } => {
            commands::remove::run(&store, name.as_deref(), force, no_hooks, json).await
        }
        Commands::Env { instance } => commands::env::run(&store, instance.as_deref(), json).await,
        Commands::Info { name } => commands::info::run(&store, name.as_deref(), json).await,
        Commands::Dir { name } => commands::dir::run(&store, &name).await,
        Commands::Doctor => commands::doctor::run(&store).await,
        Commands::Activate => commands::activate::run(&store).await,
        Commands::Prune { force } => commands::prune::run(&store, force).await,
        Commands::Run { instance, name, no_hooks } => commands::run::run(&store, instance.as_deref(), name.as_deref(), no_hooks).await,
        Commands::Exec { instance, quiet, no_hooks, command } => commands::exec::run(&store, instance.as_deref(), &command, quiet, no_hooks).await,
        Commands::Hook { name, instance } => commands::hook::run(&store, &name, instance.as_deref()).await,
        Commands::Init { .. }
        | Commands::ShellInit
        | Commands::Completions { .. }
        | Commands::DefaultConfig => unreachable!(),
    }
}
