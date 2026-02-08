use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "silo", about = "Development environment isolation via loopback IP aliasing")]
#[command(version, propagate_version = true)]
pub struct Cli {
    /// Output results as JSON (machine-readable)
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
#[command(infer_subcommands = true)]
pub enum Commands {
    /// Initialize silo in the current repository
    Init {
        /// IP range in CIDR notation
        #[arg(long, default_value = "127.0.1.0/24")]
        ip_range: String,
    },

    /// Add a new isolated instance (creates a git worktree by default)
    Add {
        /// Name for the instance
        name: String,

        /// Use an existing directory instead of creating a worktree
        #[arg(long)]
        path: Option<String>,

        /// Git branch for the worktree (defaults to instance name)
        #[arg(long, conflicts_with = "path")]
        branch: Option<String>,

        /// Skip setup hooks
        #[arg(long)]
        no_hooks: bool,
    },

    /// List all instances for the current repository
    List {
        /// Show instances for all repositories
        #[arg(long)]
        all: bool,
    },

    /// Remove an instance and clean up resources
    Remove {
        /// Name of the instance (auto-detected from cwd if omitted)
        name: Option<String>,

        /// Skip confirmation prompt
        #[arg(long, short)]
        force: bool,

        /// Skip teardown hooks
        #[arg(long)]
        no_hooks: bool,
    },

    /// Output environment variables for the current instance (used by shell hook)
    Env {
        /// Target a specific instance by name (auto-detected from cwd if omitted)
        #[arg(long, short)]
        instance: Option<String>,
    },

    /// Show info about an instance (detected from working directory if omitted)
    Info {
        /// Name of the instance (auto-detected from cwd if omitted)
        name: Option<String>,
    },

    /// Restore IP aliases for all instances
    #[command(hide = true)]
    Activate,

    /// Print the path of an instance (used by shell integration)
    #[command(hide = true)]
    Dir {
        /// Name of the instance
        name: String,
    },

    /// Print shell integration script
    #[command(hide = true)]
    ShellInit,

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },

    /// Check environment and diagnose common problems
    Doctor,

    /// Remove orphaned instances (missing paths, stale aliases)
    Prune {
        /// Apply changes without confirmation
        #[arg(long, short)]
        force: bool,
    },

    /// Run a command defined in silo.toml [run] (omit name to list available commands)
    Run {
        /// Target a specific instance by name (auto-detected from cwd if omitted)
        #[arg(long, short)]
        instance: Option<String>,

        /// Name of the command defined in silo.toml (omit to list)
        name: Option<String>,

        /// Skip enter hooks
        #[arg(long)]
        no_hooks: bool,
    },

    /// Execute a command with automatic bind() interception
    Exec {
        /// Target a specific instance by name (auto-detected from cwd if omitted)
        #[arg(long, short)]
        instance: Option<String>,

        /// Suppress the instance banner
        #[arg(long, short)]
        quiet: bool,

        /// Skip enter hooks
        #[arg(long)]
        no_hooks: bool,

        /// Command and arguments to run
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Run hooks manually (setup, enter, teardown)
    Hook {
        /// Hook name to run
        name: String,

        /// Target a specific instance by name (auto-detected from cwd if omitted)
        #[arg(long, short)]
        instance: Option<String>,
    },

    /// Print the default silo.toml configuration
    DefaultConfig,
}
