use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "silo",
    about = "silo — syscall interception on loopback",
    after_help = "Tip: `silo <cmd>` is shorthand for `silo run <cmd>`"
)]
#[command(version, propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run a command with automatic bind() interception
    Run {
        /// Override name (default: git branch)
        #[arg(long, short = 'n')]
        name: Option<String>,

        /// Suppress the silo banner
        #[arg(long, short)]
        quiet: bool,

        /// Command and arguments to run
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Show the resolved IP for the current directory
    Ip,

    /// Check environment and diagnose common problems
    Doctor,

    /// List active silo sessions
    Ls,

    /// Remove unused loopback aliases and /etc/hosts entries
    Prune {
        /// Remove ALL aliases and hosts entries, even those with active ports
        #[arg(long)]
        all: bool,

        /// Skip confirmation prompt
        #[arg(long, short)]
        yes: bool,
    },

    /// Load and pin eBPF programs for rootless operation (requires sudo, Linux only)
    #[cfg(target_os = "linux")]
    SetupEbpf,

    /// Remove pinned eBPF programs (requires sudo, Linux only)
    #[cfg(target_os = "linux")]
    TeardownEbpf,
}
