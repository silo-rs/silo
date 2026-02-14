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
    Run {
        #[arg(long, short = 'n')]
        name: Option<String>,

        #[arg(long)]
        ip: Option<std::net::Ipv4Addr>,

        #[arg(long, short)]
        quiet: bool,

        #[arg(long)]
        emit_json: bool,

        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    Env {
        #[arg(long, short = 'n')]
        name: Option<String>,

        #[arg(long)]
        ip: Option<std::net::Ipv4Addr>,

        #[arg(long)]
        json: bool,
    },

    Ip {
        #[arg(long)]
        json: bool,
    },

    Doctor {
        #[arg(long)]
        json: bool,
    },

    Ls {
        #[arg(long)]
        json: bool,
    },

    Prune {
        #[arg(long)]
        all: bool,

        #[arg(long, short)]
        yes: bool,

        #[arg(long)]
        json: bool,
    },

    #[cfg(target_os = "linux")]
    SetupEbpf,

    #[cfg(target_os = "linux")]
    TeardownEbpf,

    #[command(name = "_hosts", hide = true)]
    Hosts {
        #[command(subcommand)]
        action: HostsAction,
    },
}

#[derive(Subcommand)]
pub enum HostsAction {
    Add {
        ip: std::net::Ipv4Addr,
        hostname: String,
        dir: String,
    },
    Remove {
        #[arg(required = true)]
        ips: Vec<std::net::Ipv4Addr>,
    },
}
