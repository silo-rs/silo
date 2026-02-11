use clap::CommandFactory;
use clap_complete::generate;

use crate::cli::Cli;

pub fn run(shell: clap_complete::Shell) -> eyre::Result<()> {
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "silo", &mut std::io::stdout());
    Ok(())
}
