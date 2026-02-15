#![deny(unsafe_code)]

fn main() -> eyre::Result<()> {
    let request: silo::hosts::HostsRequest = serde_json::from_reader(std::io::stdin().lock())?;
    let removed = silo::hosts::run_hosts_direct(&request)?;
    serde_json::to_writer(std::io::stdout().lock(), &removed)?;
    Ok(())
}
