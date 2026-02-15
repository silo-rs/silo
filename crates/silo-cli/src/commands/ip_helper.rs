use silo::ip::{self, IpRequest};

pub fn run_from_stdin() -> eyre::Result<()> {
    let request: IpRequest = serde_json::from_reader(std::io::stdin().lock())?;
    ip::run_ip_direct(&request)?;
    Ok(())
}
