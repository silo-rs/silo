#![deny(unsafe_code)]

fn main() -> eyre::Result<()> {
    let request: silo::ip::IpRequest = serde_json::from_reader(std::io::stdin().lock())?;
    silo::ip::run_ip_direct(&request)?;
    Ok(())
}
