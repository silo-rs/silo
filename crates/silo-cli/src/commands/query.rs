use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;

use tracing::debug;

pub fn active_loopback_aliases() -> eyre::Result<Vec<Ipv4Addr>> {
    Ok(silo::ip::active_aliases()?)
}

pub fn listening_ports() -> HashMap<Ipv4Addr, Vec<u16>> {
    let output = match listening_ports_output() {
        Ok(o) => o,
        Err(e) => {
            debug!("failed to get listening ports: {e}");
            return HashMap::new();
        }
    };
    parse_listening_ports(&output)
}

fn listening_ports_output() -> eyre::Result<String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("lsof")
            .args(["-nP", "-iTCP", "-sTCP:LISTEN"])
            .output()?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ss").args(["-tlnH"]).output()?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

fn parse_listening_ports(output: &str) -> HashMap<Ipv4Addr, Vec<u16>> {
    let mut map: HashMap<Ipv4Addr, Vec<u16>> = HashMap::new();

    for line in output.lines() {
        let addr_port = extract_listen_address(line);
        let Some((ip_str, port_str)) = addr_port else {
            continue;
        };
        let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
            continue;
        };
        if ip.octets()[0] != 127 || ip == Ipv4Addr::new(127, 0, 0, 1) {
            continue;
        }
        let Ok(port) = port_str.parse::<u16>() else {
            continue;
        };
        let ports = map.entry(ip).or_default();
        if !ports.contains(&port) {
            ports.push(port);
        }
    }

    for ports in map.values_mut() {
        ports.sort();
    }

    map
}

fn extract_listen_address(line: &str) -> Option<(&str, &str)> {
    // macOS lsof format: "... TCP 127.1.42.7:3000 (LISTEN)"
    // Linux ss format:   "LISTEN  0  128  127.1.42.7:3000  ..."
    #[cfg(target_os = "macos")]
    {
        let addr_part = line.split_whitespace().find(|tok| {
            tok.contains(':')
                && tok
                    .split(':')
                    .next()
                    .is_some_and(|ip| ip.starts_with("127."))
        })?;
        let (ip, port) = addr_part.rsplit_once(':')?;
        Some((ip, port))
    }

    #[cfg(target_os = "linux")]
    {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // ss -tlnH columns: State Recv-Q Send-Q Local Address:Port Peer Address:Port
        let local = fields.get(3)?;
        let (ip, port) = local.rsplit_once(':')?;
        Some((ip, port))
    }
}
