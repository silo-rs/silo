use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;

use eyre::Context;

pub fn active_loopback_aliases() -> eyre::Result<Vec<Ipv4Addr>> {
    let output = loopback_output()?;
    let mut aliases = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();

        let rest = if let Some(r) = trimmed.strip_prefix("inet ") {
            r
        } else {
            continue;
        };

        let ip_str = rest.split_whitespace().next().unwrap_or("");
        let ip_str = ip_str.split('/').next().unwrap_or(ip_str);

        if let Ok(ip) = ip_str.parse::<Ipv4Addr>()
            && ip != Ipv4Addr::new(127, 0, 0, 1)
            && ip.octets()[0] == 127
        {
            aliases.push(ip);
        }
    }

    Ok(aliases)
}

pub fn listening_ports() -> HashMap<Ipv4Addr, Vec<u16>> {
    let output = match listening_ports_output() {
        Ok(o) => o,
        Err(_) => return HashMap::new(),
    };
    parse_listening_ports(&output)
}

fn loopback_output() -> eyre::Result<String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("ifconfig")
            .arg("lo0")
            .output()
            .context("failed to run ifconfig")?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["addr", "show", "lo"])
            .output()
            .context("failed to run ip addr show lo")?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

fn listening_ports_output() -> eyre::Result<String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("lsof")
            .args(["-nP", "-iTCP", "-sTCP:LISTEN"])
            .output()
            .context("failed to run lsof")?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ss")
            .args(["-tlnH"])
            .output()
            .context("failed to run ss")?;
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
