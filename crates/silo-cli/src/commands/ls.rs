use std::collections::HashMap;
use std::net::Ipv4Addr;

use colored::Colorize;
use tracing::debug;

use super::query;

pub fn run() -> eyre::Result<()> {
    let aliases = query::active_loopback_aliases()?;
    let hosts = load_silo_hosts();
    let ports = query::listening_ports();

    if aliases.is_empty() {
        eprintln!("  {} no active silo aliases", "○".dimmed());
    } else {
        eprintln!(
            "  {} {} active alias(es)",
            "●".green(),
            aliases.len().to_string().bold()
        );
        for ip in &aliases {
            if let Some(hostname) = hosts.get(ip) {
                eprintln!("    {} {} {}", ip, "·".dimmed(), hostname.dimmed());
            } else {
                eprintln!("    {}", ip);
            }
            if let Some(ip_ports) = ports.get(ip) {
                let port_list: Vec<String> = ip_ports.iter().map(|p| format!(":{}", p)).collect();
                eprintln!("      {}", port_list.join("  ").dimmed());
            }
        }
    }

    Ok(())
}

fn load_silo_hosts() -> HashMap<Ipv4Addr, String> {
    let mut map = HashMap::new();
    let Ok(content) = std::fs::read_to_string("/etc/hosts") else {
        debug!("failed to read /etc/hosts for status display");
        return map;
    };
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !trimmed.ends_with(".silo") {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        if let (Some(ip_str), Some(hostname)) = (parts.next(), parts.next())
            && let Ok(ip) = ip_str.parse::<Ipv4Addr>()
        {
            map.insert(ip, hostname.to_string());
        }
    }
    map
}
