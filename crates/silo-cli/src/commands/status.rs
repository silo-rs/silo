use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;

use colored::Colorize;
use eyre::Context;

pub fn run() -> eyre::Result<()> {
    let aliases = active_loopback_aliases()?;
    let hosts = load_silo_hosts();

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
        }
    }

    Ok(())
}

fn active_loopback_aliases() -> eyre::Result<Vec<Ipv4Addr>> {
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

fn load_silo_hosts() -> HashMap<Ipv4Addr, String> {
    let mut map = HashMap::new();
    let Ok(content) = std::fs::read_to_string("/etc/hosts") else {
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
