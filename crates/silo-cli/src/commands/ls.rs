use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use colored::Colorize;
use serde::Serialize;

use super::query;

#[derive(Serialize)]
struct AliasEntry {
    ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dir: Option<PathBuf>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ports: Vec<u16>,
}

struct HostInfo {
    hostname: String,
    dir: Option<PathBuf>,
}

pub fn run(json: bool) -> eyre::Result<()> {
    let aliases = query::active_loopback_aliases()?;
    let hosts = load_silo_hosts();
    let ports = query::listening_ports();

    if json {
        let entries: Vec<AliasEntry> = aliases
            .iter()
            .map(|ip| {
                let info = hosts.get(ip);
                AliasEntry {
                    ip: ip.to_string(),
                    hostname: info.map(|i| i.hostname.clone()),
                    dir: info.and_then(|i| i.dir.clone()),
                    ports: ports.get(ip).cloned().unwrap_or_default(),
                }
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else if aliases.is_empty() {
        eprintln!("  {} no active silo aliases", "○".dimmed());
    } else {
        eprintln!(
            "  {} {} active alias(es)",
            "●".green(),
            aliases.len().to_string().bold()
        );
        for ip in &aliases {
            if let Some(info) = hosts.get(ip) {
                eprint!("    {} {} {}", ip, "·".dimmed(), info.hostname.dimmed());
                if let Some(dir) = &info.dir {
                    eprint!("  {}", dir.display().to_string().dimmed());
                }
                eprintln!();
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

fn load_silo_hosts() -> HashMap<Ipv4Addr, HostInfo> {
    let Ok(entries) = silo::hosts::list_entries() else {
        return HashMap::new();
    };
    entries
        .into_iter()
        .map(|e| {
            (
                e.ip,
                HostInfo {
                    hostname: e.hostname,
                    dir: e.dir,
                },
            )
        })
        .collect()
}
