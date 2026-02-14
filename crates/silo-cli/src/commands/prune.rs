use std::collections::HashSet;
use std::io::{self, Write};
use std::net::Ipv4Addr;

use colored::Colorize;
use serde::Serialize;

use super::query;

#[derive(Serialize)]
struct PruneReport {
    aliases_removed: Vec<String>,
    hosts_removed: Vec<HostRemoved>,
    alias_errors: usize,
}

#[derive(Serialize)]
struct HostRemoved {
    ip: String,
    hostname: String,
}

pub fn run(all: bool, yes: bool, json: bool) -> eyre::Result<()> {
    let aliases = query::active_loopback_aliases()?;
    let listening = query::listening_ports();
    let host_entries = silo::hosts::list_entries().unwrap_or_default();

    let alias_set: HashSet<Ipv4Addr> = aliases.iter().copied().collect();

    let aliases_to_remove: Vec<Ipv4Addr> = if all {
        aliases.clone()
    } else {
        aliases
            .iter()
            .filter(|ip| !listening.contains_key(ip))
            .copied()
            .collect()
    };

    let remove_set: HashSet<Ipv4Addr> = aliases_to_remove.iter().copied().collect();

    let orphaned_host_ips: HashSet<Ipv4Addr> = host_entries
        .iter()
        .map(|e| e.ip)
        .filter(|ip| !alias_set.contains(ip))
        .collect();

    let hosts_ips_to_remove: HashSet<Ipv4Addr> = if all {
        let all_host_ips: HashSet<Ipv4Addr> = host_entries.iter().map(|e| e.ip).collect();
        remove_set.union(&all_host_ips).copied().collect()
    } else {
        remove_set.union(&orphaned_host_ips).copied().collect()
    };

    let hosts_to_remove: Vec<_> = host_entries
        .iter()
        .filter(|e| hosts_ips_to_remove.contains(&e.ip))
        .collect();

    if aliases_to_remove.is_empty() && hosts_to_remove.is_empty() {
        if json {
            let report = PruneReport {
                aliases_removed: vec![],
                hosts_removed: vec![],
                alias_errors: 0,
            };
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            eprintln!("  {} nothing to prune", "✓".green());
        }
        return Ok(());
    }

    if !json {
        if !aliases_to_remove.is_empty() {
            eprintln!(
                "  {} {} alias(es) to remove:",
                "●".yellow(),
                aliases_to_remove.len().to_string().bold()
            );
            for ip in &aliases_to_remove {
                let hostname = host_entries
                    .iter()
                    .find(|e| e.ip == *ip)
                    .map(|e| e.hostname.as_str());
                if let Some(h) = hostname {
                    eprintln!("    {} {} {}", ip, "·".dimmed(), h.dimmed());
                } else {
                    eprintln!("    {}", ip);
                }
            }
        }

        let orphan_only: Vec<_> = hosts_to_remove
            .iter()
            .filter(|e| !remove_set.contains(&e.ip))
            .collect();
        if !orphan_only.is_empty() {
            eprintln!(
                "  {} {} orphaned host(s) to remove:",
                "●".yellow(),
                orphan_only.len().to_string().bold()
            );
            for entry in &orphan_only {
                eprintln!(
                    "    {} {} {}",
                    entry.ip,
                    "·".dimmed(),
                    entry.hostname.dimmed()
                );
            }
        }
    }

    crate::sudoers::ensure()?;

    if !yes {
        eprintln!();
        eprint!("  proceed? [y/N] ");
        io::stderr().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !matches!(input.trim().to_lowercase().as_str(), "y" | "yes") {
            eprintln!("  {} cancelled", "○".dimmed());
            return Ok(());
        }
    }

    if !json {
        eprintln!();
    }

    let mut alias_errors = 0usize;
    let mut aliases_removed = Vec::new();
    for ip in &aliases_to_remove {
        if let Err(e) = silo::ip::remove_alias(*ip) {
            if !json {
                eprintln!("  {} failed to remove alias {}: {}", "✗".red(), ip, e);
            }
            alias_errors += 1;
        } else {
            aliases_removed.push(ip.to_string());
        }
    }

    let mut hosts_removed = Vec::new();
    if !hosts_ips_to_remove.is_empty() {
        match silo::hosts::remove_entries(&hosts_ips_to_remove) {
            Ok(removed) if !removed.is_empty() => {
                if !json {
                    eprintln!(
                        "  {} removed {} host(s) from /etc/hosts",
                        "✓".green(),
                        removed.len()
                    );
                }
                for (ip, hostname) in removed {
                    hosts_removed.push(HostRemoved {
                        ip: ip.to_string(),
                        hostname,
                    });
                }
            }
            Err(e) => {
                if !json {
                    eprintln!("  {} failed to update /etc/hosts: {}", "✗".red(), e);
                }
            }
            _ => {}
        }
    }

    if json {
        let report = PruneReport {
            aliases_removed,
            hosts_removed,
            alias_errors,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let removed_count = aliases_to_remove.len() - alias_errors;
        if removed_count > 0 {
            if alias_errors == 0 {
                eprintln!("  {} pruned {} alias(es)", "✓".green(), removed_count);
            } else {
                eprintln!(
                    "  {} pruned {} alias(es), {} failed",
                    "⚠".yellow(),
                    removed_count,
                    alias_errors
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let cgroups_removed = crate::ebpf::prune_stale_cgroups();
        if !json && cgroups_removed > 0 {
            eprintln!(
                "  {} pruned {} stale cgroup(s)",
                "✓".green(),
                cgroups_removed
            );
        }

        let map_removed = crate::ebpf::prune_config_map();
        if !json && map_removed > 0 {
            eprintln!(
                "  {} pruned {} stale config map entry(ies)",
                "✓".green(),
                map_removed
            );
        }
    }

    Ok(())
}
