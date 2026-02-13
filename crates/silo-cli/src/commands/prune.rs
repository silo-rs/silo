use std::collections::HashSet;
use std::io::{self, Write};
use std::net::Ipv4Addr;

use colored::Colorize;

use super::query;

pub fn run(all: bool, yes: bool) -> eyre::Result<()> {
    let aliases = query::active_loopback_aliases()?;
    let listening = query::listening_ports();
    let host_entries = silo::hosts::list_entries().unwrap_or_default();

    let alias_set: HashSet<Ipv4Addr> = aliases.iter().copied().collect();

    // Determine which aliases to remove
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

    // Orphaned hosts: entries whose IP has no active alias
    let orphaned_host_ips: HashSet<Ipv4Addr> = host_entries
        .iter()
        .map(|(ip, _)| *ip)
        .filter(|ip| !alias_set.contains(ip))
        .collect();

    // Hosts IPs to remove: aliases being removed + orphaned entries
    let hosts_ips_to_remove: HashSet<Ipv4Addr> = if all {
        let all_host_ips: HashSet<Ipv4Addr> = host_entries.iter().map(|(ip, _)| *ip).collect();
        remove_set.union(&all_host_ips).copied().collect()
    } else {
        remove_set.union(&orphaned_host_ips).copied().collect()
    };

    let hosts_to_remove: Vec<&(Ipv4Addr, String)> = host_entries
        .iter()
        .filter(|(ip, _)| hosts_ips_to_remove.contains(ip))
        .collect();

    // Nothing to do
    if aliases_to_remove.is_empty() && hosts_to_remove.is_empty() {
        eprintln!("  {} nothing to prune", "✓".green());
        return Ok(());
    }

    // Preview
    if !aliases_to_remove.is_empty() {
        eprintln!(
            "  {} {} alias(es) to remove:",
            "●".yellow(),
            aliases_to_remove.len().to_string().bold()
        );
        for ip in &aliases_to_remove {
            let hostname = host_entries
                .iter()
                .find(|(h_ip, _)| h_ip == ip)
                .map(|(_, h)| h.as_str());
            if let Some(h) = hostname {
                eprintln!("    {} {} {}", ip, "·".dimmed(), h.dimmed());
            } else {
                eprintln!("    {}", ip);
            }
        }
    }

    let orphan_only: Vec<_> = hosts_to_remove
        .iter()
        .filter(|(ip, _)| !remove_set.contains(ip))
        .collect();
    if !orphan_only.is_empty() {
        eprintln!(
            "  {} {} orphaned host(s) to remove:",
            "●".yellow(),
            orphan_only.len().to_string().bold()
        );
        for (ip, hostname) in &orphan_only {
            eprintln!("    {} {} {}", ip, "·".dimmed(), hostname.dimmed());
        }
    }

    // Confirmation
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

    eprintln!();

    // Remove aliases
    let mut alias_errors = 0usize;
    for ip in &aliases_to_remove {
        if let Err(e) = silo::ip::remove_alias(*ip) {
            eprintln!("  {} failed to remove alias {}: {}", "✗".red(), ip, e);
            alias_errors += 1;
        }
    }

    // Remove hosts entries
    if !hosts_ips_to_remove.is_empty() {
        match silo::hosts::remove_entries(&hosts_ips_to_remove) {
            Ok(removed) if !removed.is_empty() => {
                eprintln!(
                    "  {} removed {} host(s) from /etc/hosts",
                    "✓".green(),
                    removed.len()
                );
            }
            Err(e) => {
                eprintln!("  {} failed to update /etc/hosts: {}", "✗".red(), e);
            }
            _ => {}
        }
    }

    // Summary
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

    // Clean up stale eBPF state (Linux only)
    #[cfg(target_os = "linux")]
    {
        let cgroups_removed = crate::ebpf::prune_stale_cgroups();
        if cgroups_removed > 0 {
            eprintln!(
                "  {} pruned {} stale cgroup(s)",
                "✓".green(),
                cgroups_removed
            );
        }

        let map_removed = crate::ebpf::prune_config_map();
        if map_removed > 0 {
            eprintln!(
                "  {} pruned {} stale config map entry(ies)",
                "✓".green(),
                map_removed
            );
        }
    }

    Ok(())
}
