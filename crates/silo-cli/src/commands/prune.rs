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

struct PrunePlan {
    aliases_to_remove: Vec<Ipv4Addr>,
    hosts_ips_to_remove: HashSet<Ipv4Addr>,
}

fn compute_prune_plan(
    aliases: &[Ipv4Addr],
    listening: &std::collections::HashMap<Ipv4Addr, Vec<u16>>,
    host_entries: &[silo::hosts::HostEntry],
    all: bool,
) -> PrunePlan {
    let alias_set: HashSet<Ipv4Addr> = aliases.iter().copied().collect();

    let aliases_to_remove: Vec<Ipv4Addr> = if all {
        aliases.to_vec()
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

    PrunePlan {
        aliases_to_remove,
        hosts_ips_to_remove,
    }
}

pub fn run(all: bool, yes: bool, json: bool) -> eyre::Result<()> {
    let aliases = query::active_loopback_aliases()?;
    let listening = query::listening_ports();
    let host_entries = silo::hosts::list_entries().unwrap_or_default();

    let plan = compute_prune_plan(&aliases, &listening, &host_entries, all);
    let PrunePlan {
        aliases_to_remove,
        hosts_ips_to_remove,
    } = &plan;

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
        let remove_set: HashSet<Ipv4Addr> = aliases_to_remove.iter().copied().collect();
        print_preview(
            aliases_to_remove,
            &hosts_to_remove,
            &host_entries,
            &remove_set,
        );
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

    let (aliases_removed, alias_errors) = execute_alias_removal(aliases_to_remove, json);
    let hosts_removed = execute_hosts_removal(hosts_ips_to_remove, json);

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
    prune_linux_resources(json);

    Ok(())
}

fn print_preview(
    aliases_to_remove: &[Ipv4Addr],
    hosts_to_remove: &[&silo::hosts::HostEntry],
    host_entries: &[silo::hosts::HostEntry],
    remove_set: &HashSet<Ipv4Addr>,
) {
    if !aliases_to_remove.is_empty() {
        eprintln!(
            "  {} {} alias(es) to remove:",
            "●".yellow(),
            aliases_to_remove.len().to_string().bold()
        );
        for ip in aliases_to_remove {
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

fn execute_alias_removal(aliases_to_remove: &[Ipv4Addr], json: bool) -> (Vec<String>, usize) {
    let mut alias_errors = 0usize;
    let mut aliases_removed = Vec::new();
    for ip in aliases_to_remove {
        if let Err(e) = silo::ip::remove_alias(*ip) {
            if !json {
                eprintln!("  {} failed to remove alias {}: {}", "✗".red(), ip, e);
            }
            alias_errors += 1;
        } else {
            aliases_removed.push(ip.to_string());
        }
    }
    (aliases_removed, alias_errors)
}

fn execute_hosts_removal(hosts_ips_to_remove: &HashSet<Ipv4Addr>, json: bool) -> Vec<HostRemoved> {
    let mut hosts_removed = Vec::new();
    if !hosts_ips_to_remove.is_empty() {
        match silo::hosts::remove_entries(hosts_ips_to_remove) {
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
    hosts_removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn ip(a: u8, b: u8) -> Ipv4Addr {
        Ipv4Addr::new(127, 1, a, b)
    }

    fn host(addr: Ipv4Addr, name: &str) -> silo::hosts::HostEntry {
        silo::hosts::HostEntry {
            ip: addr,
            hostname: name.to_string(),
            dir: Some(PathBuf::from("/tmp")),
        }
    }

    #[test]
    fn empty_inputs_nothing_to_prune() {
        let plan = compute_prune_plan(&[], &HashMap::new(), &[], false);
        assert!(plan.aliases_to_remove.is_empty());
        assert!(plan.hosts_ips_to_remove.is_empty());
    }

    #[test]
    fn idle_alias_removed() {
        let a = ip(0, 1);
        let plan = compute_prune_plan(&[a], &HashMap::new(), &[], false);
        assert_eq!(plan.aliases_to_remove, vec![a]);
    }

    #[test]
    fn listening_alias_preserved() {
        let a = ip(0, 2);
        let mut listening = HashMap::new();
        listening.insert(a, vec![3000]);
        let plan = compute_prune_plan(&[a], &listening, &[], false);
        assert!(plan.aliases_to_remove.is_empty());
    }

    #[test]
    fn all_flag_removes_listening_alias() {
        let a = ip(0, 3);
        let mut listening = HashMap::new();
        listening.insert(a, vec![3000]);
        let plan = compute_prune_plan(&[a], &listening, &[], true);
        assert_eq!(plan.aliases_to_remove, vec![a]);
    }

    #[test]
    fn orphaned_host_detected() {
        let orphan_ip = ip(0, 10);
        let entries = vec![host(orphan_ip, "orphan.test")];
        let plan = compute_prune_plan(&[], &HashMap::new(), &entries, false);
        assert!(plan.aliases_to_remove.is_empty());
        assert!(plan.hosts_ips_to_remove.contains(&orphan_ip));
    }

    #[test]
    fn host_with_active_alias_not_orphaned() {
        let a = ip(0, 11);
        let entries = vec![host(a, "active.test")];
        let mut listening = HashMap::new();
        listening.insert(a, vec![8080]);
        let plan = compute_prune_plan(&[a], &listening, &entries, false);
        assert!(plan.aliases_to_remove.is_empty());
        assert!(plan.hosts_ips_to_remove.is_empty());
    }

    #[test]
    fn idle_alias_also_removes_its_host() {
        let a = ip(0, 12);
        let entries = vec![host(a, "idle.test")];
        let plan = compute_prune_plan(&[a], &HashMap::new(), &entries, false);
        assert_eq!(plan.aliases_to_remove, vec![a]);
        assert!(plan.hosts_ips_to_remove.contains(&a));
    }

    #[test]
    fn all_flag_removes_all_hosts() {
        let a = ip(0, 13);
        let b = ip(0, 14);
        let mut listening = HashMap::new();
        listening.insert(a, vec![3000]);
        let entries = vec![host(a, "a.test"), host(b, "b.test")];
        let plan = compute_prune_plan(&[a], &listening, &entries, true);
        assert!(plan.hosts_ips_to_remove.contains(&a));
        assert!(plan.hosts_ips_to_remove.contains(&b));
    }

    #[test]
    fn mixed_idle_and_listening() {
        let idle = ip(0, 20);
        let busy = ip(0, 21);
        let mut listening = HashMap::new();
        listening.insert(busy, vec![3000]);
        let entries = vec![host(idle, "idle.test"), host(busy, "busy.test")];

        let plan = compute_prune_plan(&[idle, busy], &listening, &entries, false);
        assert_eq!(plan.aliases_to_remove, vec![idle]);
        assert!(plan.hosts_ips_to_remove.contains(&idle));
        assert!(!plan.hosts_ips_to_remove.contains(&busy));
    }
}

#[cfg(target_os = "linux")]
fn prune_linux_resources(json: bool) {
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
