use std::collections::HashSet;
use std::io::Write;
use std::net::Ipv4Addr;

use silo::hosts;

pub fn run_add(ip: Ipv4Addr, hostname: &str, dir: &str) -> eyre::Result<()> {
    hosts::validate_ip(ip)?;
    hosts::validate_hostname(hostname)?;
    hosts::validate_dir(dir)?;

    let mut lock = hosts::open_helper_lock()?;
    let _guard = lock
        .write()
        .map_err(|e| eyre::eyre!("failed to acquire hosts lock: {}", e))?;

    let content = std::fs::read_to_string(hosts::HOSTS_PATH)
        .map_err(|e| eyre::eyre!("failed to read /etc/hosts: {}", e))?;
    let (before, mut entries, after) = hosts::parse_block(&content);

    let new_line = format!("{}\t{}\t# {}", ip, hostname, dir);

    if let Some(pos) = entries
        .iter()
        .position(|e| e.split('\t').nth(1).map(|h| h == hostname).unwrap_or(false))
    {
        if entries[pos] == new_line {
            return Ok(());
        }
        entries[pos] = new_line;
    } else {
        entries.push(new_line);
    }

    let output = hosts::rebuild(before, &entries, after);
    hosts::write_hosts_direct(&output)?;

    Ok(())
}

pub fn run_remove(ips: &[Ipv4Addr]) -> eyre::Result<()> {
    for ip in ips {
        hosts::validate_ip(*ip)?;
    }
    let ip_set: HashSet<Ipv4Addr> = ips.iter().copied().collect();

    let mut lock = hosts::open_helper_lock()?;
    let _guard = lock
        .write()
        .map_err(|e| eyre::eyre!("failed to acquire hosts lock: {}", e))?;

    let content = std::fs::read_to_string(hosts::HOSTS_PATH)
        .map_err(|e| eyre::eyre!("failed to read /etc/hosts: {}", e))?;
    let (before, entries, after) = hosts::parse_block(&content);

    let mut removed = Vec::new();
    let mut kept = Vec::new();

    for entry in &entries {
        let entry_ip: Option<Ipv4Addr> = entry.split('\t').next().and_then(|s| s.parse().ok());
        if let Some(ip) = entry_ip
            && ip_set.contains(&ip)
        {
            let main = entry.split_once("\t# ").map_or(entry.as_str(), |(m, _)| m);
            let hostname = main.split('\t').nth(1).unwrap_or("");
            removed.push((ip, hostname.to_string()));
            continue;
        }
        kept.push(entry.clone());
    }

    if !removed.is_empty() {
        let output = hosts::rebuild(before, &kept, after);
        hosts::write_hosts_direct(&output)?;
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for (ip, hostname) in &removed {
        writeln!(out, "{}\t{}", ip, hostname)?;
    }

    Ok(())
}
