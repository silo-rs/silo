use std::collections::HashSet;
use std::net::Ipv4Addr;

use fd_lock::RwLock;

use super::block;
use super::validate::{validate_dir, validate_hostname, validate_ip};
use super::{HOSTS_PATH, HostsRequest, RemovedEntry};
use crate::error::SessionError;

const HELPER_LOCK_PATH: &str = "/etc/.silo-hosts.lock";

pub fn run_hosts_direct(request: &HostsRequest) -> Result<Vec<RemovedEntry>, SessionError> {
    match request {
        HostsRequest::Add { ip, hostname, dir } => {
            run_direct_add(*ip, hostname, dir)?;
            Ok(Vec::new())
        }
        HostsRequest::Remove { ips } => run_direct_remove(ips),
    }
}

fn run_direct_add(ip: Ipv4Addr, hostname: &str, dir: &str) -> Result<(), SessionError> {
    validate_ip(ip)?;
    validate_hostname(hostname)?;
    validate_dir(dir)?;

    let mut lock = open_helper_lock()?;
    let _guard = lock
        .write()
        .map_err(|e| SessionError::io("failed to acquire hosts lock", e))?;

    let content = std::fs::read_to_string(HOSTS_PATH)
        .map_err(|e| SessionError::io("failed to read /etc/hosts", e))?;
    let (before, mut entries, after) = block::parse_block(&content);

    let new_line = format!("{}\t{}\t# {}", ip, hostname, dir);

    if let Some(conflict) = block::find_ip_conflict(&entries, ip, hostname) {
        return Err(SessionError::IpCollision {
            ip,
            existing: conflict,
            new: hostname.to_string(),
        });
    }

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

    let output = block::rebuild(before, &entries, after);
    write_hosts_direct(&output)?;

    Ok(())
}

fn run_direct_remove(ips: &[Ipv4Addr]) -> Result<Vec<RemovedEntry>, SessionError> {
    for ip in ips {
        validate_ip(*ip)?;
    }
    let ip_set: HashSet<Ipv4Addr> = ips.iter().copied().collect();

    let mut lock = open_helper_lock()?;
    let _guard = lock
        .write()
        .map_err(|e| SessionError::io("failed to acquire hosts lock", e))?;

    let content = std::fs::read_to_string(HOSTS_PATH)
        .map_err(|e| SessionError::io("failed to read /etc/hosts", e))?;
    let (before, entries, after) = block::parse_block(&content);

    let mut removed = Vec::new();
    let mut kept = Vec::new();

    for entry in &entries {
        let entry_ip: Option<Ipv4Addr> = entry.split('\t').next().and_then(|s| s.parse().ok());
        if let Some(ip) = entry_ip
            && ip_set.contains(&ip)
        {
            let main = entry.split_once("\t# ").map_or(entry.as_str(), |(m, _)| m);
            let hostname = main.split('\t').nth(1).unwrap_or("").to_string();
            removed.push(RemovedEntry { ip, hostname });
            continue;
        }
        kept.push(entry.clone());
    }

    if !removed.is_empty() {
        let output = block::rebuild(before, &kept, after);
        write_hosts_direct(&output)?;
    }

    Ok(removed)
}

pub fn open_helper_lock() -> Result<RwLock<std::fs::File>, SessionError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(HELPER_LOCK_PATH)
        .map_err(|e| SessionError::io("failed to open silo hosts lock file", e))?;
    Ok(RwLock::new(file))
}

pub fn write_hosts_direct(content: &str) -> Result<(), SessionError> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let mut file = tempfile::NamedTempFile::new_in("/etc")
        .map_err(|e| SessionError::io("failed to create temp hosts file", e))?;

    file.write_all(content.as_bytes())
        .map_err(|e| SessionError::io("failed to write temp hosts file", e))?;

    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o644))
        .map_err(|e| SessionError::io("failed to set permissions on temp hosts file", e))?;

    file.as_file()
        .sync_all()
        .map_err(|e| SessionError::io("failed to sync temp hosts file", e))?;

    file.persist(HOSTS_PATH)
        .map_err(|e| SessionError::io("failed to rename temp hosts to /etc/hosts", e.into()))?;

    let readback = std::fs::read_to_string(HOSTS_PATH)
        .map_err(|e| SessionError::io("failed to verify /etc/hosts after write", e))?;
    if readback != content {
        tracing::warn!("/etc/hosts content changed after write — possible concurrent modification");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_hosts_direct_add_rejects_non_loopback() {
        let req = HostsRequest::Add {
            ip: Ipv4Addr::new(10, 0, 0, 1),
            hostname: "test.silo".into(),
            dir: "/tmp/test".into(),
        };
        assert!(run_hosts_direct(&req).is_err());
    }

    #[test]
    fn run_hosts_direct_add_rejects_localhost() {
        let req = HostsRequest::Add {
            ip: Ipv4Addr::new(127, 0, 0, 1),
            hostname: "test.silo".into(),
            dir: "/tmp/test".into(),
        };
        assert!(run_hosts_direct(&req).is_err());
    }

    #[test]
    fn run_hosts_direct_add_rejects_bad_hostname() {
        let req = HostsRequest::Add {
            ip: Ipv4Addr::new(127, 0, 1, 1),
            hostname: "evil.com".into(),
            dir: "/tmp/test".into(),
        };
        assert!(run_hosts_direct(&req).is_err());
    }

    #[test]
    fn run_hosts_direct_add_rejects_hostname_injection() {
        let req = HostsRequest::Add {
            ip: Ipv4Addr::new(127, 0, 1, 1),
            hostname: "foo.silo\n127.0.0.1 evil".into(),
            dir: "/tmp/test".into(),
        };
        assert!(run_hosts_direct(&req).is_err());
    }

    #[test]
    fn run_hosts_direct_add_rejects_bad_dir() {
        let req = HostsRequest::Add {
            ip: Ipv4Addr::new(127, 0, 1, 1),
            hostname: "test.silo".into(),
            dir: "/tmp\n/evil".into(),
        };
        assert!(run_hosts_direct(&req).is_err());
    }

    #[test]
    fn run_hosts_direct_remove_rejects_non_loopback() {
        let req = HostsRequest::Remove {
            ips: vec![Ipv4Addr::new(10, 0, 0, 1)],
        };
        assert!(run_hosts_direct(&req).is_err());
    }
}
