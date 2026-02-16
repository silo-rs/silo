use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};

use tracing::debug;

use super::{HostsRequest, RemovedEntry, SECURE_HOSTS_HELPER};
use crate::error::SessionError;

pub fn ensure_entry(ip: Ipv4Addr, hostname: &str, dir: &Path) -> Result<(), SessionError> {
    let request = HostsRequest::Add {
        ip,
        hostname: hostname.to_string(),
        dir: dir.display().to_string(),
    };

    let mut child = Command::new("sudo")
        .arg(SECURE_HOSTS_HELPER)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| SessionError::io("failed to run silo-hosts-helper", e))?;

    {
        let stdin = child.stdin.take().ok_or_else(|| {
            SessionError::io("stdin not available", std::io::ErrorKind::Other.into())
        })?;
        serde_json::to_writer(stdin, &request).map_err(|e| {
            SessionError::io("failed to write to silo-hosts-helper stdin", e.into())
        })?;
    }

    let status = child
        .wait()
        .map_err(|e| SessionError::io("failed to wait for silo-hosts-helper", e))?;

    if !status.success() {
        return Err(SessionError::CommandFailed {
            command: format!("sudo {} (add {} {})", SECURE_HOSTS_HELPER, ip, hostname),
            status,
        });
    }

    debug!(%hostname, %ip, "hosts entry ensured");
    Ok(())
}

pub fn remove_entries(
    ips_to_remove: &HashSet<Ipv4Addr>,
) -> Result<Vec<(Ipv4Addr, String)>, SessionError> {
    if ips_to_remove.is_empty() {
        return Ok(Vec::new());
    }

    let request = HostsRequest::Remove {
        ips: ips_to_remove.iter().copied().collect(),
    };

    let mut child = Command::new("sudo")
        .arg(SECURE_HOSTS_HELPER)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| SessionError::io("failed to run silo-hosts-helper", e))?;

    {
        let stdin = child.stdin.take().ok_or_else(|| {
            SessionError::io("stdin not available", std::io::ErrorKind::Other.into())
        })?;
        serde_json::to_writer(stdin, &request).map_err(|e| {
            SessionError::io("failed to write to silo-hosts-helper stdin", e.into())
        })?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| SessionError::io("failed to wait for silo-hosts-helper", e))?;

    if !output.status.success() {
        return Err(SessionError::CommandFailed {
            command: format!("sudo {} (remove)", SECURE_HOSTS_HELPER),
            status: output.status,
        });
    }

    let removed: Vec<RemovedEntry> = serde_json::from_slice(&output.stdout)
        .map_err(|e| SessionError::io("failed to parse silo-hosts-helper response", e.into()))?;

    let result: Vec<(Ipv4Addr, String)> = removed.into_iter().map(|e| (e.ip, e.hostname)).collect();

    debug!(count = result.len(), "removed hosts entries");
    Ok(result)
}
