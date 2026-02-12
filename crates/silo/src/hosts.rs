use std::collections::HashSet;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use fd_lock::RwLock;
use tracing::debug;

use crate::error::{Error, Result};
use crate::ip;

const HOSTS_PATH: &str = "/etc/hosts";
const BEGIN_MARKER: &str = "# BEGIN silo managed block - do not edit";
const END_MARKER: &str = "# END silo managed block";

/// Ensure an entry exists in /etc/hosts for the given IP and hostname.
/// Idempotent: updates existing entry or adds a new one.
///
/// Uses an advisory exclusive lock on /etc/hosts to prevent concurrent
/// silo instances from racing on the read-modify-write cycle.
pub fn ensure_entry(ip: Ipv4Addr, hostname: &str) -> Result<()> {
    ip::ensure_sudoers()?;

    // Advisory exclusive lock on /etc/hosts to prevent TOCTOU races
    // between concurrent silo sessions. flock(2) allows exclusive locks
    // on files opened read-only.
    let lock_file = std::fs::File::open(HOSTS_PATH)
        .map_err(|e| Error::io("failed to open /etc/hosts for locking", e))?;
    let mut lock = RwLock::new(lock_file);
    let _guard = lock
        .write()
        .map_err(|e| Error::io("failed to acquire /etc/hosts lock", e))?;

    let content = std::fs::read_to_string(HOSTS_PATH)
        .map_err(|e| Error::io("failed to read /etc/hosts", e))?;
    let (before, mut entries, after) = parse_block(&content);

    let new_line = format!("{}\t{}", ip, hostname);

    if let Some(pos) = entries
        .iter()
        .position(|e| e.split('\t').nth(1).map(|h| h == hostname).unwrap_or(false))
    {
        if entries[pos] == new_line {
            debug!(%hostname, "hosts entry already up to date");
            return Ok(());
        }
        entries[pos] = new_line;
    } else {
        entries.push(new_line);
    }

    let output = rebuild(before, &entries, after);
    write_hosts(&output)?;

    debug!(%hostname, %ip, "hosts entry ensured");
    Ok(())
}

/// Parse the silo managed block and return all (ip, hostname) pairs.
pub fn list_entries() -> Result<Vec<(Ipv4Addr, String)>> {
    let content = std::fs::read_to_string(HOSTS_PATH)
        .map_err(|e| Error::io("failed to read /etc/hosts", e))?;
    let (_, entries, _) = parse_block(&content);

    let mut result = Vec::new();
    for entry in &entries {
        if let Some((ip_str, hostname)) = entry.split_once('\t')
            && let Ok(ip) = ip_str.parse::<Ipv4Addr>()
        {
            result.push((ip, hostname.to_string()));
        }
    }
    Ok(result)
}

/// Remove all /etc/hosts entries whose IP is in the given set.
/// Uses the same flock pattern as `ensure_entry` for safety.
/// Returns the list of (ip, hostname) pairs that were removed.
pub fn remove_entries(ips_to_remove: &HashSet<Ipv4Addr>) -> Result<Vec<(Ipv4Addr, String)>> {
    ip::ensure_sudoers()?;

    let lock_file = std::fs::File::open(HOSTS_PATH)
        .map_err(|e| Error::io("failed to open /etc/hosts for locking", e))?;
    let mut lock = RwLock::new(lock_file);
    let _guard = lock
        .write()
        .map_err(|e| Error::io("failed to acquire /etc/hosts lock", e))?;

    let content = std::fs::read_to_string(HOSTS_PATH)
        .map_err(|e| Error::io("failed to read /etc/hosts", e))?;
    let (before, entries, after) = parse_block(&content);

    let mut removed = Vec::new();
    let mut kept = Vec::new();

    for entry in &entries {
        let ip: Option<Ipv4Addr> = entry.split('\t').next().and_then(|s| s.parse().ok());

        if let Some(ip) = ip
            && ips_to_remove.contains(&ip)
        {
            let hostname = entry.split('\t').nth(1).unwrap_or("").to_string();
            removed.push((ip, hostname));
            continue;
        }
        kept.push(entry.clone());
    }

    if removed.is_empty() {
        return Ok(removed);
    }

    let output = rebuild(before, &kept, after);
    write_hosts(&output)?;

    debug!(count = removed.len(), "removed hosts entries");
    Ok(removed)
}

fn write_hosts(content: &str) -> Result<()> {
    let mut child = Command::new("sudo")
        .args(["tee", HOSTS_PATH])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| Error::io("failed to run sudo tee /etc/hosts", e))?;

    if let Some(ref mut stdin) = child.stdin {
        stdin
            .write_all(content.as_bytes())
            .map_err(|e| Error::io("failed to write to sudo tee stdin", e))?;
    }

    let status = child
        .wait()
        .map_err(|e| Error::io("failed to wait for sudo tee", e))?;
    if !status.success() {
        return Err(Error::CommandFailed {
            command: "sudo tee /etc/hosts".into(),
        });
    }

    Ok(())
}

fn parse_block(content: &str) -> (String, Vec<String>, String) {
    let mut before = String::new();
    let mut entries = Vec::new();
    let mut after = String::new();
    let mut state = 0u8; // 0=before, 1=inside, 2=after

    for line in content.lines() {
        match state {
            0 => {
                if line == BEGIN_MARKER {
                    state = 1;
                } else {
                    before.push_str(line);
                    before.push('\n');
                }
            }
            1 => {
                if line == END_MARKER {
                    state = 2;
                } else {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        entries.push(trimmed.to_string());
                    }
                }
            }
            _ => {
                after.push_str(line);
                after.push('\n');
            }
        }
    }

    (before, entries, after)
}

fn rebuild(before: String, entries: &[String], after: String) -> String {
    let mut out = before;

    if !out.ends_with('\n') && !out.is_empty() {
        out.push('\n');
    }

    if !entries.is_empty() {
        out.push_str(BEGIN_MARKER);
        out.push('\n');
        for entry in entries {
            out.push_str(entry);
            out.push('\n');
        }
        out.push_str(END_MARKER);
        out.push('\n');
    }

    out.push_str(&after);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn hostname(name: &str, repo: &Path) -> String {
        let repo_dir = repo
            .file_name()
            .map(|s| s.to_string_lossy())
            .unwrap_or_default();
        format!("{}.{}.silo", name, repo_dir)
    }

    #[test]
    fn hostname_format() {
        assert_eq!(
            hostname("feature-a", Path::new("/home/user/myproject")),
            "feature-a.myproject.silo"
        );
    }

    #[test]
    fn parse_no_block() {
        let content = "127.0.0.1\tlocalhost\n::1\tlocalhost\n";
        let (before, entries, after) = parse_block(content);
        assert_eq!(before, content);
        assert!(entries.is_empty());
        assert_eq!(after, "");
    }

    #[test]
    fn parse_with_block() {
        let content = format!(
            "127.0.0.1\tlocalhost\n{}\n127.0.1.1\tapi.myapp.silo\n{}\n::1\tlocalhost\n",
            BEGIN_MARKER, END_MARKER
        );
        let (before, entries, after) = parse_block(&content);
        assert_eq!(before, "127.0.0.1\tlocalhost\n");
        assert_eq!(entries, vec!["127.0.1.1\tapi.myapp.silo"]);
        assert_eq!(after, "::1\tlocalhost\n");
    }

    #[test]
    fn rebuild_with_entries() {
        let before = "127.0.0.1\tlocalhost\n".to_string();
        let entries = vec!["127.0.1.1\tapi.myapp.silo".to_string()];
        let after = "::1\tlocalhost\n".to_string();

        let result = rebuild(before, &entries, after);
        let expected = format!(
            "127.0.0.1\tlocalhost\n{}\n127.0.1.1\tapi.myapp.silo\n{}\n::1\tlocalhost\n",
            BEGIN_MARKER, END_MARKER
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn rebuild_empty_entries_removes_block() {
        let before = "127.0.0.1\tlocalhost\n".to_string();
        let entries: Vec<String> = vec![];
        let after = "::1\tlocalhost\n".to_string();

        let result = rebuild(before, &entries, after);
        assert_eq!(result, "127.0.0.1\tlocalhost\n::1\tlocalhost\n");
    }

    #[test]
    fn roundtrip() {
        let original = format!(
            "127.0.0.1\tlocalhost\n{}\n127.0.1.1\tapi.myapp.silo\n127.0.1.2\tweb.myapp.silo\n{}\n::1\tlocalhost\n",
            BEGIN_MARKER, END_MARKER
        );
        let (before, entries, after) = parse_block(&original);
        let rebuilt = rebuild(before, &entries, after);
        assert_eq!(rebuilt, original);
    }
}
