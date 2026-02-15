use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use fd_lock::RwLock;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::error::{SessionError, ValidationError};

pub(crate) const HOSTS_PATH: &str = "/etc/hosts";
pub const SECURE_IP_HELPER: &str = "/usr/local/libexec/silo-ip-helper";
pub const SECURE_HOSTS_HELPER: &str = "/usr/local/libexec/silo-hosts-helper";
const BEGIN_MARKER: &str = "# BEGIN silo managed block - do not edit";
const END_MARKER: &str = "# END silo managed block";
const HELPER_LOCK_PATH: &str = "/etc/.silo-hosts.lock";

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HostsRequest {
    Add {
        ip: Ipv4Addr,
        hostname: String,
        dir: String,
    },
    Remove {
        ips: Vec<Ipv4Addr>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemovedEntry {
    pub ip: Ipv4Addr,
    pub hostname: String,
}

pub(crate) fn validate_ip(ip: Ipv4Addr) -> Result<(), ValidationError> {
    if ip.octets()[0] != 127 {
        return Err(ValidationError::IpNotLoopback(ip));
    }
    if ip == Ipv4Addr::new(127, 0, 0, 1) {
        return Err(ValidationError::IpReservedLocalhost);
    }
    Ok(())
}

pub(crate) fn validate_hostname(hostname: &str) -> Result<(), ValidationError> {
    if !hostname.ends_with(".silo") {
        return Err(ValidationError::HostnameMissingSuffix(hostname.to_string()));
    }
    let prefix = &hostname[..hostname.len() - 5];
    if prefix.is_empty() || prefix == "." {
        return Err(ValidationError::HostnameEmptyPrefix);
    }
    if hostname.len() > 253 {
        return Err(ValidationError::HostnameTooLong);
    }
    if !hostname
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(ValidationError::HostnameInvalidChars(hostname.to_string()));
    }
    Ok(())
}

pub(crate) fn validate_dir(dir: &str) -> Result<(), ValidationError> {
    if dir.is_empty() {
        return Err(ValidationError::DirEmpty);
    }
    if dir.contains('\n') || dir.contains('\r') || dir.contains('\t') || dir.contains('\0') {
        return Err(ValidationError::DirInvalidChars);
    }
    Ok(())
}

fn find_ip_conflict(entries: &[String], ip: Ipv4Addr, hostname: &str) -> Option<String> {
    let ip_str = ip.to_string();
    for entry in entries {
        let mut parts = entry.split('\t');
        let entry_ip = parts.next()?;
        let entry_host = parts.next()?;
        if entry_ip == ip_str && entry_host != hostname {
            return Some(entry_host.to_string());
        }
    }
    None
}

pub(crate) fn check_collision(ip: Ipv4Addr, hostname: &str) -> Result<(), SessionError> {
    let content = match std::fs::read_to_string(HOSTS_PATH) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    let (_, entries, _) = parse_block(&content);
    if let Some(conflict) = find_ip_conflict(&entries, ip, hostname) {
        return Err(SessionError::IpCollision {
            ip,
            existing: conflict,
            new: hostname.to_string(),
        });
    }
    Ok(())
}

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
    let (before, mut entries, after) = parse_block(&content);

    let new_line = format!("{}\t{}\t# {}", ip, hostname, dir);

    if let Some(conflict) = find_ip_conflict(&entries, ip, hostname) {
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

    let output = rebuild(before, &entries, after);
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
    let (before, entries, after) = parse_block(&content);

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
        let output = rebuild(before, &kept, after);
        write_hosts_direct(&output)?;
    }

    Ok(removed)
}

fn hosts_helper_bin() -> PathBuf {
    PathBuf::from(SECURE_HOSTS_HELPER)
}

pub(crate) fn ensure_entry(ip: Ipv4Addr, hostname: &str, dir: &Path) -> Result<(), SessionError> {
    let bin = hosts_helper_bin();

    let request = HostsRequest::Add {
        ip,
        hostname: hostname.to_string(),
        dir: dir.display().to_string(),
    };

    let mut child = Command::new("sudo")
        .arg(&bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| SessionError::io("failed to run silo-hosts-helper", e))?;

    {
        let stdin = child.stdin.take().expect("stdin was piped");
        serde_json::to_writer(stdin, &request).map_err(|e| {
            SessionError::io("failed to write to silo-hosts-helper stdin", e.into())
        })?;
    }

    let status = child
        .wait()
        .map_err(|e| SessionError::io("failed to wait for silo-hosts-helper", e))?;

    if !status.success() {
        return Err(SessionError::CommandFailed {
            command: format!("sudo {} (add {} {})", bin.display(), ip, hostname),
            status,
        });
    }

    debug!(%hostname, %ip, "hosts entry ensured");
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct HostEntry {
    pub ip: Ipv4Addr,
    pub hostname: String,
    pub dir: Option<PathBuf>,
}

pub fn list_entries() -> Result<Vec<HostEntry>, SessionError> {
    let content = std::fs::read_to_string(HOSTS_PATH)
        .map_err(|e| SessionError::io("failed to read /etc/hosts", e))?;
    let (_, entries, _) = parse_block(&content);

    let mut result = Vec::new();
    for entry in &entries {
        let (main, dir) = match entry.split_once("\t# ") {
            Some((m, comment)) => (m, Some(PathBuf::from(comment))),
            None => (entry.as_str(), None),
        };
        if let Some((ip_str, hostname)) = main.split_once('\t')
            && let Ok(ip) = ip_str.parse::<Ipv4Addr>()
        {
            result.push(HostEntry {
                ip,
                hostname: hostname.to_string(),
                dir,
            });
        }
    }
    Ok(result)
}

pub fn remove_entries(
    ips_to_remove: &HashSet<Ipv4Addr>,
) -> Result<Vec<(Ipv4Addr, String)>, SessionError> {
    if ips_to_remove.is_empty() {
        return Ok(Vec::new());
    }

    let bin = hosts_helper_bin();

    let request = HostsRequest::Remove {
        ips: ips_to_remove.iter().copied().collect(),
    };

    let mut child = Command::new("sudo")
        .arg(&bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| SessionError::io("failed to run silo-hosts-helper", e))?;

    {
        let stdin = child.stdin.take().expect("stdin was piped");
        serde_json::to_writer(stdin, &request).map_err(|e| {
            SessionError::io("failed to write to silo-hosts-helper stdin", e.into())
        })?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| SessionError::io("failed to wait for silo-hosts-helper", e))?;

    if !output.status.success() {
        return Err(SessionError::CommandFailed {
            command: format!("sudo {} (remove)", bin.display()),
            status: output.status,
        });
    }

    let removed: Vec<RemovedEntry> = serde_json::from_slice(&output.stdout)
        .map_err(|e| SessionError::io("failed to parse silo-hosts-helper response", e.into()))?;

    let result: Vec<(Ipv4Addr, String)> = removed.into_iter().map(|e| (e.ip, e.hostname)).collect();

    debug!(count = result.len(), "removed hosts entries");
    Ok(result)
}

pub(crate) fn open_helper_lock() -> Result<RwLock<std::fs::File>, SessionError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(HELPER_LOCK_PATH)
        .map_err(|e| SessionError::io("failed to open silo hosts lock file", e))?;
    Ok(RwLock::new(file))
}

pub(crate) fn write_hosts_direct(content: &str) -> Result<(), SessionError> {
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

fn parse_block(content: &str) -> (String, Vec<String>, String) {
    enum State {
        Before,
        Inside,
        After,
    }

    let mut before = String::new();
    let mut entries = Vec::new();
    let mut after = String::new();
    let mut state = State::Before;

    for line in content.lines() {
        match state {
            State::Before => {
                if line == BEGIN_MARKER {
                    state = State::Inside;
                } else {
                    before.push_str(line);
                    before.push('\n');
                }
            }
            State::Inside => {
                if line == END_MARKER {
                    state = State::After;
                } else {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        entries.push(trimmed.to_string());
                    }
                }
            }
            State::After => {
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

    #[test]
    fn roundtrip_with_dir_comment() {
        let original = format!(
            "127.0.0.1\tlocalhost\n{}\n127.0.1.1\tapi.myapp.silo\t# /home/user/myapp\n{}\n::1\tlocalhost\n",
            BEGIN_MARKER, END_MARKER
        );
        let (before, entries, after) = parse_block(&original);
        assert_eq!(
            entries,
            vec!["127.0.1.1\tapi.myapp.silo\t# /home/user/myapp"]
        );
        let rebuilt = rebuild(before, &entries, after);
        assert_eq!(rebuilt, original);
    }

    #[test]
    fn parse_entry_with_dir_comment() {
        let entry = "127.0.1.1\tapi.myapp.silo\t# /home/user/myapp";
        let (main, dir) = entry.split_once("\t# ").unwrap();
        let (ip_str, hostname) = main.split_once('\t').unwrap();
        assert_eq!(ip_str, "127.0.1.1");
        assert_eq!(hostname, "api.myapp.silo");
        assert_eq!(dir, "/home/user/myapp");
    }

    #[test]
    fn parse_entry_without_dir_comment() {
        let entry = "127.0.1.1\tapi.myapp.silo";
        let (main, dir) = match entry.split_once("\t# ") {
            Some((m, comment)) => (m, Some(PathBuf::from(comment))),
            None => (entry, None),
        };
        let (ip_str, hostname) = main.split_once('\t').unwrap();
        assert_eq!(ip_str, "127.0.1.1");
        assert_eq!(hostname, "api.myapp.silo");
        assert!(dir.is_none());
    }

    #[test]
    fn validate_ip_accepts_loopback() {
        assert!(validate_ip(Ipv4Addr::new(127, 0, 1, 1)).is_ok());
        assert!(validate_ip(Ipv4Addr::new(127, 255, 255, 254)).is_ok());
    }

    #[test]
    fn validate_ip_rejects_localhost() {
        assert!(validate_ip(Ipv4Addr::new(127, 0, 0, 1)).is_err());
    }

    #[test]
    fn validate_ip_rejects_non_loopback() {
        assert!(validate_ip(Ipv4Addr::new(10, 0, 0, 1)).is_err());
        assert!(validate_ip(Ipv4Addr::new(192, 168, 1, 1)).is_err());
        assert!(validate_ip(Ipv4Addr::new(0, 0, 0, 0)).is_err());
    }

    #[test]
    fn validate_hostname_accepts_valid() {
        assert!(validate_hostname("feat.project.silo").is_ok());
        assert!(validate_hostname("main.my-app.silo").is_ok());
        assert!(validate_hostname("a.silo").is_ok());
        assert!(validate_hostname("feature-auth.my_project.silo").is_ok());
    }

    #[test]
    fn validate_hostname_rejects_no_silo_suffix() {
        assert!(validate_hostname("foo.com").is_err());
        assert!(validate_hostname("foo.sil").is_err());
    }

    #[test]
    fn validate_hostname_rejects_empty_prefix() {
        assert!(validate_hostname(".silo").is_err());
    }

    #[test]
    fn validate_hostname_rejects_newline() {
        assert!(validate_hostname("foo.silo\n127.0.0.1 evil").is_err());
    }

    #[test]
    fn validate_hostname_rejects_tab() {
        assert!(validate_hostname("foo.silo\tevil").is_err());
    }

    #[test]
    fn validate_hostname_rejects_space() {
        assert!(validate_hostname("foo .silo").is_err());
    }

    #[test]
    fn validate_hostname_rejects_too_long() {
        let long = format!("{}.silo", "a".repeat(250));
        assert!(validate_hostname(&long).is_err());
    }

    #[test]
    fn validate_dir_accepts_valid() {
        assert!(validate_dir("/home/user/project").is_ok());
        assert!(validate_dir("/tmp/my app").is_ok());
    }

    #[test]
    fn validate_dir_rejects_newline() {
        assert!(validate_dir("/home/user\n# evil").is_err());
    }

    #[test]
    fn validate_dir_rejects_tab() {
        assert!(validate_dir("/home/user\tevil").is_err());
    }

    #[test]
    fn validate_dir_rejects_empty() {
        assert!(validate_dir("").is_err());
    }

    #[test]
    fn validate_dir_rejects_null() {
        assert!(validate_dir("/home/user\0evil").is_err());
    }

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

    #[test]
    fn find_ip_conflict_detects_collision() {
        let entries = vec!["127.1.2.3\tmain.project-a.silo\t# /home/user/a".to_string()];
        assert!(
            find_ip_conflict(&entries, Ipv4Addr::new(127, 1, 2, 3), "feat.project-b.silo")
                .is_some()
        );
        assert!(
            find_ip_conflict(&entries, Ipv4Addr::new(127, 1, 2, 3), "main.project-a.silo")
                .is_none()
        );
        assert!(
            find_ip_conflict(&entries, Ipv4Addr::new(127, 4, 5, 6), "feat.project-b.silo")
                .is_none()
        );
    }

    #[test]
    fn parse_block_missing_end_marker() {
        let content = format!(
            "127.0.0.1\tlocalhost\n{}\n127.0.1.1\tapi.myapp.silo\n::1\tlocalhost\n",
            BEGIN_MARKER
        );
        let (before, entries, after) = parse_block(&content);
        assert_eq!(before, "127.0.0.1\tlocalhost\n");
        assert_eq!(entries, vec!["127.0.1.1\tapi.myapp.silo", "::1\tlocalhost"]);
        assert_eq!(after, "");
    }

    #[test]
    fn parse_block_end_without_begin() {
        let content = format!("127.0.0.1\tlocalhost\n{}\n::1\tlocalhost\n", END_MARKER);
        let (before, entries, after) = parse_block(&content);
        assert_eq!(
            before,
            format!("127.0.0.1\tlocalhost\n{}\n::1\tlocalhost\n", END_MARKER)
        );
        assert!(entries.is_empty());
        assert_eq!(after, "");
    }

    #[test]
    fn parse_block_duplicate_begin_marker() {
        let content = format!(
            "127.0.0.1\tlocalhost\n{b}\n127.0.1.1\tapi.myapp.silo\n{b}\n127.0.1.2\tweb.myapp.silo\n{e}\n::1\tlocalhost\n",
            b = BEGIN_MARKER,
            e = END_MARKER
        );
        let (before, entries, after) = parse_block(&content);
        assert_eq!(before, "127.0.0.1\tlocalhost\n");
        assert!(entries.contains(&"127.0.1.1\tapi.myapp.silo".to_string()));
        assert_eq!(after, "::1\tlocalhost\n");
    }

    #[test]
    fn parse_block_crlf() {
        let content = format!(
            "127.0.0.1\tlocalhost\r\n{}\r\n127.0.1.1\tapi.myapp.silo\r\n{}\r\n::1\tlocalhost\r\n",
            BEGIN_MARKER, END_MARKER
        );
        let (before, entries, _after) = parse_block(&content);
        assert!(before.contains("localhost"));
        assert_eq!(entries.len(), 1);
        assert!(entries[0].contains("api.myapp.silo"));
    }

    #[test]
    fn parse_block_empty_file() {
        let (before, entries, after) = parse_block("");
        assert_eq!(before, "");
        assert!(entries.is_empty());
        assert_eq!(after, "");
    }

    #[test]
    fn parse_block_only_silo_block() {
        let content = format!(
            "{}\n127.0.1.1\tapi.myapp.silo\n{}\n",
            BEGIN_MARKER, END_MARKER
        );
        let (before, entries, after) = parse_block(&content);
        assert_eq!(before, "");
        assert_eq!(entries, vec!["127.0.1.1\tapi.myapp.silo"]);
        assert_eq!(after, "");
    }

    #[test]
    fn rebuild_no_trailing_newline_in_before() {
        let before = "127.0.0.1\tlocalhost".to_string();
        let entries = vec!["127.0.1.1\tapi.myapp.silo".to_string()];
        let after = String::new();

        let result = rebuild(before, &entries, after);
        assert!(result.contains(BEGIN_MARKER));
        assert!(result.contains("127.0.1.1\tapi.myapp.silo"));
        assert!(result.contains(END_MARKER));
    }

    #[test]
    fn validate_hostname_boundary_253() {
        let prefix_len = 253 - 5;
        let prefix = "a".repeat(prefix_len);
        let hostname = format!("{prefix}.silo");
        assert_eq!(hostname.len(), 253);
        assert!(validate_hostname(&hostname).is_ok());
    }

    #[test]
    fn validate_hostname_boundary_254() {
        let prefix_len = 254 - 5;
        let prefix = "a".repeat(prefix_len);
        let hostname = format!("{prefix}.silo");
        assert_eq!(hostname.len(), 254);
        assert!(validate_hostname(&hostname).is_err());
    }

    #[test]
    fn find_ip_conflict_empty_entries() {
        let entries: Vec<String> = vec![];
        assert!(find_ip_conflict(&entries, Ipv4Addr::new(127, 1, 2, 3), "test.silo").is_none());
    }

    #[test]
    fn find_ip_conflict_malformed_entry() {
        let entries = vec!["not-a-valid-entry".to_string()];
        assert!(find_ip_conflict(&entries, Ipv4Addr::new(127, 1, 2, 3), "test.silo").is_none());
    }
}
