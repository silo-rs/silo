use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use fd_lock::RwLock;
use serde::Serialize;
use tracing::debug;

use crate::error::{Error, Result};

pub const HOSTS_PATH: &str = "/etc/hosts";
pub const HOSTS_TMP: &str = "/etc/.hosts.silo.tmp";
const BEGIN_MARKER: &str = "# BEGIN silo managed block - do not edit";
const END_MARKER: &str = "# END silo managed block";
const HELPER_LOCK_PATH: &str = "/etc/.silo-hosts.lock";

pub fn validate_ip(ip: Ipv4Addr) -> Result<()> {
    if ip.octets()[0] != 127 {
        return Err(Error::HostsValidation(format!(
            "IP {} is not in 127.0.0.0/8",
            ip
        )));
    }
    if ip == Ipv4Addr::new(127, 0, 0, 1) {
        return Err(Error::HostsValidation(
            "127.0.0.1 is reserved for localhost".into(),
        ));
    }
    Ok(())
}

pub fn validate_hostname(hostname: &str) -> Result<()> {
    if !hostname.ends_with(".silo") {
        return Err(Error::HostsValidation(format!(
            "hostname '{}' does not end with .silo",
            hostname
        )));
    }
    let prefix = &hostname[..hostname.len() - 5];
    if prefix.is_empty() || prefix == "." {
        return Err(Error::HostsValidation(
            "hostname must have labels before .silo".into(),
        ));
    }
    if hostname.len() > 253 {
        return Err(Error::HostsValidation("hostname too long".into()));
    }
    if !hostname
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(Error::HostsValidation(format!(
            "hostname '{}' contains invalid characters",
            hostname
        )));
    }
    Ok(())
}

pub fn validate_dir(dir: &str) -> Result<()> {
    if dir.is_empty() {
        return Err(Error::HostsValidation("directory path is empty".into()));
    }
    if dir.contains('\n') || dir.contains('\r') || dir.contains('\t') || dir.contains('\0') {
        return Err(Error::HostsValidation(
            "directory path contains invalid characters".into(),
        ));
    }
    Ok(())
}

fn silo_bin() -> Result<PathBuf> {
    std::env::current_exe().map_err(|e| Error::io("failed to resolve silo binary path", e))
}

pub fn ensure_entry(ip: Ipv4Addr, hostname: &str, dir: &Path) -> Result<()> {
    let bin = silo_bin()?;

    let status = Command::new("sudo")
        .arg(&bin)
        .args([
            "_hosts",
            "add",
            &ip.to_string(),
            hostname,
            &dir.display().to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| Error::io("failed to run silo _hosts add", e))?;

    if !status.success() {
        return Err(Error::CommandFailed {
            command: format!("sudo {} _hosts add {} {}", bin.display(), ip, hostname),
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

pub fn list_entries() -> Result<Vec<HostEntry>> {
    let content = std::fs::read_to_string(HOSTS_PATH)
        .map_err(|e| Error::io("failed to read /etc/hosts", e))?;
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

pub fn remove_entries(ips_to_remove: &HashSet<Ipv4Addr>) -> Result<Vec<(Ipv4Addr, String)>> {
    if ips_to_remove.is_empty() {
        return Ok(Vec::new());
    }

    let bin = silo_bin()?;
    let ip_args: Vec<String> = ips_to_remove.iter().map(|ip| ip.to_string()).collect();

    let output = Command::new("sudo")
        .arg(&bin)
        .arg("_hosts")
        .arg("remove")
        .args(&ip_args)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| Error::io("failed to run silo _hosts remove", e))?;

    if !output.status.success() {
        return Err(Error::CommandFailed {
            command: "sudo silo _hosts remove".to_string(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut removed = Vec::new();
    for line in stdout.lines() {
        if let Some((ip_str, hostname)) = line.split_once('\t')
            && let Ok(ip) = ip_str.parse::<Ipv4Addr>()
        {
            removed.push((ip, hostname.to_string()));
        }
    }

    debug!(count = removed.len(), "removed hosts entries");
    Ok(removed)
}

pub fn open_helper_lock() -> Result<RwLock<std::fs::File>> {
    let file = match std::fs::File::open(HELPER_LOCK_PATH) {
        Ok(f) => f,
        Err(_) => {
            let _ = std::fs::File::create(HELPER_LOCK_PATH);
            std::fs::File::open(HELPER_LOCK_PATH)
                .map_err(|e| Error::io("failed to open silo hosts lock file", e))?
        }
    };
    Ok(RwLock::new(file))
}

pub fn write_hosts_direct(content: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(HOSTS_TMP, content.as_bytes())
        .map_err(|e| Error::io("failed to write temp hosts file", e))?;

    std::fs::set_permissions(HOSTS_TMP, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| Error::io("failed to set permissions on temp hosts file", e))?;

    std::fs::rename(HOSTS_TMP, HOSTS_PATH)
        .map_err(|e| Error::io("failed to rename temp hosts to /etc/hosts", e))?;

    Ok(())
}

pub fn parse_block(content: &str) -> (String, Vec<String>, String) {
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

pub fn rebuild(before: String, entries: &[String], after: String) -> String {
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
}
