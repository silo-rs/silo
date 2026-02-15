mod block;
mod direct;
mod helper;
mod validate;

use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::SessionError;

pub(crate) const HOSTS_PATH: &str = "/etc/hosts";
pub const SECURE_IP_HELPER: &str = "/usr/local/libexec/silo-ip-helper";
pub const SECURE_HOSTS_HELPER: &str = "/usr/local/libexec/silo-hosts-helper";

pub use self::direct::run_hosts_direct;
pub(crate) use self::helper::ensure_entry;
pub use self::helper::remove_entries;
pub(crate) use self::validate::validate_ip;

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

#[derive(Debug, Clone, Serialize)]
pub struct HostEntry {
    pub ip: Ipv4Addr,
    pub hostname: String,
    pub dir: Option<PathBuf>,
}

pub(crate) fn check_collision(ip: Ipv4Addr, hostname: &str) -> Result<(), SessionError> {
    let content = match std::fs::read_to_string(HOSTS_PATH) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    let (_, entries, _) = block::parse_block(&content);
    if let Some(conflict) = block::find_ip_conflict(&entries, ip, hostname) {
        return Err(SessionError::IpCollision {
            ip,
            existing: conflict,
            new: hostname.to_string(),
        });
    }
    Ok(())
}

pub fn list_entries() -> Result<Vec<HostEntry>, SessionError> {
    let content = std::fs::read_to_string(HOSTS_PATH)
        .map_err(|e| SessionError::io("failed to read /etc/hosts", e))?;
    let (_, entries, _) = block::parse_block(&content);

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

#[cfg(test)]
mod tests {
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
        use std::path::PathBuf;

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
}
