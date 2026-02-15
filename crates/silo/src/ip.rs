use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, instrument};

use crate::error::{Error, Result};
use crate::hosts;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpRequest {
    Add { ip: Ipv4Addr },
    Remove { ip: Ipv4Addr },
}

#[cfg(target_os = "linux")]
fn find_ip_command() -> String {
    if let Ok(p) = which::which("ip") {
        return p.to_string_lossy().into_owned();
    }
    for candidate in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        if std::path::Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    "ip".to_string()
}

fn silo_bin() -> PathBuf {
    PathBuf::from(hosts::SECURE_SILO_BIN)
}

fn run_ip_helper(request: &IpRequest) -> Result<()> {
    let bin = silo_bin();

    let mut child = Command::new("sudo")
        .arg(&bin)
        .arg("_ip")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| Error::io("failed to run silo _ip", e))?;

    {
        let stdin = child.stdin.take().expect("stdin was piped");
        serde_json::to_writer(stdin, request)
            .map_err(|e| Error::io("failed to write to silo _ip stdin", e.into()))?;
    }

    let status = child
        .wait()
        .map_err(|e| Error::io("failed to wait for silo _ip", e))?;

    if !status.success() {
        return Err(Error::CommandFailed {
            command: format!("sudo {} _ip", bin.display()),
        });
    }

    Ok(())
}

#[instrument]
pub fn add_alias(ip: Ipv4Addr) -> Result<()> {
    if alias_exists(ip)? {
        debug!(%ip, "alias already exists, skipping");
        return Ok(());
    }

    info!(%ip, "adding loopback alias");
    run_ip_helper(&IpRequest::Add { ip })
}

#[instrument]
pub fn remove_alias(ip: Ipv4Addr) -> Result<()> {
    if !alias_exists(ip)? {
        debug!(%ip, "alias does not exist, skipping");
        return Ok(());
    }

    info!(%ip, "removing loopback alias");
    run_ip_helper(&IpRequest::Remove { ip })
}

pub fn run_ip_direct(request: &IpRequest) -> Result<()> {
    match request {
        IpRequest::Add { ip } => {
            hosts::validate_ip(*ip)?;
            run_direct_add(*ip)
        }
        IpRequest::Remove { ip } => {
            hosts::validate_ip(*ip)?;
            run_direct_remove(*ip)
        }
    }
}

fn run_direct_add(ip: Ipv4Addr) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let status = Command::new("/sbin/ifconfig")
            .args(["lo0", "alias", &ip.to_string(), "netmask", "255.0.0.0"])
            .status()
            .map_err(|e| Error::io("failed to run ifconfig", e))?;
        if !status.success() {
            return Err(Error::CommandFailed {
                command: format!("ifconfig lo0 alias {}", ip),
            });
        }
    }

    #[cfg(target_os = "linux")]
    {
        let ip_cmd = find_ip_command();
        let status = Command::new(&ip_cmd)
            .args(["addr", "add", &format!("{}/8", ip), "dev", "lo"])
            .status()
            .map_err(|e| Error::io("failed to run ip addr add", e))?;
        if !status.success() {
            return Err(Error::CommandFailed {
                command: format!("{} addr add {}/8 dev lo", ip_cmd, ip),
            });
        }
    }

    Ok(())
}

fn run_direct_remove(ip: Ipv4Addr) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let status = Command::new("/sbin/ifconfig")
            .args(["lo0", "-alias", &ip.to_string()])
            .status()
            .map_err(|e| Error::io("failed to run ifconfig", e))?;
        if !status.success() {
            return Err(Error::CommandFailed {
                command: format!("ifconfig lo0 -alias {}", ip),
            });
        }
    }

    #[cfg(target_os = "linux")]
    {
        let ip_cmd = find_ip_command();
        let status = Command::new(&ip_cmd)
            .args(["addr", "del", &format!("{}/8", ip), "dev", "lo"])
            .status()
            .map_err(|e| Error::io("failed to run ip addr del", e))?;
        if !status.success() {
            return Err(Error::CommandFailed {
                command: format!("{} addr del {}/8 dev lo", ip_cmd, ip),
            });
        }
    }

    Ok(())
}

pub fn alias_exists(ip: Ipv4Addr) -> Result<bool> {
    let lo_output = loopback_output()?;
    Ok(is_ip_in_output(&lo_output, ip))
}

pub fn active_aliases() -> Result<Vec<Ipv4Addr>> {
    let output = loopback_output()?;
    let mut aliases = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();

        let rest = if let Some(r) = trimmed.strip_prefix("inet ") {
            r
        } else {
            continue;
        };

        let ip_str = rest.split_whitespace().next().unwrap_or("");
        let ip_str = ip_str.split('/').next().unwrap_or(ip_str);

        if let Ok(ip) = ip_str.parse::<Ipv4Addr>()
            && ip != Ipv4Addr::new(127, 0, 0, 1)
            && ip.octets()[0] == 127
        {
            aliases.push(ip);
        }
    }

    Ok(aliases)
}

pub fn active_ips(ips: &[Ipv4Addr]) -> Result<HashSet<Ipv4Addr>> {
    let lo_output = loopback_output()?;
    Ok(ips
        .iter()
        .filter(|ip| is_ip_in_output(&lo_output, **ip))
        .copied()
        .collect())
}

pub(crate) fn is_ip_in_output(output: &str, ip: Ipv4Addr) -> bool {
    let needle = format!("inet {}", ip);
    output.lines().any(|line| {
        if let Some(pos) = line.find(&needle) {
            let after = pos + needle.len();
            matches!(
                line.as_bytes().get(after),
                None | Some(b' ') | Some(b'\t') | Some(b'/')
            )
        } else {
            false
        }
    })
}

fn loopback_output() -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("ifconfig")
            .arg("lo0")
            .output()
            .map_err(|e| Error::io("failed to run ifconfig", e))?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    #[cfg(target_os = "linux")]
    {
        let ip_cmd = find_ip_command();
        let output = Command::new(&ip_cmd)
            .args(["addr", "show", "lo"])
            .output()
            .map_err(|e| Error::io(format!("failed to run {} addr show lo", ip_cmd), e))?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_exact_match() {
        let output = "  inet 127.0.1.1 netmask 0xff000000\n";
        assert!(is_ip_in_output(output, Ipv4Addr::new(127, 0, 1, 1)));
    }

    #[test]
    fn ip_no_partial_match() {
        let output = "  inet 127.0.1.10 netmask 0xff000000\n";
        assert!(!is_ip_in_output(output, Ipv4Addr::new(127, 0, 1, 1)));
    }

    #[test]
    fn ip_match_with_slash() {
        let output = "  inet 127.0.1.1/8 scope host lo\n";
        assert!(is_ip_in_output(output, Ipv4Addr::new(127, 0, 1, 1)));
    }

    #[test]
    fn ip_match_at_eol() {
        let output = "  inet 127.0.1.1\n";
        assert!(is_ip_in_output(output, Ipv4Addr::new(127, 0, 1, 1)));
    }

    #[test]
    fn ip_no_match_different() {
        let output = "  inet 127.0.1.2 netmask 0xff000000\n";
        assert!(!is_ip_in_output(output, Ipv4Addr::new(127, 0, 1, 1)));
    }

    #[test]
    fn ip_empty_output() {
        assert!(!is_ip_in_output("", Ipv4Addr::new(127, 0, 1, 1)));
    }

    #[test]
    fn ip_multiple_lines() {
        let output = "  inet 127.0.0.1 netmask 0xff000000\n  inet 127.0.1.5 netmask 0xff000000\n";
        assert!(is_ip_in_output(output, Ipv4Addr::new(127, 0, 1, 5)));
        assert!(!is_ip_in_output(output, Ipv4Addr::new(127, 0, 1, 3)));
    }

    #[test]
    fn ip_match_macos_ifconfig_full_output() {
        let output = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet 127.0.1.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1";
        assert!(is_ip_in_output(output, Ipv4Addr::new(127, 0, 1, 1)));
        assert!(is_ip_in_output(output, Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_ip_in_output(output, Ipv4Addr::new(127, 0, 1, 2)));
    }

    #[test]
    fn ip_match_linux_ip_addr_full_output() {
        let output = "\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet 127.0.1.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever";
        assert!(is_ip_in_output(output, Ipv4Addr::new(127, 0, 1, 1)));
        assert!(is_ip_in_output(output, Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_ip_in_output(output, Ipv4Addr::new(127, 0, 1, 2)));
    }

    #[test]
    fn ip_no_false_positive_inet6() {
        let output = "    inet6 ::1/128 scope host\n";
        assert!(!is_ip_in_output(output, Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn ip_request_serde_roundtrip_add() {
        let req = IpRequest::Add {
            ip: Ipv4Addr::new(127, 1, 2, 3),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: IpRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            IpRequest::Add { ip } => assert_eq!(ip, Ipv4Addr::new(127, 1, 2, 3)),
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn ip_request_serde_roundtrip_remove() {
        let req = IpRequest::Remove {
            ip: Ipv4Addr::new(127, 1, 2, 3),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: IpRequest = serde_json::from_str(&json).unwrap();
        match parsed {
            IpRequest::Remove { ip } => assert_eq!(ip, Ipv4Addr::new(127, 1, 2, 3)),
            _ => panic!("expected Remove"),
        }
    }

    #[test]
    fn run_ip_direct_rejects_non_loopback() {
        let req = IpRequest::Add {
            ip: Ipv4Addr::new(10, 0, 0, 1),
        };
        assert!(run_ip_direct(&req).is_err());
    }

    #[test]
    fn run_ip_direct_rejects_localhost() {
        let req = IpRequest::Add {
            ip: Ipv4Addr::new(127, 0, 0, 1),
        };
        assert!(run_ip_direct(&req).is_err());
    }

    #[test]
    fn run_ip_direct_rejects_non_loopback_remove() {
        let req = IpRequest::Remove {
            ip: Ipv4Addr::new(192, 168, 1, 1),
        };
        assert!(run_ip_direct(&req).is_err());
    }
}
