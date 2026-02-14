use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

use tracing::{debug, info, instrument};

use crate::error::{Error, Result};

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

#[instrument]
pub fn add_alias(ip: Ipv4Addr) -> Result<()> {
    if alias_exists(ip)? {
        debug!(%ip, "alias already exists, skipping");
        return Ok(());
    }

    info!(%ip, "adding loopback alias");

    #[cfg(target_os = "macos")]
    run_sudo(&[
        "ifconfig",
        "lo0",
        "alias",
        &ip.to_string(),
        "netmask",
        "255.0.0.0",
    ])?;

    #[cfg(target_os = "linux")]
    {
        let ip_cmd = find_ip_command();
        run_sudo(&[&ip_cmd, "addr", "add", &format!("{}/8", ip), "dev", "lo"])?;
    }

    Ok(())
}

#[instrument]
pub fn remove_alias(ip: Ipv4Addr) -> Result<()> {
    if !alias_exists(ip)? {
        debug!(%ip, "alias does not exist, skipping");
        return Ok(());
    }

    info!(%ip, "removing loopback alias");

    #[cfg(target_os = "macos")]
    run_sudo(&["ifconfig", "lo0", "-alias", &ip.to_string()])?;

    #[cfg(target_os = "linux")]
    {
        let ip_cmd = find_ip_command();
        run_sudo(&[&ip_cmd, "addr", "del", &format!("{}/8", ip), "dev", "lo"])?;
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

fn run_sudo(args: &[&str]) -> Result<()> {
    debug!(cmd = %args.join(" "), "running sudo");
    let status = Command::new("sudo")
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| Error::io("failed to run sudo", e))?;

    if !status.success() {
        return Err(Error::CommandFailed {
            command: format!("sudo {}", args.join(" ")),
        });
    }

    Ok(())
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
}
