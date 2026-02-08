use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};

use eyre::Context;
use ipnet::Ipv4Net;
use tracing::{debug, info, instrument, warn};

use crate::error::SiloError;

#[instrument(skip(used))]
pub fn allocate_ip(range: &str, used: &HashSet<Ipv4Addr>) -> Result<Ipv4Addr, SiloError> {
    let network: Ipv4Net = range
        .parse()
        .map_err(|e: ipnet::AddrParseError| {
            SiloError::InvalidCidrRange(range.to_string(), e.to_string())
        })?;

    if network.network().octets()[0] != 127 {
        return Err(SiloError::IpNotLoopback(network.network()));
    }

    debug!(used_count = used.len(), "scanning for available IP");

    for ip in network.hosts() {
        if ip == Ipv4Addr::new(127, 0, 0, 1) {
            continue;
        }
        if !used.contains(&ip) {
            info!(%ip, "allocated IP");
            return Ok(ip);
        }
    }

    Err(SiloError::IpRangeExhausted(range.to_string()))
}

#[instrument]
pub fn add_alias(ip: Ipv4Addr) -> eyre::Result<()> {
    if alias_exists(ip)? {
        debug!(%ip, "alias already exists, skipping");
        return Ok(());
    }

    ensure_sudoers()?;

    eprintln!("  adding loopback alias {}", ip);

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
    run_sudo(&["ip", "addr", "add", &format!("{}/8", ip), "dev", "lo"])?;

    Ok(())
}

#[instrument]
pub fn remove_alias(ip: Ipv4Addr) -> eyre::Result<()> {
    if !alias_exists(ip)? {
        debug!(%ip, "alias does not exist, skipping");
        return Ok(());
    }

    ensure_sudoers()?;

    eprintln!("  removing loopback alias {}", ip);

    #[cfg(target_os = "macos")]
    run_sudo(&["ifconfig", "lo0", "-alias", &ip.to_string()])?;

    #[cfg(target_os = "linux")]
    run_sudo(&["ip", "addr", "del", &format!("{}/8", ip), "dev", "lo"])?;

    Ok(())
}

pub fn alias_exists(ip: Ipv4Addr) -> eyre::Result<bool> {
    let lo_output = loopback_output()?;
    Ok(is_ip_in_output(&lo_output, ip))
}

pub fn active_ips(ips: &[Ipv4Addr]) -> eyre::Result<HashSet<Ipv4Addr>> {
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
            match line.as_bytes().get(after) {
                None | Some(b' ') | Some(b'\t') | Some(b'/') => true,
                _ => false,
            }
        } else {
            false
        }
    })
}

fn loopback_output() -> eyre::Result<String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("ifconfig")
            .arg("lo0")
            .output()
            .context("failed to run ifconfig")?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["addr", "show", "lo"])
            .output()
            .context("failed to run ip addr")?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

fn sudoers_configured() -> bool {
    let exists = Path::new("/etc/sudoers.d/silo").exists();
    debug!(exists, "checking /etc/sudoers.d/silo");
    exists
}

fn install_sudoers() -> eyre::Result<()> {
    eprintln!();
    eprintln!("silo needs passwordless sudo for loopback IP aliases (one-time setup)");
    eprintln!("this will create /etc/sudoers.d/silo");
    eprintln!();

    #[cfg(target_os = "macos")]
    let rules = "%admin ALL=(root) NOPASSWD: /sbin/ifconfig lo0 alias 127.0.* netmask 255.0.0.0\n\
                 %admin ALL=(root) NOPASSWD: /sbin/ifconfig lo0 -alias 127.0.*\n\
                 %admin ALL=(root) NOPASSWD: /usr/bin/tee /etc/hosts\n";

    #[cfg(target_os = "linux")]
    let rules = "%sudo ALL=(root) NOPASSWD: /sbin/ip addr add 127.0.*/8 dev lo\n\
                 %sudo ALL=(root) NOPASSWD: /sbin/ip addr del 127.0.*/8 dev lo\n\
                 %sudo ALL=(root) NOPASSWD: /usr/bin/tee /etc/hosts\n";

    let status = Command::new("sudo")
        .args(["tee", "/etc/sudoers.d/silo"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(rules.as_bytes())?;
            }
            child.wait()
        })
        .context("failed to install sudoers rule")?;

    if !status.success() {
        eyre::bail!("failed to install sudoers rule");
    }

    let status = Command::new("sudo")
        .args(["chmod", "0440", "/etc/sudoers.d/silo"])
        .status()
        .context("failed to chmod sudoers rule")?;

    if !status.success() {
        eyre::bail!("failed to chmod sudoers rule");
    }

    eprintln!("  configured. future commands won't ask for a password");
    eprintln!();

    Ok(())
}

pub fn ensure_sudoers() -> eyre::Result<()> {
    if !sudoers_configured() {
        install_sudoers()?;
    }
    Ok(())
}

fn run_sudo(args: &[&str]) -> eyre::Result<()> {
    debug!(cmd = %args.join(" "), "running sudo");
    let status = Command::new("sudo")
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("failed to run sudo")?;

    if !status.success() {
        eyre::bail!("command failed: sudo {}", args.join(" "));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_used() -> HashSet<Ipv4Addr> {
        HashSet::new()
    }

    fn used_set(ips: &[Ipv4Addr]) -> HashSet<Ipv4Addr> {
        ips.iter().copied().collect()
    }

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
    fn allocate_first_ip() {
        let used = empty_used();
        let ip = allocate_ip("127.0.1.0/24", &used).unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 1, 1));
    }

    #[test]
    fn allocate_skips_used() {
        let used = used_set(&[Ipv4Addr::new(127, 0, 1, 1)]);
        let ip = allocate_ip("127.0.1.0/24", &used).unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 1, 2));
    }

    #[test]
    fn allocate_skips_localhost() {
        let used = empty_used();
        let ip = allocate_ip("127.0.0.0/24", &used).unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 2));
    }

    #[test]
    fn allocate_rejects_non_loopback() {
        let used = empty_used();
        let err = allocate_ip("192.168.1.0/24", &used).unwrap_err();
        assert!(matches!(err, SiloError::IpNotLoopback(_)));
    }

    #[test]
    fn allocate_exhausted() {
        let used = used_set(&[
            Ipv4Addr::new(127, 0, 1, 1),
            Ipv4Addr::new(127, 0, 1, 2),
        ]);
        let err = allocate_ip("127.0.1.0/30", &used).unwrap_err();
        assert!(matches!(err, SiloError::IpRangeExhausted(_)));
    }

    #[test]
    fn allocate_invalid_cidr() {
        let used = empty_used();
        let err = allocate_ip("not-a-cidr", &used).unwrap_err();
        assert!(matches!(err, SiloError::InvalidCidrRange(_, _)));
    }
}
