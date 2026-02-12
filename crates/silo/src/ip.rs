use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};

use tracing::{debug, instrument};

use crate::error::{Error, Result};

/// Locate the `ip` command on Linux. Tries `which` first, then falls back to
/// well-known paths across distributions (Debian, Fedora, Arch, etc.).
#[cfg(target_os = "linux")]
fn find_ip_command() -> String {
    if let Ok(p) = which::which("ip") {
        return p.to_string_lossy().into_owned();
    }
    for candidate in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        if Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    "ip".to_string()
}

/// Detect the admin group for sudoers rules on Linux.
/// Debian/Ubuntu use `sudo`, RHEL/Fedora/Arch use `wheel`.
#[cfg(target_os = "linux")]
pub(crate) fn detect_admin_group() -> &'static str {
    if let Ok(content) = std::fs::read_to_string("/etc/group") {
        return admin_group_from_etc_group(&content);
    }
    "%sudo"
}

/// Parse /etc/group content and return the appropriate sudoers group.
/// Extracted for testability.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn admin_group_from_etc_group(content: &str) -> &'static str {
    let has_sudo = content.lines().any(|l| l.starts_with("sudo:"));
    let has_wheel = content.lines().any(|l| l.starts_with("wheel:"));
    if has_sudo {
        return "%sudo";
    }
    if has_wheel {
        return "%wheel";
    }
    "%sudo"
}

#[instrument]
pub fn add_alias(ip: Ipv4Addr) -> Result<()> {
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
    {
        let ip_cmd = find_ip_command();
        run_sudo(&[&ip_cmd, "addr", "add", &format!("{}/8", ip), "dev", "lo"])?;
    }

    Ok(())
}

#[allow(dead_code)]
#[instrument]
pub fn remove_alias(ip: Ipv4Addr) -> Result<()> {
    if !alias_exists(ip)? {
        debug!(%ip, "alias does not exist, skipping");
        return Ok(());
    }

    ensure_sudoers()?;

    eprintln!("  removing loopback alias {}", ip);

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

#[allow(dead_code)]
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

fn sudoers_configured() -> bool {
    let exists = Path::new("/etc/sudoers.d/silo").exists();
    debug!(exists, "checking /etc/sudoers.d/silo");
    exists
}

fn install_sudoers() -> Result<()> {
    eprintln!();
    eprintln!("silo needs passwordless sudo for loopback IP aliases (one-time setup)");
    eprintln!("this will create /etc/sudoers.d/silo");
    eprintln!();

    #[cfg(target_os = "macos")]
    let rules = "%admin ALL=(root) NOPASSWD: /sbin/ifconfig lo0 alias 127.* netmask 255.0.0.0\n\
                 %admin ALL=(root) NOPASSWD: /sbin/ifconfig lo0 -alias 127.*\n\
                 %admin ALL=(root) NOPASSWD: /usr/bin/tee /etc/hosts\n";

    #[cfg(target_os = "linux")]
    let rules = {
        let group = detect_admin_group();
        let ip_cmd = find_ip_command();
        let tee_cmd = which::which("tee")
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "/usr/bin/tee".to_string());
        format!(
            "{group} ALL=(root) NOPASSWD: {ip_cmd} addr add 127.*/8 dev lo\n\
             {group} ALL=(root) NOPASSWD: {ip_cmd} addr del 127.*/8 dev lo\n\
             {group} ALL=(root) NOPASSWD: {tee_cmd} /etc/hosts\n"
        )
    };

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
        .map_err(|e| Error::io("failed to install sudoers rule", e))?;

    if !status.success() {
        return Err(Error::CommandFailed {
            command: "sudo tee /etc/sudoers.d/silo".into(),
        });
    }

    let status = Command::new("sudo")
        .args(["chmod", "0440", "/etc/sudoers.d/silo"])
        .status()
        .map_err(|e| Error::io("failed to chmod sudoers rule", e))?;

    if !status.success() {
        return Err(Error::CommandFailed {
            command: "sudo chmod 0440 /etc/sudoers.d/silo".into(),
        });
    }

    eprintln!("  configured. future commands won't ask for a password");
    eprintln!();

    Ok(())
}

pub fn ensure_sudoers() -> Result<()> {
    if !sudoers_configured() {
        install_sudoers()?;
    }
    Ok(())
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

    #[test]
    fn admin_group_debian_has_sudo() {
        let etc_group = "root:x:0:\ndaemon:x:1:\nsudo:x:27:user\nusers:x:100:\n";
        assert_eq!(admin_group_from_etc_group(etc_group), "%sudo");
    }

    #[test]
    fn admin_group_fedora_has_wheel() {
        let etc_group = "root:x:0:\nwheel:x:10:user\nusers:x:100:\n";
        assert_eq!(admin_group_from_etc_group(etc_group), "%wheel");
    }

    #[test]
    fn admin_group_both_prefers_sudo() {
        let etc_group = "root:x:0:\nsudo:x:27:user\nwheel:x:10:user\n";
        assert_eq!(admin_group_from_etc_group(etc_group), "%sudo");
    }

    #[test]
    fn admin_group_neither_defaults_sudo() {
        let etc_group = "root:x:0:\nusers:x:100:\n";
        assert_eq!(admin_group_from_etc_group(etc_group), "%sudo");
    }
}
