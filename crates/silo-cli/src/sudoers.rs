use std::process::{Command, Stdio};

use colored::Colorize;
use eyre::{Context, bail};

const SUDOERS_PATH: &str = "/etc/sudoers.d/silo";
const SUDOERS_VERSION: u32 = 2;
const SUDOERS_VERSION_PREFIX: &str = "# silo sudoers v";

pub(crate) fn ensure() -> eyre::Result<()> {
    if let Ok(content) = std::fs::read_to_string(SUDOERS_PATH) {
        let current_bin = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();

        if let Some(first_line) = content.lines().next()
            && let Some(ver_str) = first_line.strip_prefix(SUDOERS_VERSION_PREFIX)
            && let Ok(ver) = ver_str.parse::<u32>()
            && ver >= SUDOERS_VERSION
            && content.contains(&current_bin)
        {
            return Ok(());
        }
    } else if std::path::Path::new(SUDOERS_PATH).exists() {
        return Ok(());
    }
    install()
}

fn install() -> eyre::Result<()> {
    eprintln!();
    eprintln!("silo needs passwordless sudo for loopback IP aliases (one-time setup)");
    eprintln!("this will create {SUDOERS_PATH}");
    eprintln!();

    let rules = sudoers_rules();

    if let Ok(bin_path) = std::env::current_exe() {
        let warnings = check_path_security(&bin_path);
        if !warnings.is_empty() {
            eprintln!(
                "  {} {}",
                "ERROR:".red().bold(),
                "refusing to install sudoers rules for an insecure binary path:".red()
            );
            eprintln!("    {}", bin_path.display());
            for w in &warnings {
                eprintln!("    - {w}");
            }
            eprintln!();
            eprintln!(
                "  {}",
                "To fix: install silo to a root-owned path (e.g. /usr/local/bin/silo)".yellow()
            );
            eprintln!(
                "  {}",
                "  sudo cp ~/.cargo/bin/silo /usr/local/bin/silo".dimmed()
            );
            eprintln!();
            if std::env::var("SILO_ALLOW_INSECURE_PATH").is_ok() {
                eprintln!(
                    "  {} proceeding anyway (SILO_ALLOW_INSECURE_PATH is set)",
                    "WARNING:".yellow().bold()
                );
                eprintln!();
            } else {
                bail!(
                    "sudoers installation blocked: binary path is not secure. \
                     Set SILO_ALLOW_INSECURE_PATH=1 to override (not recommended)."
                );
            }
        }
    }

    validate_sudoers_syntax(&rules)?;

    let status = Command::new("sudo")
        .args(["tee", SUDOERS_PATH])
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
        bail!("sudo tee {SUDOERS_PATH} failed");
    }

    let status = Command::new("sudo")
        .args(["chmod", "0440", SUDOERS_PATH])
        .status()
        .context("failed to chmod sudoers rule")?;

    if !status.success() {
        bail!("sudo chmod 0440 {SUDOERS_PATH} failed");
    }

    eprintln!("  configured. future commands won't ask for a password");
    eprintln!();

    Ok(())
}

fn validate_sudoers_syntax(rules: &str) -> eyre::Result<()> {
    use std::io::Write;

    let mut tmp_file = match tempfile::NamedTempFile::new() {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "  {} could not create temp file for visudo check: {e}",
                "WARNING:".yellow().bold()
            );
            return Ok(());
        }
    };

    if let Err(e) = tmp_file.write_all(rules.as_bytes()) {
        eprintln!(
            "  {} could not write temp file for visudo check: {e}",
            "WARNING:".yellow().bold()
        );
        return Ok(());
    }

    let result = Command::new("visudo")
        .args([
            "-cf",
            tmp_file.path().to_str().expect("temp path is valid UTF-8"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    drop(tmp_file);

    match result {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => {
            bail!(
                "generated sudoers rules failed visudo validation (exit {status}). \
                 This is a silo bug — please report it at https://github.com/silo-rs/silo/issues"
            );
        }
        Err(_) => {
            eprintln!(
                "  {} visudo not found; skipping syntax validation",
                "WARNING:".yellow().bold()
            );
            Ok(())
        }
    }
}

pub(crate) fn check_path_security(bin_path: &std::path::Path) -> Vec<String> {
    use std::os::unix::fs::MetadataExt;

    let mut warnings = Vec::new();
    let mut current = Some(bin_path);

    while let Some(path) = current {
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            let uid = meta.uid();
            let mode = meta.mode();
            let display = path.display();

            if uid != 0 {
                warnings.push(format!("{display} is owned by uid {uid} (not root)"));
            }
            if mode & 0o002 != 0 {
                warnings.push(format!("{display} is world-writable"));
            }
            if mode & 0o020 != 0 && uid != 0 {
                warnings.push(format!("{display} is group-writable and not root-owned"));
            }
        }

        if path == std::path::Path::new("/") {
            break;
        }
        current = path.parent();
    }

    warnings
}

fn sudoers_rules() -> String {
    let silo_bin = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "silo".to_string());

    #[cfg(target_os = "macos")]
    {
        format!(
            "{SUDOERS_VERSION_PREFIX}{SUDOERS_VERSION}\n\
             %admin ALL=(root) NOPASSWD: /sbin/ifconfig lo0 alias 127.* netmask 255.0.0.0\n\
             %admin ALL=(root) NOPASSWD: /sbin/ifconfig lo0 -alias 127.*\n\
             %admin ALL=(root) NOPASSWD: {silo_bin} _hosts add 127.* *.silo *\n\
             %admin ALL=(root) NOPASSWD: {silo_bin} _hosts remove *\n"
        )
    }

    #[cfg(target_os = "linux")]
    {
        let group = detect_admin_group();
        let ip_cmd = find_ip_command();
        format!(
            "{SUDOERS_VERSION_PREFIX}{SUDOERS_VERSION}\n\
             {group} ALL=(root) NOPASSWD: {ip_cmd} addr add 127.*/8 dev lo\n\
             {group} ALL=(root) NOPASSWD: {ip_cmd} addr del 127.*/8 dev lo\n\
             {group} ALL=(root) NOPASSWD: {silo_bin} _hosts add 127.* *.silo *\n\
             {group} ALL=(root) NOPASSWD: {silo_bin} _hosts remove *\n"
        )
    }
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

#[cfg(target_os = "linux")]
fn detect_admin_group() -> &'static str {
    if let Ok(content) = std::fs::read_to_string("/etc/group") {
        return admin_group_from_etc_group(&content);
    }
    "%sudo"
}

#[cfg(any(target_os = "linux", test))]
fn admin_group_from_etc_group(content: &str) -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn sudoers_rules_use_silo_hosts_helper() {
        let rules = sudoers_rules();
        assert!(
            rules.contains("_hosts add"),
            "sudoers rules must use silo _hosts add, got:\n{rules}"
        );
        assert!(
            rules.contains("_hosts remove"),
            "sudoers rules must use silo _hosts remove, got:\n{rules}"
        );
        assert!(
            !rules.contains("/usr/bin/tee"),
            "sudoers rules must not allow tee, got:\n{rules}"
        );
        assert!(
            !rules.contains(" mv "),
            "sudoers rules must not allow mv, got:\n{rules}"
        );
    }

    #[test]
    fn sudoers_has_version_header() {
        let rules = sudoers_rules();
        assert!(
            rules.starts_with(SUDOERS_VERSION_PREFIX),
            "sudoers rules must start with version header, got:\n{rules}"
        );
    }

    #[test]
    fn sudoers_ip_rules_restricted_to_loopback() {
        let rules = sudoers_rules();
        assert!(
            rules.contains("127.*"),
            "sudoers rules must restrict IPs to 127.*, got:\n{rules}"
        );
    }

    #[test]
    fn sudoers_hosts_rules_restrict_to_silo_suffix() {
        let rules = sudoers_rules();
        assert!(
            rules.contains("*.silo"),
            "sudoers rules must restrict hostnames to *.silo, got:\n{rules}"
        );
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

    #[test]
    fn path_security_detects_non_root_owner() {
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let bin_path = dir.path().join("silo");
        std::fs::write(&bin_path, b"fake").unwrap();
        let warnings = check_path_security(&bin_path);
        assert!(
            warnings.iter().any(|w| w.contains("not root")),
            "should detect non-root owner, got: {warnings:?}"
        );
    }

    #[test]
    fn path_security_checks_parent_directories() {
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let bin_path = dir.path().join("silo");
        std::fs::write(&bin_path, b"fake").unwrap();
        let warnings = check_path_security(&bin_path);
        let has_dir_warning = warnings
            .iter()
            .any(|w| w.contains(&dir.path().display().to_string()));
        assert!(
            has_dir_warning,
            "should check parent directory, got: {warnings:?}"
        );
    }

    #[test]
    fn path_security_root_path_ok() {
        let warnings = check_path_security(std::path::Path::new("/usr/bin/true"));
        let filtered: Vec<_> = warnings
            .iter()
            .filter(|w| {
                w.contains("/usr/bin/true") || w.contains("/usr/bin ") || w.contains("/usr ")
            })
            .collect();
        assert!(
            filtered.is_empty(),
            "root-owned paths should not warn, got: {filtered:?}"
        );
    }

    #[test]
    fn path_security_world_writable() {
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let bin_path = dir.path().join("silo");
        std::fs::write(&bin_path, b"fake").unwrap();
        std::fs::set_permissions(&bin_path, std::fs::Permissions::from_mode(0o777)).unwrap();
        let warnings = check_path_security(&bin_path);
        assert!(
            warnings.iter().any(|w| w.contains("world-writable")),
            "should detect world-writable, got: {warnings:?}"
        );
    }

    #[test]
    fn visudo_validates_generated_rules() {
        use std::io::Write;
        let rules = sudoers_rules();
        let mut tmp_file = tempfile::NamedTempFile::new().unwrap();
        tmp_file.write_all(rules.as_bytes()).unwrap();
        let result = std::process::Command::new("visudo")
            .args([
                "-cf",
                tmp_file.path().to_str().expect("temp path is valid UTF-8"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        drop(tmp_file);
        if let Ok(status) = result {
            assert!(
                status.success(),
                "generated sudoers rules must pass visudo validation"
            );
        }
    }
}
