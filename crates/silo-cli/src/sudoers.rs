use std::process::{Command, Stdio};

use colored::Colorize;
use eyre::{Context, bail};

const SUDOERS_PATH: &str = "/etc/sudoers.d/silo";
const STAMP_PATH: &str = "/usr/local/libexec/.silo-stamp";
const SUDOERS_VERSION: u32 = 7;
const SUDOERS_VERSION_PREFIX: &str = "# silo sudoers v";
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) fn ensure() -> eyre::Result<()> {
    if let Ok(stamp) = std::fs::read_to_string(STAMP_PATH)
        && stamp_is_current(&stamp)
        && std::path::Path::new(SUDOERS_PATH).exists()
        && helper_matches_embedded(silo::hosts::SECURE_IP_HELPER, EMBEDDED_IP_HELPER)
        && helper_matches_embedded(silo::hosts::SECURE_HOSTS_HELPER, EMBEDDED_HOSTS_HELPER)
    {
        return Ok(());
    }
    install()
}

fn helper_matches_embedded(path: &str, embedded: &[u8]) -> bool {
    match std::fs::read(path) {
        Ok(content) => content == embedded,
        Err(_) => false,
    }
}

fn stamp_is_current(stamp: &str) -> bool {
    let Some(line) = stamp.lines().next() else {
        return false;
    };
    let Some(rest) = line.strip_prefix(SUDOERS_VERSION_PREFIX) else {
        return false;
    };
    let parts: Vec<&str> = rest.splitn(2, ' ').collect();
    let ver_ok = parts
        .first()
        .and_then(|v| v.parse::<u32>().ok())
        .map(|v| v >= SUDOERS_VERSION)
        .unwrap_or(false);
    let pkg_ok = parts
        .get(1)
        .and_then(|s| s.strip_prefix("pkg="))
        .map(|v| v == PKG_VERSION)
        .unwrap_or(false);
    ver_ok && pkg_ok
}

const EMBEDDED_IP_HELPER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/silo-ip-helper"));
const EMBEDDED_HOSTS_HELPER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/silo-hosts-helper"));

const HELPER_DIR: &str = "/usr/local/libexec";

fn install() -> eyre::Result<()> {
    let ip_helper = silo::hosts::SECURE_IP_HELPER;
    let hosts_helper = silo::hosts::SECURE_HOSTS_HELPER;

    eprintln!();
    eprintln!("silo needs passwordless sudo for loopback IP aliases (one-time setup)");
    eprintln!("this will install helper binaries to {HELPER_DIR} and create {SUDOERS_PATH}");
    eprintln!();

    let helper_dir = std::path::Path::new(HELPER_DIR);

    if !helper_dir.exists() {
        let status = Command::new("sudo")
            .args(["mkdir", "-p", HELPER_DIR])
            .status()
            .context("failed to create helper directory")?;

        if !status.success() {
            bail!("sudo mkdir -p {HELPER_DIR} failed");
        }
    }

    let path_warnings = check_path_security(helper_dir);
    if !path_warnings.is_empty() {
        for warn in &path_warnings {
            eprintln!("  {} {}", "WARNING:".yellow().bold(), warn);
        }
        bail!(
            "{HELPER_DIR} failed path security check — \
             refusing to install sudoers rules for an insecure path"
        );
    }

    install_embedded_helper(EMBEDDED_IP_HELPER, ip_helper)?;
    install_embedded_helper(EMBEDDED_HOSTS_HELPER, hosts_helper)?;

    let rules = sudoers_rules();
    validate_sudoers_syntax(&rules)?;

    write_root_file(rules.as_bytes(), SUDOERS_PATH, "0440")?;

    let stamp_content = format!("{SUDOERS_VERSION_PREFIX}{SUDOERS_VERSION} pkg={PKG_VERSION}\n");
    write_root_file(stamp_content.as_bytes(), STAMP_PATH, "0644")?;

    cleanup_legacy_paths();

    eprintln!("  configured. future commands won't ask for a password");
    eprintln!();

    Ok(())
}

fn cleanup_legacy_paths() {
    const LEGACY_BIN: &str = "/usr/local/bin/silo";
    const LEGACY_STAMP: &str = "/usr/local/bin/.silo-stamp";

    for path in [LEGACY_BIN, LEGACY_STAMP] {
        if std::path::Path::new(path).exists() {
            let _ = Command::new("sudo").args(["rm", "-f", path]).status();
        }
    }
}

fn install_embedded_helper(bytes: &[u8], dest: &str) -> eyre::Result<()> {
    write_root_file(bytes, dest, "755")
}

fn write_root_file(bytes: &[u8], dest: &str, mode: &str) -> eyre::Result<()> {
    use std::io::Write;

    let tmp_dest = format!("{dest}.tmp");

    let status = Command::new("sudo")
        .args(["install", "-m", mode, "/dev/null", &tmp_dest])
        .status()
        .with_context(|| format!("failed to create {tmp_dest}"))?;

    if !status.success() {
        bail!("failed to pre-create {tmp_dest} with mode {mode}");
    }

    let status = Command::new("sudo")
        .args(["tee", &tmp_dest])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .and_then(|mut child| {
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(bytes)?;
            }
            child.wait()
        })
        .with_context(|| format!("failed to write {tmp_dest}"))?;

    if !status.success() {
        let _ = Command::new("sudo").args(["rm", "-f", &tmp_dest]).status();
        bail!("sudo tee {tmp_dest} failed");
    }

    let status = Command::new("sudo")
        .args(["mv", "-f", &tmp_dest, dest])
        .status()
        .with_context(|| format!("failed to move {tmp_dest} to {dest}"))?;

    if !status.success() {
        let _ = Command::new("sudo").args(["rm", "-f", &tmp_dest]).status();
        bail!("sudo mv {tmp_dest} {dest} failed");
    }

    Ok(())
}

fn validate_sudoers_syntax(rules: &str) -> eyre::Result<()> {
    use std::io::Write;

    let mut tmp_file =
        tempfile::NamedTempFile::new().context("could not create temp file for visudo check")?;

    tmp_file
        .write_all(rules.as_bytes())
        .context("could not write temp file for visudo check")?;

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
            if mode & 0o020 != 0 {
                warnings.push(format!("{display} is group-writable"));
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
    let ip_helper = silo::hosts::SECURE_IP_HELPER;
    let hosts_helper = silo::hosts::SECURE_HOSTS_HELPER;

    #[cfg(target_os = "macos")]
    {
        format!(
            "{SUDOERS_VERSION_PREFIX}{SUDOERS_VERSION} pkg={PKG_VERSION}\n\
             %admin ALL=(root) NOPASSWD: {ip_helper} \"\"\n\
             %admin ALL=(root) NOPASSWD: {hosts_helper} \"\"\n"
        )
    }

    #[cfg(target_os = "linux")]
    {
        let group = detect_admin_group();
        format!(
            "{SUDOERS_VERSION_PREFIX}{SUDOERS_VERSION} pkg={PKG_VERSION}\n\
             {group} ALL=(root) NOPASSWD: {ip_helper} \"\"\n\
             {group} ALL=(root) NOPASSWD: {hosts_helper} \"\"\n"
        )
    }
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
    fn sudoers_rules_use_helpers() {
        let rules = sudoers_rules();
        assert!(
            rules.contains(silo::hosts::SECURE_IP_HELPER),
            "sudoers rules must reference ip helper path, got:\n{rules}"
        );
        assert!(
            rules.contains(silo::hosts::SECURE_HOSTS_HELPER),
            "sudoers rules must reference hosts helper path, got:\n{rules}"
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
        let expected_prefix =
            format!("{SUDOERS_VERSION_PREFIX}{SUDOERS_VERSION} pkg={PKG_VERSION}");
        assert!(
            rules.starts_with(&expected_prefix),
            "sudoers rules must start with version+pkg header, got:\n{rules}"
        );
    }

    #[test]
    fn sudoers_rules_reference_helper_paths() {
        let rules = sudoers_rules();
        assert!(
            rules.contains(silo::hosts::SECURE_IP_HELPER),
            "sudoers rules must reference ip helper path, got:\n{rules}"
        );
        assert!(
            rules.contains(silo::hosts::SECURE_HOSTS_HELPER),
            "sudoers rules must reference hosts helper path, got:\n{rules}"
        );
    }

    #[test]
    fn sudoers_rules_restrict_to_no_args() {
        let rules = sudoers_rules();
        for line in rules.lines() {
            if line.starts_with('#') {
                continue;
            }
            if line.contains("silo-ip-helper") || line.contains("silo-hosts-helper") {
                assert!(
                    line.ends_with("\"\""),
                    "helper rule must end with \"\" to restrict to no arguments, got:\n{line}"
                );
            }
        }
    }

    #[test]
    fn sudoers_rules_have_no_wildcards() {
        let rules = sudoers_rules();
        for line in rules.lines() {
            if line.starts_with('#') {
                continue;
            }
            assert!(
                !line.contains('*'),
                "sudoers rules must not contain wildcards, got:\n{line}"
            );
        }
    }

    #[test]
    fn sudoers_rules_no_main_binary_reference() {
        let rules = sudoers_rules();
        assert!(
            !rules.contains("/usr/local/bin/silo"),
            "sudoers rules must not reference the main silo binary, got:\n{rules}"
        );
    }

    #[test]
    fn sudoers_rules_no_direct_ifconfig_or_ip() {
        let rules = sudoers_rules();
        assert!(
            !rules.contains("ifconfig"),
            "sudoers rules must not reference ifconfig directly, got:\n{rules}"
        );
        assert!(
            !rules.contains("ip addr"),
            "sudoers rules must not reference ip addr directly, got:\n{rules}"
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
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let bin_path = dir.path().join("silo");
        std::fs::write(&bin_path, b"fake").unwrap();
        let warnings = check_path_security(&bin_path);
        assert!(
            !warnings.is_empty(),
            "should detect insecure path, got no warnings"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("not root") || w.contains("world-writable")),
            "should detect ownership or permission issue, got: {warnings:?}"
        );
    }

    #[test]
    fn path_security_checks_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let bin_path = dir.path().join("silo");
        std::fs::write(&bin_path, b"fake").unwrap();
        let warnings = check_path_security(&bin_path);
        assert!(
            !warnings.is_empty(),
            "should check parent directories, got: {warnings:?}"
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
    fn install_sh_has_no_sudoers_rules() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let install_sh = std::path::Path::new(manifest_dir)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("install.sh");
        let content = std::fs::read_to_string(&install_sh).expect("install.sh must exist");
        assert!(
            !content.contains("/usr/bin/tee"),
            "install.sh must not grant sudo access to tee"
        );
        assert!(
            !content.contains("sudoers.d/silo"),
            "install.sh must not write sudoers rules directly; \
             sudoers setup is handled by the silo binary on first run"
        );
    }

    #[test]
    fn stamp_current_valid() {
        let stamp = format!("{SUDOERS_VERSION_PREFIX}{SUDOERS_VERSION} pkg={PKG_VERSION}\n");
        assert!(stamp_is_current(&stamp));
    }

    #[test]
    fn stamp_current_old_version() {
        assert!(!stamp_is_current(&format!(
            "{SUDOERS_VERSION_PREFIX}1 pkg={PKG_VERSION}\n"
        )));
    }

    #[test]
    fn stamp_current_wrong_pkg() {
        assert!(!stamp_is_current(&format!(
            "{SUDOERS_VERSION_PREFIX}{SUDOERS_VERSION} pkg=0.0.0\n"
        )));
    }

    #[test]
    fn stamp_current_empty() {
        assert!(!stamp_is_current(""));
    }

    #[test]
    fn stamp_current_garbage() {
        assert!(!stamp_is_current("not a stamp"));
    }

    #[test]
    fn stamp_current_future_version() {
        let stamp = format!(
            "{SUDOERS_VERSION_PREFIX}{} pkg={PKG_VERSION}\n",
            SUDOERS_VERSION + 1
        );
        assert!(
            stamp_is_current(&stamp),
            "should accept newer sudoers versions"
        );
    }

    #[test]
    fn stamp_matches_sudoers_header() {
        let rules = sudoers_rules();
        let first_line = rules.lines().next().unwrap();
        let stamp = format!("{first_line}\n");
        assert!(
            stamp_is_current(&stamp),
            "stamp format must match sudoers header"
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
