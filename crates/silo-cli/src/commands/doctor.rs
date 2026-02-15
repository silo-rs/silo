use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use colored::Colorize;
use serde::Serialize;

use crate::ui;

#[derive(Serialize)]
struct DoctorReport {
    version: String,
    checks: Vec<Check>,
    errors: usize,
    warnings: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    shell: Option<ShellInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<EnvironmentInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<NetworkInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    worktrees: Option<WorktreeInfo>,
}

#[derive(Serialize)]
struct Check {
    name: String,
    status: CheckStatus,
    detail: String,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum CheckStatus {
    Ok,
    Warn,
    Error,
    Info,
}

#[derive(Serialize)]
struct ShellInfo {
    current_shell: Option<String>,
    current_shell_name: Option<String>,
    default_shell: Option<String>,
    #[cfg(target_os = "macos")]
    sip_protected: bool,
    #[cfg(target_os = "macos")]
    non_sip_alternative: Option<String>,
}

#[derive(Serialize)]
struct EnvironmentInfo {
    silo_ip: Option<String>,
    silo_backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ld_preload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dyld_insert_libraries: Option<String>,
    nested_session: bool,
}

#[derive(Serialize)]
struct NetworkInfo {
    loopback_up: bool,
    active_aliases: Vec<String>,
    alias_count: usize,
}

#[derive(Serialize)]
struct WorktreeInfo {
    worktree_count: usize,
    entries: Vec<WorktreeEntry>,
}

#[derive(Serialize)]
struct WorktreeEntry {
    path: String,
    branch: Option<String>,
    ip: Option<String>,
}

fn detect_parent_shell() -> Option<(String, String)> {
    let our_pid = std::process::id();

    #[cfg(target_os = "macos")]
    {
        let ppid_output = Command::new("ps")
            .args(["-o", "ppid=", "-p", &our_pid.to_string()])
            .output()
            .ok()?;
        let ppid_str = String::from_utf8_lossy(&ppid_output.stdout)
            .trim()
            .to_string();
        let ppid: u32 = ppid_str.parse().ok()?;

        let comm_output = Command::new("ps")
            .args(["-o", "comm=", "-p", &ppid.to_string()])
            .output()
            .ok()?;
        let shell_path = String::from_utf8_lossy(&comm_output.stdout)
            .trim()
            .to_string();
        if shell_path.is_empty() {
            return None;
        }
        let name = Path::new(&shell_path)
            .file_name()?
            .to_str()?
            .trim_start_matches('-')
            .to_string();
        Some((shell_path, name))
    }

    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{our_pid}/stat")).ok()?;
        let after_comm = stat.rfind(')')? + 2;
        let rest = &stat[after_comm..];
        let fields: Vec<&str> = rest.split_whitespace().collect();
        let ppid: u32 = fields.get(1)?.parse().ok()?;

        let shell_path = std::fs::read_link(format!("/proc/{ppid}/exe"))
            .ok()?
            .to_string_lossy()
            .into_owned();
        let name = Path::new(&shell_path)
            .file_name()?
            .to_str()?
            .trim_start_matches('-')
            .to_string();
        Some((shell_path, name))
    }
}

fn detect_default_shell() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let user = std::env::var("USER").ok()?;
        let output = Command::new("dscl")
            .args([".", "-read", &format!("/Users/{user}"), "UserShell"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        text.lines()
            .find_map(|line| line.strip_prefix("UserShell:"))
            .map(|s| s.trim().to_string())
    }

    #[cfg(target_os = "linux")]
    {
        let user = std::env::var("USER").ok()?;
        let output = Command::new("getent")
            .args(["passwd", &user])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        text.split(':').nth(6).map(|s| s.trim().to_string())
    }
}

fn check_os(checks: &mut Vec<Check>, warnings: &mut usize) {
    match os_info() {
        Some(info) => checks.push(Check {
            name: "os".into(),
            status: CheckStatus::Ok,
            detail: info,
        }),
        None => {
            checks.push(Check {
                name: "os".into(),
                status: CheckStatus::Warn,
                detail: "could not determine OS version".into(),
            });
            *warnings += 1;
        }
    }
}

fn check_shell(checks: &mut Vec<Check>, warnings: &mut usize) -> Option<ShellInfo> {
    let (shell_path, shell_name) = match detect_parent_shell() {
        Some(s) => s,
        None => {
            checks.push(Check {
                name: "shell".into(),
                status: CheckStatus::Info,
                detail: "could not detect parent shell".into(),
            });
            return None;
        }
    };

    let default_shell = detect_default_shell();

    #[cfg(target_os = "macos")]
    let (sip_protected, non_sip_alternative) = {
        let path = Path::new(&shell_path);
        if silo::shebang::is_sip_protected(path) {
            let alt = silo::shebang::find_non_sip_binary(&shell_name);
            if let Some(ref alt_path) = alt {
                checks.push(Check {
                    name: "shell".into(),
                    status: CheckStatus::Warn,
                    detail: format!(
                        "{shell_path} is SIP-protected; non-SIP alternative: {alt_path}"
                    ),
                });
            } else {
                checks.push(Check {
                    name: "shell".into(),
                    status: CheckStatus::Warn,
                    detail: format!(
                        "{shell_path} is SIP-protected — install via Homebrew: brew install {shell_name}"
                    ),
                });
            }
            *warnings += 1;
            (true, alt)
        } else {
            checks.push(Check {
                name: "shell".into(),
                status: CheckStatus::Ok,
                detail: format!("{shell_path} ({shell_name})"),
            });
            (false, None)
        }
    };

    #[cfg(not(target_os = "macos"))]
    checks.push(Check {
        name: "shell".into(),
        status: CheckStatus::Ok,
        detail: format!("{shell_path} ({shell_name})"),
    });

    if let Some(ref default) = default_shell {
        if default != &shell_path {
            checks.push(Check {
                name: "default shell".into(),
                status: CheckStatus::Info,
                detail: default.clone(),
            });
        }
    }

    Some(ShellInfo {
        current_shell: Some(shell_path),
        current_shell_name: Some(shell_name),
        default_shell,
        #[cfg(target_os = "macos")]
        sip_protected,
        #[cfg(target_os = "macos")]
        non_sip_alternative,
    })
}

fn check_environment(checks: &mut Vec<Check>, warnings: &mut usize) -> EnvironmentInfo {
    let silo_ip = std::env::var("SILO_IP").ok();
    let silo_backend = std::env::var("SILO_BACKEND").ok();
    let nested = silo_ip.is_some();

    if nested {
        checks.push(Check {
            name: "session".into(),
            status: CheckStatus::Warn,
            detail: format!(
                "nested silo session detected (SILO_IP={})",
                silo_ip.as_deref().unwrap_or("?")
            ),
        });
        *warnings += 1;
    } else {
        checks.push(Check {
            name: "session".into(),
            status: CheckStatus::Ok,
            detail: "not inside a silo session".into(),
        });
    }

    #[cfg(target_os = "macos")]
    let dyld = std::env::var("DYLD_INSERT_LIBRARIES").ok();
    #[cfg(not(target_os = "macos"))]
    let dyld: Option<String> = None;

    #[cfg(target_os = "linux")]
    let ld_preload = std::env::var("LD_PRELOAD").ok();
    #[cfg(not(target_os = "linux"))]
    let ld_preload: Option<String> = None;

    #[cfg(target_os = "macos")]
    if let Some(ref val) = dyld {
        if !val.contains("libsilo_bind") {
            checks.push(Check {
                name: "DYLD_INSERT_LIBRARIES".into(),
                status: CheckStatus::Warn,
                detail: format!("already set to: {val} (may conflict with silo)"),
            });
            *warnings += 1;
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(ref val) = ld_preload {
        if !val.contains("libsilo_bind") {
            checks.push(Check {
                name: "LD_PRELOAD".into(),
                status: CheckStatus::Warn,
                detail: format!("already set to: {val} (may conflict with silo)"),
            });
            *warnings += 1;
        }
    }

    EnvironmentInfo {
        silo_ip,
        silo_backend,
        ld_preload,
        dyld_insert_libraries: dyld,
        nested_session: nested,
    }
}

fn check_git(checks: &mut Vec<Check>, errors: &mut usize) {
    match Command::new("git").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            checks.push(Check {
                name: "git".into(),
                status: CheckStatus::Ok,
                detail: version.trim().to_string(),
            });
        }
        _ => {
            checks.push(Check {
                name: "git".into(),
                status: CheckStatus::Error,
                detail: "not found in PATH".into(),
            });
            *errors += 1;
        }
    }
}

fn check_worktrees(checks: &mut Vec<Check>) -> Option<WorktreeInfo> {
    let cwd = std::env::current_dir().ok()?;

    let git_root_output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(&cwd)
        .output()
        .ok()?;
    if !git_root_output.status.success() {
        return None;
    }
    let git_root = PathBuf::from(
        String::from_utf8_lossy(&git_root_output.stdout)
            .trim()
            .to_string(),
    );

    let output = Command::new("git")
        .args(["worktree", "list", "--porcelain"])
        .current_dir(&git_root)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut entries = Vec::new();
    let mut current_path: Option<String> = None;
    let mut current_branch: Option<String> = None;

    for line in text.lines() {
        if let Some(path) = line.strip_prefix("worktree ") {
            if let Some(ref p) = current_path {
                entries.push(make_worktree_entry(p, current_branch.take()));
            }
            current_path = Some(path.to_string());
            current_branch = None;
        } else if let Some(branch) = line.strip_prefix("branch refs/heads/") {
            current_branch = Some(branch.to_string());
        }
    }
    if let Some(ref p) = current_path {
        entries.push(make_worktree_entry(p, current_branch.take()));
    }

    let count = entries.len();
    if count > 1 {
        let ips: Vec<&str> = entries.iter().filter_map(|e| e.ip.as_deref()).collect();
        let unique: HashSet<&&str> = ips.iter().collect();
        if unique.len() < ips.len() {
            checks.push(Check {
                name: "worktrees".into(),
                status: CheckStatus::Warn,
                detail: format!("{count} worktree(s), IP collision detected"),
            });
        } else {
            checks.push(Check {
                name: "worktrees".into(),
                status: CheckStatus::Ok,
                detail: format!("{count} worktree(s), all unique IPs"),
            });
        }
    } else {
        checks.push(Check {
            name: "worktrees".into(),
            status: CheckStatus::Info,
            detail: format!("{count} worktree(s)"),
        });
    }

    Some(WorktreeInfo {
        worktree_count: count,
        entries,
    })
}

fn make_worktree_entry(path: &str, branch: Option<String>) -> WorktreeEntry {
    let canonical = Path::new(path)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(path));
    let branch_name = branch.unwrap_or_default();
    let name = silo::sanitize_name(&branch_name);
    let ip = if !name.is_empty() {
        Some(silo::compute_ip(&canonical, &name).to_string())
    } else {
        None
    };
    WorktreeEntry {
        path: path.to_string(),
        branch: if branch_name.is_empty() {
            None
        } else {
            Some(branch_name)
        },
        ip,
    }
}

fn check_sudoers(checks: &mut Vec<Check>, warnings: &mut usize) {
    if Path::new("/etc/sudoers.d/silo").exists() {
        checks.push(Check {
            name: "sudoers".into(),
            status: CheckStatus::Ok,
            detail: "/etc/sudoers.d/silo configured".into(),
        });
    } else {
        checks.push(Check {
            name: "sudoers".into(),
            status: CheckStatus::Warn,
            detail: "not configured (will be set up on first use)".into(),
        });
        *warnings += 1;
    }
}

fn check_helpers(checks: &mut Vec<Check>, warnings: &mut usize) {
    for (name, path) in [
        ("ip helper", silo::hosts::SECURE_IP_HELPER),
        ("hosts helper", silo::hosts::SECURE_HOSTS_HELPER),
    ] {
        let helper_path = Path::new(path);
        if helper_path.exists() {
            let path_warnings = crate::sudoers::check_path_security(helper_path);
            if path_warnings.is_empty() {
                checks.push(Check {
                    name: name.into(),
                    status: CheckStatus::Ok,
                    detail: format!("{} (root-owned)", helper_path.display()),
                });
            } else {
                checks.push(Check {
                    name: name.into(),
                    status: CheckStatus::Warn,
                    detail: format!(
                        "insecure path: {}",
                        path_warnings.first().unwrap_or(&String::new())
                    ),
                });
                *warnings += 1;
            }
        } else {
            checks.push(Check {
                name: name.into(),
                status: CheckStatus::Warn,
                detail: format!(
                    "{} not found (will be installed on first use)",
                    helper_path.display()
                ),
            });
            *warnings += 1;
        }
    }
}

fn check_bind_lib(checks: &mut Vec<Check>, errors: &mut usize) -> Option<PathBuf> {
    match super::run::find_bind_lib() {
        Ok(path) => {
            checks.push(Check {
                name: "bind lib".into(),
                status: CheckStatus::Ok,
                detail: path.display().to_string(),
            });
            Some(path)
        }
        Err(e) => {
            checks.push(Check {
                name: "bind lib".into(),
                status: CheckStatus::Error,
                detail: format!("failed to locate: {e}"),
            });
            *errors += 1;
            None
        }
    }
}

fn check_injection(
    checks: &mut Vec<Check>,
    errors: &mut usize,
    warnings: &mut usize,
    bind_lib: Option<&Path>,
) {
    let lib_path = match bind_lib {
        Some(p) => p,
        None => return,
    };

    #[cfg(target_os = "macos")]
    let (env_key, test_cmd, test_args) = {
        let shell = silo::shebang::find_non_sip_binary("sh");
        match shell {
            Some(sh) => (
                "DYLD_INSERT_LIBRARIES",
                sh,
                vec!["-c".to_string(), "exit 0".to_string()],
            ),
            None => {
                checks.push(Check {
                    name: "injection test".into(),
                    status: CheckStatus::Info,
                    detail: "skipped: no non-SIP binary available for testing".into(),
                });
                return;
            }
        }
    };

    #[cfg(target_os = "linux")]
    let (env_key, test_cmd, test_args) = (
        "LD_PRELOAD",
        "/usr/bin/true".to_string(),
        Vec::<String>::new(),
    );

    let result = Command::new(&test_cmd)
        .args(&test_args)
        .env(env_key, lib_path.display().to_string())
        .env("SILO_IP", "127.0.0.1")
        .output();

    match result {
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if output.status.success() && stderr.is_empty() {
                checks.push(Check {
                    name: "injection test".into(),
                    status: CheckStatus::Ok,
                    detail: format!("bind library loads successfully via {env_key}"),
                });
            } else if output.status.success() {
                let first_line = stderr.lines().next().unwrap_or("").to_string();
                checks.push(Check {
                    name: "injection test".into(),
                    status: CheckStatus::Warn,
                    detail: format!("loaded with warnings: {first_line}"),
                });
                *warnings += 1;
            } else {
                let first_line = stderr.lines().next().unwrap_or("").to_string();
                checks.push(Check {
                    name: "injection test".into(),
                    status: CheckStatus::Error,
                    detail: format!("failed to load: exit={}, {first_line}", output.status),
                });
                *errors += 1;
            }
        }
        Err(e) => {
            checks.push(Check {
                name: "injection test".into(),
                status: CheckStatus::Error,
                detail: format!("could not run injection test: {e}"),
            });
            *errors += 1;
        }
    }
}

fn check_loopback(checks: &mut Vec<Check>, errors: &mut usize) -> NetworkInfo {
    let loopback_up = is_loopback_up();

    if loopback_up {
        checks.push(Check {
            name: "loopback".into(),
            status: CheckStatus::Ok,
            detail: loopback_interface_name().into(),
        });
    } else {
        checks.push(Check {
            name: "loopback".into(),
            status: CheckStatus::Error,
            detail: "loopback interface not detected or not up".into(),
        });
        *errors += 1;
    }

    let aliases = silo::ip::active_aliases().unwrap_or_default();
    let alias_count = aliases.len();

    if alias_count > 0 {
        checks.push(Check {
            name: "ip aliases".into(),
            status: CheckStatus::Ok,
            detail: format!("{alias_count} active alias(es) on loopback"),
        });
    } else {
        checks.push(Check {
            name: "ip aliases".into(),
            status: CheckStatus::Info,
            detail: "no active silo aliases".into(),
        });
    }

    NetworkInfo {
        loopback_up,
        active_aliases: aliases.iter().map(Ipv4Addr::to_string).collect(),
        alias_count,
    }
}

fn is_loopback_up() -> bool {
    #[cfg(target_os = "macos")]
    {
        Command::new("ifconfig")
            .arg("lo0")
            .output()
            .ok()
            .is_some_and(|o| {
                let s = String::from_utf8_lossy(&o.stdout);
                o.status.success() && s.contains("UP")
            })
    }

    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/sys/class/net/lo/operstate")
            .map(|s| {
                let state = s.trim();
                state == "unknown" || state == "up"
            })
            .unwrap_or(false)
    }
}

const fn loopback_interface_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "lo0"
    }
    #[cfg(target_os = "linux")]
    {
        "lo"
    }
}

fn check_hosts_entries(checks: &mut Vec<Check>, warnings: &mut usize) {
    match std::fs::read_to_string("/etc/hosts") {
        Ok(content) => {
            let count = content.lines().filter(|l| l.ends_with(".silo")).count();
            if count > 0 {
                checks.push(Check {
                    name: "hosts".into(),
                    status: CheckStatus::Ok,
                    detail: format!("{count} silo entry(ies) in /etc/hosts"),
                });
            } else {
                checks.push(Check {
                    name: "hosts".into(),
                    status: CheckStatus::Info,
                    detail: "no silo entries in /etc/hosts".into(),
                });
            }
        }
        Err(e) => {
            checks.push(Check {
                name: "hosts".into(),
                status: CheckStatus::Warn,
                detail: format!("failed to read /etc/hosts: {e}"),
            });
            *warnings += 1;
        }
    }
}

fn check_stale_hosts(checks: &mut Vec<Check>, warnings: &mut usize) {
    let entries = match silo::hosts::list_entries() {
        Ok(e) => e,
        Err(_) => return,
    };

    if entries.is_empty() {
        return;
    }

    let mut stale_count = 0;
    for entry in &entries {
        if let Some(ref dir) = entry.dir {
            if !dir.exists() {
                stale_count += 1;
            }
        }
    }

    if stale_count > 0 {
        checks.push(Check {
            name: "stale hosts".into(),
            status: CheckStatus::Warn,
            detail: format!(
                "{stale_count} stale entry(ies) — directory no longer exists. Run `silo prune` to clean up"
            ),
        });
        *warnings += 1;
    } else {
        checks.push(Check {
            name: "stale hosts".into(),
            status: CheckStatus::Ok,
            detail: "all host entries reference existing directories".into(),
        });
    }
}

#[cfg(target_os = "linux")]
fn check_ebpf(checks: &mut Vec<Check>, warnings: &mut usize) {
    use std::path::Path;

    if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        checks.push(Check {
            name: "cgroup".into(),
            status: CheckStatus::Ok,
            detail: "v2 mounted".into(),
        });
    } else {
        checks.push(Check {
            name: "cgroup".into(),
            status: CheckStatus::Warn,
            detail: "v2 not detected (eBPF backend requires cgroup v2)".into(),
        });
        *warnings += 1;
        return;
    }

    let ver_ok = std::fs::read_to_string("/proc/version")
        .ok()
        .and_then(|v| {
            let rest = v.strip_prefix("Linux version ")?;
            let parts: Vec<&str> = rest.split(|c: char| !c.is_ascii_digit()).collect();
            let major: u32 = parts.first()?.parse().ok()?;
            let minor: u32 = parts.get(1)?.parse().ok()?;
            Some((major, minor) >= (5, 8))
        })
        .unwrap_or(false);

    if ver_ok {
        checks.push(Check {
            name: "kernel".into(),
            status: CheckStatus::Ok,
            detail: ">= 5.8 (cgroup/sock_addr supported)".into(),
        });
    } else {
        checks.push(Check {
            name: "kernel".into(),
            status: CheckStatus::Warn,
            detail: "< 5.8 or unknown (eBPF backend needs >= 5.8)".into(),
        });
        *warnings += 1;
    }

    let has_bytes = !crate::ebpf::embedded_bytes_empty();
    if has_bytes {
        checks.push(Check {
            name: "ebpf bytecode".into(),
            status: CheckStatus::Ok,
            detail: "embedded (built with nightly + bpf-linker)".into(),
        });
    } else {
        checks.push(Check {
            name: "ebpf bytecode".into(),
            status: CheckStatus::Info,
            detail: "not embedded (build with nightly toolchain to enable)".into(),
        });
    }

    let pin_base = Path::new("/sys/fs/bpf/silo");
    if pin_base.join("silo_bind4").exists() {
        let pinned = crate::ebpf::BpfProgram::ALL
            .iter()
            .filter(|p| pin_base.join(p.name()).exists())
            .count();
        let has_map = pin_base.join("SILO_CONFIG").exists();
        checks.push(Check {
            name: "ebpf pinned".into(),
            status: CheckStatus::Ok,
            detail: format!(
                "{}/{} programs, config map: {}",
                pinned,
                crate::ebpf::BpfProgram::ALL.len(),
                if has_map { "yes" } else { "no" },
            ),
        });
    } else if crate::ebpf::ebpf_available() {
        checks.push(Check {
            name: "ebpf pinned".into(),
            status: CheckStatus::Info,
            detail: "not pinned (run `sudo silo setup-ebpf` for rootless use)".into(),
        });
    } else {
        checks.push(Check {
            name: "ebpf pinned".into(),
            status: CheckStatus::Info,
            detail: "not available (will use LD_PRELOAD backend)".into(),
        });
    }
}

fn os_info() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let name = Command::new("sw_vers")
            .arg("-productName")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
        let version = Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
        match (name, version) {
            (Some(n), Some(v)) => return Some(format!("{n} {v}")),
            (None, Some(v)) => return Some(v),
            (Some(n), None) => return Some(n),
            _ => {}
        }
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("uname").args(["-sr"]).output().ok()?;
        if output.status.success() {
            return Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
        }
    }

    None
}

pub fn run(json: bool) -> eyre::Result<()> {
    let mut checks: Vec<Check> = Vec::new();
    let mut warnings = 0;
    let mut errors = 0;

    checks.push(Check {
        name: "silo".into(),
        status: CheckStatus::Ok,
        detail: format!("v{}", env!("CARGO_PKG_VERSION")),
    });

    check_os(&mut checks, &mut warnings);

    let shell_info = check_shell(&mut checks, &mut warnings);

    let env_info = check_environment(&mut checks, &mut warnings);

    check_git(&mut checks, &mut errors);

    let worktree_info = check_worktrees(&mut checks);

    check_sudoers(&mut checks, &mut warnings);

    check_helpers(&mut checks, &mut warnings);

    let bind_lib = check_bind_lib(&mut checks, &mut errors);

    check_injection(&mut checks, &mut errors, &mut warnings, bind_lib.as_deref());

    let network_info = check_loopback(&mut checks, &mut errors);

    #[cfg(target_os = "linux")]
    check_ebpf(&mut checks, &mut warnings);

    check_hosts_entries(&mut checks, &mut warnings);

    check_stale_hosts(&mut checks, &mut warnings);

    if json {
        let report = DoctorReport {
            version: env!("CARGO_PKG_VERSION").to_string(),
            checks,
            errors,
            warnings,
            shell: shell_info,
            environment: Some(env_info),
            network: Some(network_info),
            worktrees: worktree_info,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        eprintln!();
        eprintln!(
            "  {}",
            "Please include the above JSON output with bug reports.".dimmed()
        );
        if errors > 0 {
            std::process::exit(1);
        }
    } else {
        for check in &checks {
            match check.status {
                CheckStatus::Ok => ui::check_ok(&check.name, &check.detail),
                CheckStatus::Warn => ui::check_warn(&check.name, &check.detail),
                CheckStatus::Error => ui::check_error(&check.name, &check.detail),
                CheckStatus::Info => ui::check_info(&check.name, &check.detail),
            }
        }

        eprintln!();
        if errors > 0 {
            eprintln!(
                "  {} {}",
                "✗".red(),
                format!("{errors} error(s), {warnings} warning(s)")
                    .red()
                    .bold()
            );
            eprintln!();
            eprintln!(
                "  {}",
                "Run `silo doctor --json` and include the output with bug reports.".dimmed()
            );
            std::process::exit(1);
        } else if warnings > 0 {
            eprintln!(
                "  {} {}",
                "⚠".yellow(),
                format!("no errors, {warnings} warning(s)").yellow().bold()
            );
        } else {
            eprintln!("  {} {}", "✓".green(), "all checks passed".green().bold());
        }
    }

    Ok(())
}
