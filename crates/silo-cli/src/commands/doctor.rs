use std::process::Command;

use colored::Colorize;
use serde::Serialize;

use crate::ui;

#[derive(Serialize)]
struct DoctorReport {
    checks: Vec<Check>,
    errors: usize,
    warnings: usize,
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

pub fn run(json: bool) -> eyre::Result<()> {
    let mut checks: Vec<Check> = Vec::new();
    let mut warnings = 0;
    let mut errors = 0;

    checks.push(Check {
        name: "silo".into(),
        status: CheckStatus::Ok,
        detail: format!("v{}", env!("CARGO_PKG_VERSION")),
    });

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
            warnings += 1;
        }
    }

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
            errors += 1;
        }
    }

    if std::path::Path::new("/etc/sudoers.d/silo").exists() {
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
        warnings += 1;
    }

    for (name, path) in [
        ("ip helper", silo::hosts::SECURE_IP_HELPER),
        ("hosts helper", silo::hosts::SECURE_HOSTS_HELPER),
    ] {
        let helper_path = std::path::Path::new(path);
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
                warnings += 1;
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
            warnings += 1;
        }
    }

    match super::run::find_bind_lib() {
        Ok(path) => checks.push(Check {
            name: "bind lib".into(),
            status: CheckStatus::Ok,
            detail: path.display().to_string(),
        }),
        Err(e) => {
            checks.push(Check {
                name: "bind lib".into(),
                status: CheckStatus::Error,
                detail: format!("failed to locate: {e}"),
            });
            errors += 1;
        }
    }

    #[cfg(target_os = "linux")]
    check_ebpf(&mut checks, &mut warnings);

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
            warnings += 1;
        }
    }

    if json {
        let report = DoctorReport {
            checks,
            errors,
            warnings,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
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
                format!("{} error(s), {} warning(s)", errors, warnings)
                    .red()
                    .bold()
            );
            std::process::exit(1);
        } else if warnings > 0 {
            eprintln!(
                "  {} {}",
                "⚠".yellow(),
                format!("no errors, {} warning(s)", warnings)
                    .yellow()
                    .bold()
            );
        } else {
            eprintln!("  {} {}", "✓".green(), "all checks passed".green().bold());
        }
    }

    Ok(())
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
        let output = Command::new("sw_vers")
            .args(["-productName", "-productVersion"])
            .output()
            .ok()?;
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            return Some(text.lines().collect::<Vec<_>>().join(" "));
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
