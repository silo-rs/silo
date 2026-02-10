use std::process::Command;

use colored::Colorize;

use crate::ui;
use silo_core::config;
use silo_core::hosts;
use silo_core::ip;
use silo_core::store::Store;

pub async fn run(store: &Store) -> eyre::Result<()> {
    let mut warnings = 0;
    let mut errors = 0;

    ui::check_ok("silo", format!("v{}", env!("CARGO_PKG_VERSION")));

    match os_info() {
        Some(info) => ui::check_ok("os", &info),
        None => {
            ui::check_warn("os", "could not determine OS version");
            warnings += 1;
        }
    }

    match Command::new("git").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            ui::check_ok("git", version.trim());
        }
        _ => {
            ui::check_error("git", "not found in PATH");
            errors += 1;
        }
    }

    if std::path::Path::new("/etc/sudoers.d/silo").exists() {
        ui::check_ok("sudoers", "/etc/sudoers.d/silo configured");
    } else {
        ui::check_warn("sudoers", "not configured (will be set up on first use)");
        warnings += 1;
    }

    let count = store.count().await;
    let has_instances = match count {
        Ok(n) => {
            ui::check_ok("store", format!("{} instance(s)", n));
            n > 0
        }
        Err(e) => {
            ui::check_error("store", format!("failed to query: {e}"));
            errors += 1;
            false
        }
    };

    if has_instances {
        let instances = store.list_all().await.unwrap_or_default();
        let ips: Vec<_> = instances.iter().map(|i| i.ip).collect();
        let active = ip::active_ips(&ips).unwrap_or_default();

        let registered_count = instances.len();
        let active_count = active.len();
        if registered_count > 0 && active_count != registered_count {
            ui::check_warn(
                "aliases",
                format!(
                    "{}/{} IP aliases active (run `silo activate` to restore)",
                    active_count, registered_count
                ),
            );
            warnings += 1;
        } else if registered_count > 0 {
            ui::check_ok(
                "aliases",
                format!("all {} IP aliases active", registered_count),
            );
        }

        for inst in &instances {
            let mut issues = Vec::new();

            if !inst.path.exists() {
                issues.push("path missing".to_string());
            }

            if !active.contains(&inst.ip) {
                issues.push(format!("alias {} inactive", inst.ip));
            }

            if issues.is_empty() {
                ui::check_ok(
                    &format!("instance:{}", inst.name),
                    format!("{} @ {}", inst.ip, inst.path.display()),
                );
            } else {
                ui::check_warn(&format!("instance:{}", inst.name), issues.join(", "));
                warnings += 1;
            }
        }
    }

    match hosts::has_managed_block() {
        Ok(true) => match hosts::current_entries() {
            Ok(entries) => ui::check_ok(
                "hosts",
                format!("{} entry(ies) in /etc/hosts", entries.len()),
            ),
            Err(e) => {
                ui::check_warn("hosts", format!("failed to parse: {e}"));
                warnings += 1;
            }
        },
        Ok(false) => {
            if has_instances {
                ui::check_warn(
                    "hosts",
                    "no silo block in /etc/hosts (run `silo activate` to sync)",
                );
                warnings += 1;
            } else {
                ui::check_info("hosts", "no silo block in /etc/hosts");
            }
        }
        Err(e) => {
            ui::check_warn("hosts", format!("failed to read /etc/hosts: {e}"));
            warnings += 1;
        }
    }

    match config::load_config() {
        Ok((cfg, repo_root)) => {
            ui::check_ok("config", format!("{}/silo.toml", repo_root.display()));

            if cfg.instance.ip_range.parse::<ipnet::Ipv4Net>().is_ok() {
                ui::check_ok("ip_range", &cfg.instance.ip_range);
            } else {
                ui::check_error(
                    "ip_range",
                    format!("invalid CIDR: {}", cfg.instance.ip_range),
                );
                errors += 1;
            }
        }
        Err(_) => {
            ui::check_info("config", "not in a silo-enabled repository");
        }
    }

    for var in [
        "SILO_IP_RANGE",
        "SILO_WORKTREE_BASE_DIR",
        "SILO_WORKTREE_LINK",
    ] {
        if let Ok(val) = std::env::var(var) {
            ui::check_info("env", format!("{var}={val}"));
        }
    }

    if std::env::var("SILO_IP").is_ok() {
        ui::check_ok("shell", "SILO_IP set (inside an instance)");
    } else {
        ui::check_info("shell", "SILO_IP not set (not inside an instance)");
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

    Ok(())
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
