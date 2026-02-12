use std::process::Command;

use colored::Colorize;

use crate::ui;

pub fn run() -> eyre::Result<()> {
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

    match super::run::find_bind_lib() {
        Ok(path) => ui::check_ok("bind lib", path.display().to_string()),
        Err(e) => {
            ui::check_error("bind lib", format!("failed to locate: {e}"));
            errors += 1;
        }
    }

    match std::fs::read_to_string("/etc/hosts") {
        Ok(content) => {
            let count = content.lines().filter(|l| l.ends_with(".silo")).count();
            if count > 0 {
                ui::check_ok("hosts", format!("{count} silo entry(ies) in /etc/hosts"));
            } else {
                ui::check_info("hosts", "no silo entries in /etc/hosts");
            }
        }
        Err(e) => {
            ui::check_warn("hosts", format!("failed to read /etc/hosts: {e}"));
            warnings += 1;
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
