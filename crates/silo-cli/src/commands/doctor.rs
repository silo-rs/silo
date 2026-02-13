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

    // eBPF backend (Linux only)
    #[cfg(target_os = "linux")]
    check_ebpf(&mut warnings);

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

#[cfg(target_os = "linux")]
fn check_ebpf(warnings: &mut usize) {
    use std::path::Path;

    // cgroup v2
    if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        ui::check_ok("cgroup", "v2 mounted");
    } else {
        ui::check_warn(
            "cgroup",
            "v2 not detected (eBPF backend requires cgroup v2)",
        );
        *warnings += 1;
        return;
    }

    // Kernel version
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
        ui::check_ok("kernel", ">= 5.8 (cgroup/sock_addr supported)");
    } else {
        ui::check_warn("kernel", "< 5.8 or unknown (eBPF backend needs >= 5.8)");
        *warnings += 1;
    }

    // Embedded bytecode
    let has_bytes = !crate::ebpf::embedded_bytes_empty();
    if has_bytes {
        ui::check_ok(
            "ebpf bytecode",
            "embedded (built with nightly + bpf-linker)",
        );
    } else {
        ui::check_info(
            "ebpf bytecode",
            "not embedded (build with nightly toolchain to enable)",
        );
    }

    // Pinned programs
    let pin_base = Path::new("/sys/fs/bpf/silo");
    if pin_base.join("silo_bind4").exists() {
        let pinned = crate::ebpf::PROGRAM_NAMES
            .iter()
            .filter(|name| pin_base.join(name).exists())
            .count();
        let has_map = pin_base.join("SILO_CONFIG").exists();
        ui::check_ok(
            "ebpf pinned",
            format!(
                "{}/{} programs, config map: {}",
                pinned,
                crate::ebpf::PROGRAM_NAMES.len(),
                if has_map { "yes" } else { "no" },
            ),
        );
    } else if crate::ebpf::ebpf_available() {
        ui::check_info(
            "ebpf pinned",
            "not pinned (run `sudo silo setup-ebpf` for rootless use)",
        );
    } else {
        ui::check_info("ebpf pinned", "not available (will use LD_PRELOAD backend)");
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
