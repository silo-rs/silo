use std::process::Command;

use super::Checker;

pub fn check_os(ck: &mut Checker) {
    match os_info() {
        Some(info) => ck.ok("os", info),
        None => ck.warn("os", "could not determine OS version"),
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

#[cfg(target_os = "linux")]
pub fn check_ebpf(ck: &mut Checker) {
    use std::path::Path;

    if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        ck.ok("cgroup", "v2 mounted");
    } else {
        ck.warn(
            "cgroup",
            "v2 not detected (eBPF backend requires cgroup v2)",
        );
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
        ck.ok("kernel", ">= 5.8 (cgroup/sock_addr supported)");
    } else {
        ck.warn("kernel", "< 5.8 or unknown (eBPF backend needs >= 5.8)");
    }

    let has_bytes = !crate::ebpf::embedded_bytes_empty();
    if has_bytes {
        ck.ok(
            "ebpf bytecode",
            "embedded (built with nightly + bpf-linker)",
        );
    } else {
        ck.info(
            "ebpf bytecode",
            "not embedded (build with nightly toolchain to enable)",
        );
    }

    let pin_base = Path::new("/sys/fs/bpf/silo");
    if pin_base.join("silo_bind4").exists() {
        let pinned = crate::ebpf::BpfProgram::ALL
            .iter()
            .filter(|p| pin_base.join(p.name()).exists())
            .count();
        let has_map = pin_base.join("SILO_CONFIG").exists();
        ck.ok(
            "ebpf pinned",
            format!(
                "{}/{} programs, config map: {}",
                pinned,
                crate::ebpf::BpfProgram::ALL.len(),
                if has_map { "yes" } else { "no" },
            ),
        );
    } else if crate::ebpf::ebpf_available() {
        ck.info(
            "ebpf pinned",
            "not pinned (run `sudo silo setup-ebpf` for rootless use)",
        );
    } else {
        ck.info("ebpf pinned", "not available (will use LD_PRELOAD backend)");
    }
}
