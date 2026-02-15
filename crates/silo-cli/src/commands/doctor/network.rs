use std::net::Ipv4Addr;

use serde::Serialize;

use super::Checker;

#[derive(Serialize)]
pub struct NetworkInfo {
    loopback_up: bool,
    active_aliases: Vec<String>,
    alias_count: usize,
}

pub fn check_loopback(ck: &mut Checker) -> NetworkInfo {
    let loopback_up = is_loopback_up();

    if loopback_up {
        ck.ok("loopback", loopback_interface_name());
    } else {
        ck.error("loopback", "loopback interface not detected or not up");
    }

    let aliases = silo::ip::active_aliases().unwrap_or_default();
    let alias_count = aliases.len();

    if alias_count > 0 {
        ck.ok(
            "ip aliases",
            format!("{alias_count} active alias(es) on loopback"),
        );
    } else {
        ck.info("ip aliases", "no active silo aliases");
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
        std::process::Command::new("ifconfig")
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
