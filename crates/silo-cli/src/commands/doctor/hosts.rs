use super::Checker;

pub fn check_hosts_entries(ck: &mut Checker) {
    match std::fs::read_to_string("/etc/hosts") {
        Ok(content) => {
            let count = content.lines().filter(|l| l.ends_with(".silo")).count();
            if count > 0 {
                ck.ok("hosts", format!("{count} silo entry(ies) in /etc/hosts"));
            } else {
                ck.info("hosts", "no silo entries in /etc/hosts");
            }
        }
        Err(e) => {
            ck.warn("hosts", format!("failed to read /etc/hosts: {e}"));
        }
    }
}

pub fn check_stale_hosts(ck: &mut Checker) {
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
        ck.warn(
            "stale hosts",
            format!(
                "{stale_count} stale entry(ies) — directory no longer exists. Run `silo prune` to clean up"
            ),
        );
    } else {
        ck.ok(
            "stale hosts",
            "all host entries reference existing directories",
        );
    }
}
