use std::path::{Path, PathBuf};
use std::process::Command;

use super::Checker;

pub fn check_sudoers(ck: &mut Checker) {
    if Path::new("/etc/sudoers.d/silo").exists() {
        ck.ok("sudoers", "/etc/sudoers.d/silo configured");
    } else {
        ck.warn("sudoers", "not configured (will be set up on first use)");
    }
}

pub fn check_helpers(ck: &mut Checker) {
    for (name, path) in [
        ("ip helper", silo::hosts::SECURE_IP_HELPER),
        ("hosts helper", silo::hosts::SECURE_HOSTS_HELPER),
    ] {
        let helper_path = Path::new(path);
        if helper_path.exists() {
            let path_warnings = crate::sudoers::check_path_security(helper_path);
            if path_warnings.is_empty() {
                ck.ok(name, format!("{} (root-owned)", helper_path.display()));
            } else {
                ck.warn(
                    name,
                    format!(
                        "insecure path: {}",
                        path_warnings.first().unwrap_or(&String::new())
                    ),
                );
            }
        } else {
            ck.warn(
                name,
                format!(
                    "{} not found (will be installed on first use)",
                    helper_path.display()
                ),
            );
        }
    }
}

pub fn check_bind_lib(ck: &mut Checker) -> Option<PathBuf> {
    match super::super::run::find_bind_lib() {
        Ok(path) => {
            ck.ok("bind lib", path.display().to_string());
            Some(path)
        }
        Err(e) => {
            ck.error("bind lib", format!("failed to locate: {e}"));
            None
        }
    }
}

pub fn check_injection(ck: &mut Checker, bind_lib: Option<&Path>) {
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
                ck.info(
                    "injection test",
                    "skipped: no non-SIP binary available for testing",
                );
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
                ck.ok(
                    "injection test",
                    format!("bind library loads successfully via {env_key}"),
                );
            } else if output.status.success() {
                let first_line = stderr.lines().next().unwrap_or("").to_string();
                ck.warn(
                    "injection test",
                    format!("loaded with warnings: {first_line}"),
                );
            } else {
                let first_line = stderr.lines().next().unwrap_or("").to_string();
                ck.error(
                    "injection test",
                    format!("failed to load: exit={}, {first_line}", output.status),
                );
            }
        }
        Err(e) => {
            ck.error(
                "injection test",
                format!("could not run injection test: {e}"),
            );
        }
    }
}
