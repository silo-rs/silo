use std::path::Path;
use std::process::Command;

use serde::Serialize;

use super::Checker;

#[derive(Serialize)]
pub struct ShellInfo {
    current_shell: Option<String>,
    current_shell_name: Option<String>,
    default_shell: Option<String>,
    #[cfg(target_os = "macos")]
    sip_protected: bool,
    #[cfg(target_os = "macos")]
    non_sip_alternative: Option<String>,
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

pub fn check_shell(ck: &mut Checker) -> Option<ShellInfo> {
    let (shell_path, shell_name) = match detect_parent_shell() {
        Some(s) => s,
        None => {
            ck.info("shell", "could not detect parent shell");
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
                ck.warn(
                    "shell",
                    format!("{shell_path} is SIP-protected; non-SIP alternative: {alt_path}"),
                );
            } else {
                ck.warn(
                    "shell",
                    format!(
                        "{shell_path} is SIP-protected — install via Homebrew: brew install {shell_name}"
                    ),
                );
            }
            (true, alt)
        } else {
            ck.ok("shell", format!("{shell_path} ({shell_name})"));
            (false, None)
        }
    };

    #[cfg(not(target_os = "macos"))]
    ck.ok("shell", format!("{shell_path} ({shell_name})"));

    if let Some(ref default) = default_shell {
        if default != &shell_path {
            ck.info("default shell", default.clone());
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
