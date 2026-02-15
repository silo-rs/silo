use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

use super::Checker;

#[derive(Serialize)]
pub struct WorktreeInfo {
    worktree_count: usize,
    entries: Vec<WorktreeEntry>,
}

#[derive(Serialize)]
struct WorktreeEntry {
    path: String,
    branch: Option<String>,
    ip: Option<String>,
}

pub fn check_git(ck: &mut Checker) {
    match Command::new("git").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            ck.ok("git", version.trim().to_string());
        }
        _ => {
            ck.error("git", "not found in PATH");
        }
    }
}

pub fn check_worktrees(ck: &mut Checker) -> Option<WorktreeInfo> {
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
            ck.warn(
                "worktrees",
                format!("{count} worktree(s), IP collision detected"),
            );
        } else {
            ck.ok("worktrees", format!("{count} worktree(s), all unique IPs"));
        }
    } else {
        ck.info("worktrees", format!("{count} worktree(s)"));
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
