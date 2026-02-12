use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use eyre::Context;
use tracing::debug;

use crate::error::SiloError;

pub struct SiloContext {
    pub name: String,
    pub ip: Ipv4Addr,
    pub dir: PathBuf,
    pub hostname: String,
}

impl SiloContext {
    pub fn env_vars(&self) -> HashMap<String, String> {
        HashMap::from([
            ("SILO_IP".into(), self.ip.to_string()),
            ("SILO_NAME".into(), self.name.clone()),
            ("SILO_DIR".into(), self.dir.display().to_string()),
            ("SILO_HOST".into(), self.hostname.clone()),
        ])
    }
}

pub fn resolve(cwd: &Path, name_override: Option<&str>) -> eyre::Result<SiloContext> {
    let git_root = find_git_root(cwd)?;
    let canonical = git_root.canonicalize().unwrap_or_else(|_| git_root.clone());

    let name = match name_override {
        Some(n) => n.to_string(),
        None => {
            let branch = get_branch_name(&git_root)?;
            sanitize_name(&branch)
        }
    };

    let ip = compute_ip(&canonical);

    let repo_dir = git_root
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let hostname = format!("{}.{}.silo", name, repo_dir);

    debug!(%ip, %name, %hostname, dir = %git_root.display(), "resolved silo context");

    Ok(SiloContext {
        name,
        ip,
        dir: git_root,
        hostname,
    })
}

pub fn find_git_root(start: &Path) -> Result<PathBuf, SiloError> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join(".git");
        if candidate.exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err(SiloError::NotGitRepo);
        }
    }
}

pub fn get_branch_name(git_root: &Path) -> eyre::Result<String> {
    let output = Command::new("git")
        .args(["branch", "--show-current"])
        .current_dir(git_root)
        .output()
        .context("failed to run git")?;

    if output.status.success() {
        let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !branch.is_empty() {
            return Ok(branch);
        }
    }

    let head_path = git_root.join(".git");
    let head_ref = if head_path.is_file() {
        // Git worktree: .git is a file like "gitdir: /path/to/.git/worktrees/name"
        let content = std::fs::read_to_string(&head_path).context("failed to read .git file")?;
        let gitdir = content.strip_prefix("gitdir: ").unwrap_or(&content).trim();
        let head = Path::new(gitdir).join("HEAD");
        std::fs::read_to_string(&head).context("failed to read HEAD")?
    } else {
        let head = head_path.join("HEAD");
        std::fs::read_to_string(&head).context("failed to read HEAD")?
    };

    let head_ref = head_ref.trim();
    if let Some(branch) = head_ref.strip_prefix("ref: refs/heads/") {
        Ok(branch.to_string())
    } else {
        // Detached HEAD — use short hash
        Ok(head_ref.chars().take(8).collect())
    }
}

pub fn sanitize_name(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn compute_ip(canonical_path: &Path) -> Ipv4Addr {
    let bytes = canonical_path.as_os_str().as_encoded_bytes();
    let hash = fnv1a_hash(bytes);

    // Map to 127.1.{hi}.{lo}, avoiding .0.0 and .255.255
    let raw = (hash % 65534) + 1; // 1..=65534
    let hi = ((raw >> 8) & 0xFF) as u8;
    let lo = (raw & 0xFF) as u8;

    Ipv4Addr::new(127, 1, hi, lo)
}

fn fnv1a_hash(bytes: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_basic() {
        assert_eq!(sanitize_name("feature/auth"), "feature-auth");
        assert_eq!(sanitize_name("main"), "main");
        assert_eq!(sanitize_name("my_branch"), "my_branch");
    }

    #[test]
    fn sanitize_collapses_dashes() {
        assert_eq!(sanitize_name("a//b"), "a-b");
        assert_eq!(sanitize_name("a---b"), "a-b");
    }

    #[test]
    fn sanitize_strips_leading_trailing() {
        assert_eq!(sanitize_name("/feature/"), "feature");
        assert_eq!(sanitize_name("--main--"), "main");
    }

    #[test]
    fn sanitize_dots_and_special() {
        assert_eq!(sanitize_name("release/v1.0.0"), "release-v1-0-0");
        assert_eq!(sanitize_name("feat@thing"), "feat-thing");
    }

    #[test]
    fn compute_ip_deterministic() {
        let path = Path::new("/home/user/project");
        let ip1 = compute_ip(path);
        let ip2 = compute_ip(path);
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn compute_ip_different_paths() {
        let ip1 = compute_ip(Path::new("/home/user/project-a"));
        let ip2 = compute_ip(Path::new("/home/user/project-b"));
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn compute_ip_in_range() {
        let ip = compute_ip(Path::new("/some/path"));
        assert_eq!(ip.octets()[0], 127);
        assert_eq!(ip.octets()[1], 1);
    }

    #[test]
    fn compute_ip_not_zero() {
        // Should never produce 127.1.0.0
        for i in 0..1000 {
            let path = format!("/test/path/{}", i);
            let ip = compute_ip(Path::new(&path));
            assert!(ip != Ipv4Addr::new(127, 1, 0, 0));
        }
    }

    #[test]
    fn env_vars_complete() {
        let ctx = SiloContext {
            name: "feature-auth".into(),
            ip: Ipv4Addr::new(127, 1, 0, 42),
            dir: PathBuf::from("/home/user/project"),
            hostname: "feature-auth.project.silo".into(),
        };
        let vars = ctx.env_vars();
        assert_eq!(vars.len(), 4);
        assert_eq!(vars["SILO_IP"], "127.1.0.42");
        assert_eq!(vars["SILO_NAME"], "feature-auth");
        assert_eq!(vars["SILO_DIR"], "/home/user/project");
        assert_eq!(vars["SILO_HOST"], "feature-auth.project.silo");
    }

    #[test]
    fn find_git_root_not_git() {
        let dir = tempfile::tempdir().unwrap();
        let err = find_git_root(dir.path());
        assert!(err.is_err());
    }

    #[test]
    fn find_git_root_at_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        let root = find_git_root(dir.path()).unwrap();
        assert_eq!(root, dir.path());
    }

    #[test]
    fn find_git_root_from_subdir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        let sub = dir.path().join("src").join("lib");
        std::fs::create_dir_all(&sub).unwrap();
        let root = find_git_root(&sub).unwrap();
        assert_eq!(root, dir.path());
    }
}
