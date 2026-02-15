use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::debug;

use crate::context::Context;
use crate::error::{Error, Result};

pub fn resolve(
    cwd: &Path,
    name_override: Option<&str>,
    ip_override: Option<Ipv4Addr>,
) -> Result<Context> {
    let git_root = find_git_root(cwd)?;
    let canonical = git_root.canonicalize().unwrap_or_else(|_| git_root.clone());

    let name = match name_override {
        Some(n) => sanitize_name(n),
        None => {
            let branch = get_branch_name(&git_root)?;
            sanitize_name(&branch)
        }
    };

    let ip = match ip_override {
        Some(ip) => {
            if ip.octets()[0] != 127 {
                return Err(Error::InvalidIpOverride(ip));
            }
            ip
        }
        None => compute_ip(&canonical, &name),
    };

    let project_name = sanitize_name(&main_repo_name(&git_root));
    let hostname = format!("{}.{}.silo", name, project_name);

    debug!(%ip, %name, %hostname, dir = %git_root.display(), "resolved silo context");

    Ok(Context {
        name,
        ip,
        dir: git_root,
        hostname,
    })
}

pub(crate) fn find_git_root(start: &Path) -> std::result::Result<PathBuf, Error> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join(".git");
        if candidate.exists() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err(Error::NotGitRepo);
        }
    }
}

pub(crate) fn get_branch_name(git_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["branch", "--show-current"])
        .current_dir(git_root)
        .output()
        .map_err(|e| Error::io("failed to run git", e))?;

    if output.status.success() {
        let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !branch.is_empty() {
            return Ok(branch);
        }
    }

    let head_path = git_root.join(".git");
    let head_ref = if head_path.is_file() {
        let content = std::fs::read_to_string(&head_path)
            .map_err(|e| Error::io("failed to read .git file", e))?;
        let gitdir = content.strip_prefix("gitdir: ").unwrap_or(&content).trim();
        let head = Path::new(gitdir).join("HEAD");
        std::fs::read_to_string(&head).map_err(|e| Error::io("failed to read HEAD", e))?
    } else {
        let head = head_path.join("HEAD");
        std::fs::read_to_string(&head).map_err(|e| Error::io("failed to read HEAD", e))?
    };

    let head_ref = head_ref.trim();
    if let Some(branch) = head_ref.strip_prefix("ref: refs/heads/") {
        Ok(branch.to_string())
    } else {
        Ok(head_ref.chars().take(8).collect())
    }
}

pub fn sanitize_name(raw: &str) -> String {
    let ascii_part: String = raw
        .chars()
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
        .join("-");

    if !raw.is_ascii() || (!raw.is_empty() && ascii_part.is_empty()) {
        let mut hash = FNV_OFFSET;
        for &b in raw.as_bytes() {
            hash ^= b as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        let suffix = format!("{:08x}", hash as u32);
        if ascii_part.is_empty() {
            suffix
        } else {
            format!("{ascii_part}-{suffix}")
        }
    } else {
        ascii_part
    }
}

fn main_repo_name(git_root: &Path) -> String {
    let dot_git = git_root.join(".git");
    if dot_git.is_file()
        && let Ok(content) = std::fs::read_to_string(&dot_git)
        && let Some(gitdir) = content.strip_prefix("gitdir: ")
    {
        let gitdir = gitdir.trim();
        if let Some(name) = Path::new(gitdir)
            .ancestors()
            .find(|p| p.ends_with(".git"))
            .and_then(|p| p.parent())
            .and_then(|p| p.file_name())
        {
            return name.to_string_lossy().into_owned();
        }
    }
    git_root
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

pub fn compute_ip(canonical_path: &Path, name: &str) -> Ipv4Addr {
    let mut hash = FNV_OFFSET;
    hash ^= IP_VERSION as u64;
    hash = hash.wrapping_mul(FNV_PRIME);
    for &byte in canonical_path.as_os_str().as_encoded_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash ^= 0xff_u64;
    hash = hash.wrapping_mul(FNV_PRIME);
    for &byte in name.as_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    const OCTET1_RANGE: u64 = 254;
    const OCTET2_RANGE: u64 = 256;
    const OCTET3_RANGE: u64 = 254;
    const SPACE: u64 = OCTET1_RANGE * OCTET2_RANGE * OCTET3_RANGE;

    let raw = hash % SPACE;
    let o1 = (raw / (OCTET2_RANGE * OCTET3_RANGE)) as u8 + 1;
    let o2 = ((raw / OCTET3_RANGE) % OCTET2_RANGE) as u8;
    let o3 = (raw % OCTET3_RANGE) as u8 + 1;

    Ipv4Addr::new(127, o1, o2, o3)
}

const IP_VERSION: u8 = 1;

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

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
        let ip1 = compute_ip(path, "main");
        let ip2 = compute_ip(path, "main");
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn compute_ip_different_paths() {
        let ip1 = compute_ip(Path::new("/home/user/project-a"), "main");
        let ip2 = compute_ip(Path::new("/home/user/project-b"), "main");
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn compute_ip_different_names() {
        let path = Path::new("/home/user/project");
        let ip1 = compute_ip(path, "main");
        let ip2 = compute_ip(path, "feature");
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn compute_ip_in_range() {
        for i in 0..1000 {
            let path = format!("/test/path/{}", i);
            let ip = compute_ip(Path::new(&path), "main");
            let [o0, o1, _o2, o3] = ip.octets();
            assert_eq!(o0, 127);
            assert!((1..=254).contains(&o1), "second octet {o1} out of range");
            assert!((1..=254).contains(&o3), "fourth octet {o3} out of range");
        }
    }

    #[test]
    fn env_vars_complete() {
        let ctx = Context {
            name: "feature-auth".into(),
            ip: Ipv4Addr::new(127, 42, 0, 7),
            dir: PathBuf::from("/home/user/project"),
            hostname: "feature-auth.project.silo".into(),
        };
        let vars = ctx.env_vars();
        assert_eq!(vars.len(), 4);
        assert_eq!(vars["SILO_IP"], "127.42.0.7");
        assert_eq!(vars["SILO_NAME"], "feature-auth");
        assert_eq!(vars["SILO_DIR"], "/home/user/project");
        assert_eq!(vars["SILO_HOST"], "feature-auth.project.silo");
    }

    #[test]
    fn compute_ip_golden() {
        assert_eq!(
            compute_ip(Path::new("/home/user/project"), "main"),
            Ipv4Addr::new(127, 120, 134, 3),
        );
        assert_eq!(
            compute_ip(Path::new("/home/user/project"), "feature-auth"),
            Ipv4Addr::new(127, 185, 176, 25),
        );
        assert_eq!(
            compute_ip(Path::new("/tmp/myapp"), "develop"),
            Ipv4Addr::new(127, 139, 94, 75),
        );
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

    #[test]
    fn compute_ip_never_localhost() {
        for i in 0..10_000 {
            let path = format!("/test/project/{i}");
            let ip = compute_ip(Path::new(&path), &format!("branch-{i}"));
            assert_ne!(
                ip,
                Ipv4Addr::new(127, 0, 0, 1),
                "generated localhost for {path}"
            );
        }
    }

    #[test]
    fn compute_ip_never_zero_octets() {
        for i in 0..10_000 {
            let path = format!("/proj/{i}");
            let ip = compute_ip(Path::new(&path), &format!("b{i}"));
            let [_, o1, _, o3] = ip.octets();
            assert_ne!(o1, 0, "second octet is 0 for {path}");
            assert_ne!(o3, 0, "fourth octet is 0 for {path}");
        }
    }

    #[test]
    fn sanitize_name_empty() {
        assert_eq!(sanitize_name(""), "");
    }

    #[test]
    fn sanitize_name_all_special() {
        assert!(!sanitize_name("///...///").is_empty());
        assert_ne!(sanitize_name("///"), sanitize_name("..."));
        assert_ne!(sanitize_name("@@@"), sanitize_name("+++"));
    }

    #[test]
    fn sanitize_name_unicode() {
        let result = sanitize_name("기능/인증");
        assert!(!result.is_empty());
        assert!(!result.contains('/'));
        assert!(!result.contains("--"));
        assert_ne!(sanitize_name("기능/인증"), sanitize_name("기능/로그인"));
        assert_ne!(sanitize_name("기능/인증"), sanitize_name("버그/수정"));
    }

    #[test]
    fn sanitize_name_mixed_unicode_ascii() {
        let result = sanitize_name("feature/인증");
        assert!(result.starts_with("feature-"));
        assert_ne!(result, "feature");
        assert_ne!(
            sanitize_name("feature/인증"),
            sanitize_name("feature/로그인")
        );
    }

    #[test]
    fn sanitize_name_unicode_languages() {
        let names = [
            "기능/인증",
            "機能/認証",
            "フィーチャー/認証",
            "功能/认证",
            "功能/認證",
            "фича/авторизация",
            "функція/авторизація",
            "özellik/kimlik",
            "tính-năng/xác-thực",
            "ميزة/مصادقة",
            "תכונה/אימות",
            "ฟีเจอร์/ยืนยัน",
            "सुविधा/प्रमाणीकरण",
        ];
        let sanitized: Vec<String> = names.iter().map(|n| sanitize_name(n)).collect();
        for (name, result) in names.iter().zip(&sanitized) {
            assert!(!result.is_empty(), "{name} sanitized to empty");
        }
        let unique: std::collections::HashSet<&String> = sanitized.iter().collect();
        assert_eq!(
            unique.len(),
            sanitized.len(),
            "collision among: {:?}",
            sanitized
        );
    }

    #[test]
    fn compute_ip_collision_rate() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        let n = 10_000;
        for i in 0..n {
            let path = format!("/users/dev/project-{}", i / 100);
            let ip = compute_ip(Path::new(&path), &format!("branch-{i}"));
            seen.insert(ip);
        }
        let collisions = n - seen.len();
        let expected_max = n * n / (2 * 16_516_096) + 50;
        assert!(
            collisions <= expected_max,
            "too many collisions: {collisions} (expected at most ~{expected_max})"
        );
    }
}
