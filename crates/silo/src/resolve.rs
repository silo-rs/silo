use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

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

pub fn find_git_root(start: &Path) -> Result<PathBuf> {
    let mut current = start
        .canonicalize()
        .map_err(|e| Error::io("failed to resolve path", e))?;
    loop {
        if current.join(".git").exists() {
            return Ok(current);
        }
        if !current.pop() {
            return Err(Error::NotGitRepo);
        }
    }
}

pub fn get_branch_name(git_root: &Path) -> Result<String> {
    let dot_git = git_root.join(".git");
    let head_ref = if dot_git.is_file() {
        let content = std::fs::read_to_string(&dot_git)
            .map_err(|e| Error::io("failed to read .git file", e))?;
        let gitdir = content.strip_prefix("gitdir: ").unwrap_or(&content).trim();
        let gitdir_path = if Path::new(gitdir).is_absolute() {
            PathBuf::from(gitdir)
        } else {
            git_root.join(gitdir)
        };
        let head = gitdir_path.join("HEAD");
        std::fs::read_to_string(&head).map_err(|e| Error::io("failed to read HEAD", e))?
    } else {
        let head = dot_git.join("HEAD");
        std::fs::read_to_string(&head).map_err(|e| Error::io("failed to read HEAD", e))?
    };

    let head_ref = head_ref.trim();
    head_ref.strip_prefix("ref: refs/heads/").map_or_else(
        || Ok(head_ref.chars().take(8).collect()),
        |branch| Ok(branch.to_string()),
    )
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
    use std::process::{Command, Stdio};

    fn make_git_repo(dir: &Path, branch: &str) {
        let git_dir = dir.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(git_dir.join("HEAD"), format!("ref: refs/heads/{branch}\n")).unwrap();
    }

    fn make_detached(dir: &Path, hash: &str) {
        let git_dir = dir.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(git_dir.join("HEAD"), format!("{hash}\n")).unwrap();
    }

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
        let map: std::collections::HashMap<&str, &str> =
            vars.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(map["SILO_IP"], "127.42.0.7");
        assert_eq!(map["SILO_NAME"], "feature-auth");
        assert_eq!(map["SILO_DIR"], "/home/user/project");
        assert_eq!(map["SILO_HOST"], "feature-auth.project.silo");
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

    fn git_init(dir: &Path) {
        Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("git init failed");
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
        git_init(dir.path());
        let root = find_git_root(dir.path()).unwrap();
        assert_eq!(
            root.canonicalize().unwrap(),
            dir.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn find_git_root_from_subdir() {
        let dir = tempfile::tempdir().unwrap();
        git_init(dir.path());
        let sub = dir.path().join("src").join("lib");
        std::fs::create_dir_all(&sub).unwrap();
        let root = find_git_root(&sub).unwrap();
        assert_eq!(
            root.canonicalize().unwrap(),
            dir.path().canonicalize().unwrap()
        );
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

    #[test]
    fn find_git_root_manual_dir() {
        let dir = tempfile::tempdir().unwrap();
        make_git_repo(dir.path(), "main");
        let root = find_git_root(dir.path()).unwrap();
        assert_eq!(
            root.canonicalize().unwrap(),
            dir.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn find_git_root_deeply_nested() {
        let dir = tempfile::tempdir().unwrap();
        make_git_repo(dir.path(), "main");
        let deep = dir.path().join("a").join("b").join("c").join("d").join("e");
        std::fs::create_dir_all(&deep).unwrap();
        let root = find_git_root(&deep).unwrap();
        assert_eq!(
            root.canonicalize().unwrap(),
            dir.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn find_git_root_dot_git_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".git"),
            "gitdir: /tmp/fake/.git/worktrees/wt",
        )
        .unwrap();
        let root = find_git_root(dir.path()).unwrap();
        assert_eq!(
            root.canonicalize().unwrap(),
            dir.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn find_git_root_nonexistent_path() {
        let result = find_git_root(Path::new("/nonexistent/path/surely/missing"));
        assert!(result.is_err());
    }

    #[test]
    fn find_git_root_no_git_anywhere() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("a").join("b");
        std::fs::create_dir_all(&sub).unwrap();
        let _ = find_git_root(&sub);
    }

    #[test]
    fn find_git_root_stops_at_nearest() {
        let dir = tempfile::tempdir().unwrap();
        make_git_repo(dir.path(), "outer");
        let inner = dir.path().join("sub").join("inner");
        make_git_repo(&inner, "inner");
        let deep = inner.join("src");
        std::fs::create_dir_all(&deep).unwrap();

        let root = find_git_root(&deep).unwrap();
        assert_eq!(
            root.canonicalize().unwrap(),
            inner.canonicalize().unwrap(),
            "should find the nearest .git, not the outer one"
        );
    }

    #[test]
    fn branch_name_normal_ref() {
        let dir = tempfile::tempdir().unwrap();
        make_git_repo(dir.path(), "main");
        assert_eq!(get_branch_name(dir.path()).unwrap(), "main");
    }

    #[test]
    fn branch_name_feature_slash() {
        let dir = tempfile::tempdir().unwrap();
        make_git_repo(dir.path(), "feature/auth");
        assert_eq!(get_branch_name(dir.path()).unwrap(), "feature/auth");
    }

    #[test]
    fn branch_name_deeply_nested_ref() {
        let dir = tempfile::tempdir().unwrap();
        make_git_repo(dir.path(), "refs/stash/something");
        assert_eq!(get_branch_name(dir.path()).unwrap(), "refs/stash/something");
    }

    #[test]
    fn branch_name_detached_head() {
        let dir = tempfile::tempdir().unwrap();
        make_detached(dir.path(), "abc123def456789012345678901234567890abcd");
        let name = get_branch_name(dir.path()).unwrap();
        assert_eq!(name, "abc123de", "should take first 8 chars of hash");
    }

    #[test]
    fn branch_name_short_detached_hash() {
        let dir = tempfile::tempdir().unwrap();
        make_detached(dir.path(), "abcd");
        let name = get_branch_name(dir.path()).unwrap();
        assert_eq!(name, "abcd", "should take all chars when hash is short");
    }

    #[test]
    fn branch_name_worktree_absolute() {
        let dir = tempfile::tempdir().unwrap();
        let main_repo = dir.path().join("main");
        let worktree = dir.path().join("wt");

        let wt_gitdir = main_repo.join(".git").join("worktrees").join("wt");
        std::fs::create_dir_all(&wt_gitdir).unwrap();
        std::fs::write(wt_gitdir.join("HEAD"), "ref: refs/heads/feature-x\n").unwrap();

        std::fs::create_dir_all(&worktree).unwrap();
        std::fs::write(
            worktree.join(".git"),
            format!("gitdir: {}", wt_gitdir.display()),
        )
        .unwrap();

        assert_eq!(get_branch_name(&worktree).unwrap(), "feature-x");
    }

    #[test]
    fn branch_name_relative_gitdir() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let sub = repo.join("sub");

        let modules_dir = repo.join(".git").join("modules").join("sub");
        std::fs::create_dir_all(&modules_dir).unwrap();
        std::fs::write(modules_dir.join("HEAD"), "ref: refs/heads/sub-branch\n").unwrap();

        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join(".git"), "gitdir: ../.git/modules/sub").unwrap();

        assert_eq!(get_branch_name(&sub).unwrap(), "sub-branch");
    }

    #[test]
    fn branch_name_no_head_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        assert!(get_branch_name(dir.path()).is_err());
    }

    #[test]
    fn branch_name_no_git_at_all() {
        let dir = tempfile::tempdir().unwrap();
        assert!(get_branch_name(dir.path()).is_err());
    }

    #[test]
    fn branch_name_trailing_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main  \n").unwrap();
        assert_eq!(get_branch_name(dir.path()).unwrap(), "main");
    }

    #[test]
    fn branch_name_crlf() {
        let dir = tempfile::tempdir().unwrap();
        let git_dir = dir.path().join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\r\n").unwrap();
        assert_eq!(get_branch_name(dir.path()).unwrap(), "main");
    }

    #[test]
    fn branch_name_worktree_detached() {
        let dir = tempfile::tempdir().unwrap();
        let main_repo = dir.path().join("main");
        let worktree = dir.path().join("wt");

        let wt_gitdir = main_repo.join(".git").join("worktrees").join("wt");
        std::fs::create_dir_all(&wt_gitdir).unwrap();
        std::fs::write(
            wt_gitdir.join("HEAD"),
            "deadbeefcafe12345678901234567890abcdef01\n",
        )
        .unwrap();

        std::fs::create_dir_all(&worktree).unwrap();
        std::fs::write(
            worktree.join(".git"),
            format!("gitdir: {}", wt_gitdir.display()),
        )
        .unwrap();

        assert_eq!(get_branch_name(&worktree).unwrap(), "deadbeef");
    }

    #[test]
    fn find_git_root_real_git_init() {
        let dir = tempfile::tempdir().unwrap();
        git_init(dir.path());
        let root = find_git_root(dir.path()).unwrap();
        assert_eq!(
            root.canonicalize().unwrap(),
            dir.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn branch_name_real_git_init() {
        let dir = tempfile::tempdir().unwrap();
        git_init(dir.path());
        let name = get_branch_name(dir.path()).unwrap();
        assert!(
            name == "main" || name == "master",
            "expected main or master, got: {name}"
        );
    }
}
