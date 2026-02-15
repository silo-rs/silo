use std::path::{Path, PathBuf};

use crate::error::ResolveError;

pub fn find_git_root(start: &Path) -> Result<PathBuf, ResolveError> {
    let mut current = start
        .canonicalize()
        .map_err(|e| ResolveError::io("failed to resolve path", e))?;
    loop {
        if current.join(".git").exists() {
            return Ok(current);
        }
        if !current.pop() {
            return Err(ResolveError::NotGitRepo);
        }
    }
}

pub(super) fn get_branch_name(git_root: &Path) -> Result<String, ResolveError> {
    let dot_git = git_root.join(".git");
    let head_ref = if dot_git.is_file() {
        let content = std::fs::read_to_string(&dot_git)
            .map_err(|e| ResolveError::io("failed to read .git file", e))?;
        let gitdir = content.strip_prefix("gitdir: ").unwrap_or(&content).trim();
        let gitdir_path = if Path::new(gitdir).is_absolute() {
            PathBuf::from(gitdir)
        } else {
            git_root.join(gitdir)
        };
        let head = gitdir_path.join("HEAD");
        std::fs::read_to_string(&head).map_err(|e| ResolveError::io("failed to read HEAD", e))?
    } else {
        let head = dot_git.join("HEAD");
        std::fs::read_to_string(&head).map_err(|e| ResolveError::io("failed to read HEAD", e))?
    };

    let head_ref = head_ref.trim();
    head_ref.strip_prefix("ref: refs/heads/").map_or_else(
        || Ok(head_ref.chars().take(8).collect()),
        |branch| Ok(branch.to_string()),
    )
}

pub(super) fn main_repo_name(git_root: &Path) -> String {
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
