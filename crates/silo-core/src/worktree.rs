use std::path::{Path, PathBuf};
use std::process::Command;

use eyre::Context;
use tracing::{debug, info, instrument, warn};

pub fn prune_stale(repo_root: &Path) -> eyre::Result<()> {
    debug!(repo = %repo_root.display(), "pruning stale worktrees");
    let status = Command::new("git")
        .args(["worktree", "prune"])
        .current_dir(repo_root)
        .status()
        .context("failed to run git worktree prune")?;

    if !status.success() {
        warn!("git worktree prune exited with non-zero status");
    }
    Ok(())
}

pub fn delete_branch(repo_root: &Path, branch: &str) -> eyre::Result<()> {
    debug!(branch, "deleting branch");
    let status = Command::new("git")
        .args(["branch", "-D", branch])
        .current_dir(repo_root)
        .status()
        .context("failed to run git branch -D")?;

    if !status.success() {
        warn!(branch, "failed to delete branch (may not exist)");
    }
    Ok(())
}

#[instrument(skip(repo_root), fields(repo = %repo_root.display()))]
pub fn create_worktree(
    repo_root: &Path,
    instance_name: &str,
    base_dir: &str,
    branch: Option<&str>,
) -> eyre::Result<PathBuf> {
    let worktree_path = repo_root.join(base_dir).join(instance_name);
    let branch_name = branch.unwrap_or(instance_name);

    prune_stale(repo_root)?;

    debug!(branch = branch_name, path = %worktree_path.display(), "creating worktree with new branch");

    let status = Command::new("git")
        .args(["worktree", "add", "-b", branch_name])
        .arg(&worktree_path)
        .current_dir(repo_root)
        .status()
        .context("failed to run git worktree add")?;

    if !status.success() {
        debug!(branch = branch_name, "branch already exists, retrying without -b");
        let status = Command::new("git")
            .args(["worktree", "add"])
            .arg(&worktree_path)
            .arg(branch_name)
            .current_dir(repo_root)
            .status()
            .context("failed to run git worktree add")?;

        if !status.success() {
            eyre::bail!(
                "failed to create git worktree at {}",
                worktree_path.display()
            );
        }
    }

    let worktree_path = worktree_path
        .canonicalize()
        .unwrap_or(worktree_path);

    info!(path = %worktree_path.display(), "worktree created");
    Ok(worktree_path)
}

#[instrument(fields(repo = %repo_root.display(), path = %worktree_path.display()))]
pub fn remove_worktree(repo_root: &Path, worktree_path: &Path) -> eyre::Result<()> {
    let status = Command::new("git")
        .args(["worktree", "remove", "--force"])
        .arg(worktree_path)
        .current_dir(repo_root)
        .status()
        .context("failed to run git worktree remove")?;

    if !status.success() {
        eyre::bail!(
            "failed to remove git worktree at {}",
            worktree_path.display()
        );
    }

    Ok(())
}
