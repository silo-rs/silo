use std::collections::HashMap;
use std::path::Path;

use eyre::Context;
use tracing::{debug, instrument};

/// Scan for `**/*.silo` files under `worktree_path`, substitute `${VAR}` references,
/// and append the resulting KEY=VALUE lines to the corresponding target file
/// (e.g. `.env.silo` appends to `.env`). Creates the target file if it doesn't exist.
/// Returns the number of `.silo` files processed.
#[instrument(skip(env_vars), fields(worktree = %worktree_path.display()))]
pub fn apply_silo_env(
    worktree_path: &Path,
    env_vars: &HashMap<String, String>,
) -> eyre::Result<usize> {
    let pattern = format!("{}/**/*.silo", worktree_path.display());
    let entries = glob::glob(&pattern).context("invalid glob pattern for .silo files")?;

    let mut applied = 0;

    for entry in entries {
        let path = entry.context("glob error while scanning .silo files")?;

        if path.is_dir() {
            continue;
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;

        let target = path.with_extension("");

        let rendered_lines = render_lines(&content, env_vars);
        if rendered_lines.is_empty() {
            continue;
        }

        let mut output = String::new();

        // If target already exists (e.g. copied .env), read it and ensure trailing newline
        if target.exists() {
            let existing = std::fs::read_to_string(&target)
                .with_context(|| format!("failed to read {}", target.display()))?;
            output.push_str(&existing);
            if !output.ends_with('\n') {
                output.push('\n');
            }
        }

        output.push_str(&rendered_lines);

        std::fs::write(&target, &output)
            .with_context(|| format!("failed to write {}", target.display()))?;

        let relative = path
            .strip_prefix(worktree_path)
            .unwrap_or(&path);
        let target_relative = target
            .strip_prefix(worktree_path)
            .unwrap_or(&target);

        debug!(source = %relative.display(), target = %target_relative.display(), "silo env applied");
        eprintln!("  apply {}", target_relative.display());
        applied += 1;
    }

    Ok(applied)
}

/// Parse KEY=VALUE lines (skipping comments and blanks), substitute variables,
/// and return the rendered content as a string.
fn render_lines(content: &str, vars: &HashMap<String, String>) -> String {
    let mut lines = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            let rendered_value = substitute(value, vars);
            lines.push(format!("{}={}", key, rendered_value));
        }
    }
    if lines.is_empty() {
        return String::new();
    }
    let mut result = lines.join("\n");
    result.push('\n');
    result
}

/// Copy files matching `patterns` from `repo_root` into `worktree_path`,
/// preserving relative paths. Skips files that already exist in the target.
#[instrument(skip(patterns), fields(pattern_count = patterns.len(), repo = %repo_root.display(), worktree = %worktree_path.display()))]
pub fn copy_files(
    repo_root: &Path,
    worktree_path: &Path,
    patterns: &[String],
) -> eyre::Result<usize> {
    if patterns.is_empty() {
        debug!("no copy patterns configured");
        return Ok(0);
    }

    let mut copied = 0;

    for pattern in patterns {
        let full_pattern = repo_root.join(pattern);
        let full_pattern_str = full_pattern.to_string_lossy().to_string();

        let entries = glob::glob(&full_pattern_str)
            .with_context(|| format!("invalid glob pattern: {}", pattern))?;

        for entry in entries {
            let source = entry
                .with_context(|| format!("glob error for pattern: {}", pattern))?;

            if source.is_dir() {
                continue;
            }

            let relative = source.strip_prefix(repo_root).with_context(|| {
                format!(
                    "path {} is not under repo root {}",
                    source.display(),
                    repo_root.display()
                )
            })?;

            let target = worktree_path.join(relative);

            if target.exists() {
                debug!(target = %target.display(), "skipping copy (already exists)");
                continue;
            }

            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create directory {}", parent.display())
                })?;
            }

            std::fs::copy(&source, &target).with_context(|| {
                format!(
                    "failed to copy {} -> {}",
                    source.display(),
                    target.display()
                )
            })?;

            debug!(source = %source.display(), target = %target.display(), "file copied");
            eprintln!("  copy {}", relative.display());
            copied += 1;
        }
    }

    Ok(copied)
}

fn substitute(content: &str, vars: &HashMap<String, String>) -> String {
    let mut result = content.to_string();
    for (key, value) in vars {
        result = result.replace(&format!("${{{key}}}"), value);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitute_replaces_known_vars() {
        let vars = HashMap::from([
            ("SILO_NAME".into(), "api".into()),
            ("SILO_IP".into(), "127.0.1.1".into()),
        ]);
        let input = "db_${SILO_NAME} at ${SILO_IP}";
        assert_eq!(substitute(input, &vars), "db_api at 127.0.1.1");
    }

    #[test]
    fn substitute_leaves_unknown_vars() {
        let vars = HashMap::from([("SILO_NAME".into(), "api".into())]);
        let input = "${SILO_NAME} ${UNKNOWN}";
        assert_eq!(substitute(input, &vars), "api ${UNKNOWN}");
    }

    #[test]
    fn substitute_no_vars() {
        let vars = HashMap::new();
        let input = "no variables here";
        assert_eq!(substitute(input, &vars), "no variables here");
    }

    #[test]
    fn render_lines_basic() {
        let vars = HashMap::from([("SILO_NAME".into(), "api".into())]);
        let content = "DB=myapp_${SILO_NAME}\nPORT=3000";
        assert_eq!(render_lines(content, &vars), "DB=myapp_api\nPORT=3000\n");
    }

    #[test]
    fn render_lines_skips_comments_and_blanks() {
        let vars = HashMap::new();
        let content = "# comment\n\nKEY=value\n  # another";
        assert_eq!(render_lines(content, &vars), "KEY=value\n");
    }

    #[test]
    fn render_lines_empty_input() {
        let vars = HashMap::new();
        assert_eq!(render_lines("# only comments\n\n", &vars), "");
    }
}
