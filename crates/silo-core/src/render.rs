use std::collections::HashMap;
use std::path::Path;

use eyre::Context;
use tracing::{debug, instrument};

#[instrument(skip(env_vars), fields(worktree = %worktree_path.display()))]
pub fn render_templates(
    worktree_path: &Path,
    env_vars: &HashMap<String, String>,
) -> eyre::Result<usize> {
    let pattern = format!("{}/**/*.silo", worktree_path.display());
    let entries = glob::glob(&pattern).context("invalid glob pattern for .silo templates")?;

    let mut rendered = 0;

    for entry in entries {
        let source = entry.context("glob error while scanning .silo templates")?;

        if source.is_dir() {
            continue;
        }

        let target = source.with_extension("");

        if target.exists() {
            debug!(target = %target.display(), "skipping (already exists)");
            continue;
        }

        let content = std::fs::read_to_string(&source)
            .with_context(|| format!("failed to read {}", source.display()))?;

        let rendered_content = substitute(&content, env_vars);

        std::fs::write(&target, &rendered_content)
            .with_context(|| format!("failed to write {}", target.display()))?;

        let relative = source
            .strip_prefix(worktree_path)
            .unwrap_or(&source);
        let target_relative = target
            .strip_prefix(worktree_path)
            .unwrap_or(&target);

        debug!(source = %relative.display(), target = %target_relative.display(), "template rendered");
        eprintln!("  render {}", target_relative.display());
        rendered += 1;
    }

    Ok(rendered)
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
}
