use std::collections::HashMap;
use std::path::Path;

use tracing::{debug, instrument};

use crate::error::{Error, Result};

/// Scan for `**/*.silo` files under `root_path`, substitute `${VAR}` references,
/// and merge the resulting KEY=VALUE lines into the corresponding target file
/// (e.g. `.env.silo` → `.env`). If a key already exists in the target, its value
/// is replaced in-place. New keys are appended. Creates the target if it doesn't exist.
/// Returns the number of `.silo` files processed.
#[instrument(skip(env_vars), fields(dir = %root_path.display()))]
pub fn apply_silo_env(root_path: &Path, env_vars: &HashMap<String, String>) -> Result<usize> {
    let pattern = format!("{}/**/*.silo", root_path.display());
    let entries = glob::glob(&pattern)?;

    let mut applied = 0;

    for entry in entries {
        let path = entry?;

        if path.is_dir() {
            continue;
        }

        let content = std::fs::read_to_string(&path)
            .map_err(|e| Error::io(format!("failed to read {}", path.display()), e))?;

        let target = path.with_extension("");

        let overrides = parse_overrides(&content, env_vars);
        if overrides.is_empty() {
            continue;
        }

        let output = if target.exists() {
            let existing = std::fs::read_to_string(&target)
                .map_err(|e| Error::io(format!("failed to read {}", target.display()), e))?;
            merge_env(&existing, &overrides)
        } else {
            let mut out = String::new();
            for (key, value) in &overrides {
                out.push_str(&format!("{key}={value}\n"));
            }
            out
        };

        std::fs::write(&target, &output)
            .map_err(|e| Error::io(format!("failed to write {}", target.display()), e))?;

        let relative = path.strip_prefix(root_path).unwrap_or(&path);
        let target_relative = target.strip_prefix(root_path).unwrap_or(&target);

        debug!(source = %relative.display(), target = %target_relative.display(), "silo env applied");
        eprintln!("  apply {}", target_relative.display());
        applied += 1;
    }

    Ok(applied)
}

/// Parse KEY=VALUE lines (skipping comments and blanks), substitute variables,
/// and return as ordered (key, value) pairs.
///
/// Handles common `.env` conventions:
/// - `export VAR=value` — `export` prefix is stripped
/// - `VAR="hello world"` — surrounding double/single quotes are stripped
/// - Duplicate keys — last occurrence wins
fn parse_overrides(content: &str, vars: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim().to_string();
            let value = strip_quotes(value.trim());
            let value = substitute(&value, vars);

            // Last-write-wins: remove earlier duplicate if present
            if let Some(pos) = pairs.iter().position(|(k, _)| k == &key) {
                pairs.remove(pos);
            }
            pairs.push((key, value));
        }
    }
    pairs
}

/// Strip matching surrounding quotes (double or single) from a value.
fn strip_quotes(value: &str) -> String {
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

/// Merge overrides into existing env content. If a key already exists, replace
/// that line in-place (preserving `export` prefix if present). Otherwise append
/// at the end.
fn merge_env(existing: &str, overrides: &[(String, String)]) -> String {
    let mut lines: Vec<String> = existing.lines().map(String::from).collect();
    let mut appended = Vec::new();

    for (key, value) in overrides {
        let prefix_plain = format!("{key}=");
        let prefix_export = format!("export {key}=");
        let mut replaced = false;
        for line in &mut lines {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                continue;
            }
            if trimmed.starts_with(&prefix_export) {
                *line = format!("export {key}={value}");
                replaced = true;
                break;
            }
            if trimmed.starts_with(&prefix_plain) {
                *line = format!("{key}={value}");
                replaced = true;
                break;
            }
        }
        if !replaced {
            appended.push(format!("{key}={value}"));
        }
    }

    lines.extend(appended);

    let mut result = lines.join("\n");
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result
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
    fn parse_overrides_basic() {
        let vars = HashMap::from([("SILO_NAME".into(), "api".into())]);
        let content = "DB=myapp_${SILO_NAME}\nPORT=3000";
        let pairs = parse_overrides(content, &vars);
        assert_eq!(
            pairs,
            vec![
                ("DB".into(), "myapp_api".into()),
                ("PORT".into(), "3000".into()),
            ]
        );
    }

    #[test]
    fn parse_overrides_skips_comments_and_blanks() {
        let vars = HashMap::new();
        let content = "# comment\n\nKEY=value\n  # another";
        let pairs = parse_overrides(content, &vars);
        assert_eq!(pairs, vec![("KEY".into(), "value".into())]);
    }

    #[test]
    fn parse_overrides_empty_input() {
        let vars = HashMap::new();
        assert!(parse_overrides("# only comments\n\n", &vars).is_empty());
    }

    #[test]
    fn merge_env_replaces_existing_key() {
        let existing = "SECRET=abc\nDATABASE_URL=old\nPORT=3000\n";
        let overrides = vec![("DATABASE_URL".into(), "new".into())];
        let result = merge_env(existing, &overrides);
        assert_eq!(result, "SECRET=abc\nDATABASE_URL=new\nPORT=3000\n");
    }

    #[test]
    fn merge_env_appends_new_key() {
        let existing = "SECRET=abc\n";
        let overrides = vec![("NEW_KEY".into(), "value".into())];
        let result = merge_env(existing, &overrides);
        assert_eq!(result, "SECRET=abc\nNEW_KEY=value\n");
    }

    #[test]
    fn merge_env_mixed_replace_and_append() {
        let existing = "A=1\nB=2\nC=3\n";
        let overrides = vec![("B".into(), "replaced".into()), ("D".into(), "new".into())];
        let result = merge_env(existing, &overrides);
        assert_eq!(result, "A=1\nB=replaced\nC=3\nD=new\n");
    }

    #[test]
    fn merge_env_preserves_comments() {
        let existing = "# database\nDB=old\n# cache\nREDIS=localhost\n";
        let overrides = vec![("DB".into(), "new".into())];
        let result = merge_env(existing, &overrides);
        assert_eq!(result, "# database\nDB=new\n# cache\nREDIS=localhost\n");
    }

    #[test]
    fn parse_overrides_strips_export_prefix() {
        let vars = HashMap::new();
        let content = "export DB=mydb\nexport PORT=3000\nHOST=localhost";
        let pairs = parse_overrides(content, &vars);
        assert_eq!(
            pairs,
            vec![
                ("DB".into(), "mydb".into()),
                ("PORT".into(), "3000".into()),
                ("HOST".into(), "localhost".into()),
            ]
        );
    }

    #[test]
    fn merge_env_matches_export_prefix_in_existing() {
        let existing = "export DB=old\nexport PORT=3000\n";
        let overrides = vec![("DB".into(), "new".into())];
        let result = merge_env(existing, &overrides);
        assert_eq!(result, "export DB=new\nexport PORT=3000\n");
    }

    #[test]
    fn parse_overrides_strips_double_quotes() {
        let vars = HashMap::new();
        let content = "MSG=\"hello world\"";
        let pairs = parse_overrides(content, &vars);
        assert_eq!(pairs, vec![("MSG".into(), "hello world".into())]);
    }

    #[test]
    fn parse_overrides_strips_single_quotes() {
        let vars = HashMap::new();
        let content = "MSG='hello world'";
        let pairs = parse_overrides(content, &vars);
        assert_eq!(pairs, vec![("MSG".into(), "hello world".into())]);
    }

    #[test]
    fn parse_overrides_preserves_inner_quotes() {
        let vars = HashMap::new();
        let content = "MSG=\"it's a 'test'\"";
        let pairs = parse_overrides(content, &vars);
        assert_eq!(pairs, vec![("MSG".into(), "it's a 'test'".into())]);
    }

    #[test]
    fn parse_overrides_unmatched_quote_preserved() {
        let vars = HashMap::new();
        let content = "MSG=\"hello";
        let pairs = parse_overrides(content, &vars);
        assert_eq!(pairs, vec![("MSG".into(), "\"hello".into())]);
    }

    #[test]
    fn parse_overrides_empty_quoted_value() {
        let vars = HashMap::new();
        let content = "EMPTY=\"\"";
        let pairs = parse_overrides(content, &vars);
        assert_eq!(pairs, vec![("EMPTY".into(), "".into())]);
    }

    #[test]
    fn parse_overrides_duplicate_key_last_wins() {
        let vars = HashMap::new();
        let content = "KEY=first\nKEY=second\nKEY=third";
        let pairs = parse_overrides(content, &vars);
        assert_eq!(pairs, vec![("KEY".into(), "third".into())]);
    }

    #[test]
    fn parse_overrides_duplicate_mixed_with_export() {
        let vars = HashMap::new();
        let content = "export DB=old\nDB=new";
        let pairs = parse_overrides(content, &vars);
        assert_eq!(pairs, vec![("DB".into(), "new".into())]);
    }

    #[test]
    fn strip_quotes_no_quotes() {
        assert_eq!(strip_quotes("hello"), "hello");
    }

    #[test]
    fn strip_quotes_double() {
        assert_eq!(strip_quotes("\"hello world\""), "hello world");
    }

    #[test]
    fn strip_quotes_single() {
        assert_eq!(strip_quotes("'hello world'"), "hello world");
    }

    #[test]
    fn strip_quotes_mismatched() {
        assert_eq!(strip_quotes("\"hello'"), "\"hello'");
    }

    #[test]
    fn strip_quotes_single_char() {
        assert_eq!(strip_quotes("\""), "\"");
    }

    #[test]
    fn strip_quotes_empty() {
        assert_eq!(strip_quotes(""), "");
    }

    #[test]
    fn parse_overrides_export_with_quotes_and_substitution() {
        let vars = HashMap::from([("SILO_NAME".into(), "api".into())]);
        let content = "export DATABASE_URL=\"postgres://localhost/${SILO_NAME}\"";
        let pairs = parse_overrides(content, &vars);
        assert_eq!(
            pairs,
            vec![("DATABASE_URL".into(), "postgres://localhost/api".into())]
        );
    }

    fn test_vars() -> HashMap<String, String> {
        HashMap::from([
            ("SILO_NAME".into(), "feature-a".into()),
            ("SILO_IP".into(), "127.1.0.42".into()),
            ("SILO_DIR".into(), "/work/feature-a".into()),
            ("SILO_HOST".into(), "feature-a.project.silo".into()),
        ])
    }

    #[test]
    fn apply_creates_env_from_silo() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env.silo"),
            "DATABASE_URL=postgres://localhost/myapp_${SILO_NAME}\nHOST=${SILO_IP}\n",
        )
        .unwrap();

        let count = apply_silo_env(dir.path(), &test_vars()).unwrap();
        assert_eq!(count, 1);

        let output = std::fs::read_to_string(dir.path().join(".env")).unwrap();
        assert_eq!(
            output,
            "DATABASE_URL=postgres://localhost/myapp_feature-a\nHOST=127.1.0.42\n"
        );
    }

    #[test]
    fn apply_appends_new_keys_to_existing_env() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "SECRET_KEY=abc123\nSTRIPE_KEY=sk_test_xxx\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".env.silo"),
            "DATABASE_URL=postgres://localhost/myapp_${SILO_NAME}",
        )
        .unwrap();

        let count = apply_silo_env(dir.path(), &test_vars()).unwrap();
        assert_eq!(count, 1);

        let output = std::fs::read_to_string(dir.path().join(".env")).unwrap();
        assert_eq!(
            output,
            "SECRET_KEY=abc123\nSTRIPE_KEY=sk_test_xxx\nDATABASE_URL=postgres://localhost/myapp_feature-a\n"
        );
    }

    #[test]
    fn apply_replaces_existing_keys() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "SECRET_KEY=abc123\nDATABASE_URL=postgres://localhost/myapp\nSTRIPE_KEY=sk_test_xxx\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".env.silo"),
            "DATABASE_URL=postgres://localhost/myapp_${SILO_NAME}",
        )
        .unwrap();

        let count = apply_silo_env(dir.path(), &test_vars()).unwrap();
        assert_eq!(count, 1);

        let output = std::fs::read_to_string(dir.path().join(".env")).unwrap();
        assert_eq!(
            output,
            "SECRET_KEY=abc123\nDATABASE_URL=postgres://localhost/myapp_feature-a\nSTRIPE_KEY=sk_test_xxx\n"
        );
    }

    #[test]
    fn apply_skips_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env.silo"),
            "# this is a comment\n\nKEY=value\n  # another comment\n",
        )
        .unwrap();

        let count = apply_silo_env(dir.path(), &test_vars()).unwrap();
        assert_eq!(count, 1);

        let output = std::fs::read_to_string(dir.path().join(".env")).unwrap();
        assert_eq!(output, "KEY=value\n");
    }

    #[test]
    fn apply_nested_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let api_dir = dir.path().join("packages/api");
        let web_dir = dir.path().join("packages/web");
        std::fs::create_dir_all(&api_dir).unwrap();
        std::fs::create_dir_all(&web_dir).unwrap();

        std::fs::write(api_dir.join(".env.silo"), "DB=api_${SILO_NAME}").unwrap();
        std::fs::write(web_dir.join(".env.silo"), "DB=web_${SILO_NAME}").unwrap();

        let count = apply_silo_env(dir.path(), &test_vars()).unwrap();
        assert_eq!(count, 2);

        assert_eq!(
            std::fs::read_to_string(api_dir.join(".env")).unwrap(),
            "DB=api_feature-a\n"
        );
        assert_eq!(
            std::fs::read_to_string(web_dir.join(".env")).unwrap(),
            "DB=web_feature-a\n"
        );
    }

    #[test]
    fn apply_no_silo_files() {
        let dir = tempfile::tempdir().unwrap();
        let count = apply_silo_env(dir.path(), &test_vars()).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn apply_preserves_equals_in_value() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env.silo"),
            "DATABASE_URL=postgres://user:pass@host/db?sslmode=require",
        )
        .unwrap();

        apply_silo_env(dir.path(), &test_vars()).unwrap();

        let output = std::fs::read_to_string(dir.path().join(".env")).unwrap();
        assert!(output.contains("DATABASE_URL=postgres://user:pass@host/db?sslmode=require"));
    }

    #[test]
    fn apply_only_comments_produces_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env.silo"), "# only comments\n\n").unwrap();

        let count = apply_silo_env(dir.path(), &test_vars()).unwrap();
        assert_eq!(count, 0);
        assert!(!dir.path().join(".env").exists());
    }
}
