use eyre::Context;
use serde_json::json;

use silo_core::store::Store;

pub async fn run(store: &Store, instance: Option<&str>, json_output: bool) -> eyre::Result<()> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let cwd = cwd.canonicalize().unwrap_or(cwd);

    match super::resolve_instance_interactive(store, instance, &cwd).await {
        Ok(inst) => {
            let host = inst.hostname();
            if json_output {
                println!("{}", serde_json::to_string(&json!({
                    "SILO_NAME": inst.name,
                    "SILO_IP": inst.ip.to_string(),
                    "SILO_HOST": host,
                    "SILO_REPO": inst.repo,
                    "SILO_DIR": inst.path,
                    "SILO_WORKTREE": if inst.is_worktree { "1" } else { "0" },
                }))?);
            } else {
                println!(
                    "export SILO_NAME={} SILO_IP={} SILO_HOST={} SILO_REPO={} SILO_DIR={} SILO_WORKTREE={}",
                    shell_escape(&inst.name),
                    shell_escape(&inst.ip.to_string()),
                    shell_escape(&host),
                    shell_escape(&inst.repo.display().to_string()),
                    shell_escape(&inst.path.display().to_string()),
                    if inst.is_worktree { "1" } else { "0" },
                );
            }
        }
        Err(_) => {
            if json_output {
                println!("null");
            } else {
                println!("unset SILO_NAME SILO_IP SILO_HOST SILO_REPO SILO_DIR SILO_WORKTREE");
            }
        }
    }

    Ok(())
}

pub(crate) fn shell_escape(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '/' | '.' | '-' | '_' | ':'))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_string_unchanged() {
        assert_eq!(shell_escape("hello"), "hello");
        assert_eq!(shell_escape("/usr/bin/foo"), "/usr/bin/foo");
        assert_eq!(shell_escape("my-app_v2.0"), "my-app_v2.0");
        assert_eq!(shell_escape("127.0.1.1:8080"), "127.0.1.1:8080");
    }

    #[test]
    fn space_gets_quoted() {
        assert_eq!(shell_escape("hello world"), "'hello world'");
    }

    #[test]
    fn single_quote_escaped() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn special_chars_quoted() {
        assert_eq!(shell_escape("foo;bar"), "'foo;bar'");
        assert_eq!(shell_escape("$(cmd)"), "'$(cmd)'");
        assert_eq!(shell_escape("a&b"), "'a&b'");
    }

    #[test]
    fn empty_string_passthrough() {
        assert_eq!(shell_escape(""), "");
    }
}
