use std::fs;

use silo::config::{generate_default, load_config_from};

#[test]
fn parse_default_config() {
    let dir = tempfile::tempdir().unwrap();
    let content = generate_default("127.0.1.0/24");
    fs::write(dir.path().join("silo.toml"), &content).unwrap();

    let config = load_config_from(dir.path()).unwrap().unwrap();
    assert_eq!(config.instance.ip_range, "127.0.1.0/24");
    assert!(config.hooks.setup.is_empty());
    assert!(config.hooks.enter.is_empty());
    assert!(config.hooks.teardown.is_empty());
    assert_eq!(config.worktree.base_dir, "../");
}

#[test]
fn parse_full_config() {
    let dir = tempfile::tempdir().unwrap();
    let content = r#"
[instance]
ip_range = "127.0.2.0/24"

[hooks]
setup = ["npm install", "echo done"]
enter = ["echo entering"]
teardown = ["echo bye"]

[worktree]
base_dir = "../worktrees"
copy = [".env", ".env.local"]
"#;
    fs::write(dir.path().join("silo.toml"), content).unwrap();

    let config = load_config_from(dir.path()).unwrap().unwrap();
    assert_eq!(config.instance.ip_range, "127.0.2.0/24");
    assert_eq!(config.hooks.setup, vec!["npm install", "echo done"]);
    assert_eq!(config.hooks.enter, vec!["echo entering"]);
    assert_eq!(config.hooks.teardown, vec!["echo bye"]);
    assert_eq!(config.worktree.base_dir, "../worktrees");
    assert_eq!(config.worktree.copy, vec![".env", ".env.local"]);
}

#[test]
fn missing_config_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let config = load_config_from(dir.path()).unwrap();
    assert!(config.is_none());
}

#[test]
fn minimal_config() {
    let dir = tempfile::tempdir().unwrap();
    let content = r#"
[instance]
ip_range = "127.0.1.0/24"
"#;
    fs::write(dir.path().join("silo.toml"), content).unwrap();

    let config = load_config_from(dir.path()).unwrap().unwrap();
    assert_eq!(config.instance.ip_range, "127.0.1.0/24");
    assert!(config.hooks.setup.is_empty());
    assert!(config.hooks.enter.is_empty());
    assert_eq!(config.worktree.base_dir, "../");
    assert_eq!(config.worktree.copy, vec!["**/.env*"]);
}

#[test]
fn copy_default_can_be_overridden() {
    let dir = tempfile::tempdir().unwrap();
    let content = r#"
[instance]
ip_range = "127.0.1.0/24"

[worktree]
copy = []
"#;
    fs::write(dir.path().join("silo.toml"), content).unwrap();

    let config = load_config_from(dir.path()).unwrap().unwrap();
    assert!(config.worktree.copy.is_empty());
}

#[test]
fn invalid_toml_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("silo.toml"), "not valid toml {{{").unwrap();

    let result = load_config_from(dir.path());
    assert!(result.is_err());
}

#[test]
fn missing_required_field_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let content = r#"
[hooks]
setup = ["echo hi"]
"#;
    fs::write(dir.path().join("silo.toml"), content).unwrap();

    let result = load_config_from(dir.path());
    assert!(result.is_err());
}
