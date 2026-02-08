use std::collections::HashMap;
use std::fs;

use silo_core::render;

fn test_vars() -> HashMap<String, String> {
    HashMap::from([
        ("SILO_NAME".into(), "feature-a".into()),
        ("SILO_IP".into(), "127.0.1.1".into()),
        ("SILO_HOST".into(), "feature-a.myapp.silo".into()),
        ("SILO_REPO".into(), "/repo".into()),
        ("SILO_DIR".into(), "/work/feature-a".into()),
        ("SILO_WORKTREE".into(), "1".into()),
    ])
}

#[test]
fn renders_env_silo_to_env() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join(".env.silo"),
        "DATABASE_URL=postgres://localhost/myapp_${SILO_NAME}\nHOST=${SILO_IP}\n",
    )
    .unwrap();

    let count = render::render_templates(dir.path(), &test_vars()).unwrap();
    assert_eq!(count, 1);

    let output = fs::read_to_string(dir.path().join(".env")).unwrap();
    assert_eq!(
        output,
        "DATABASE_URL=postgres://localhost/myapp_feature-a\nHOST=127.0.1.1\n"
    );
}

#[test]
fn renders_nested_templates() {
    let dir = tempfile::tempdir().unwrap();
    let api_dir = dir.path().join("packages/api");
    let web_dir = dir.path().join("packages/web");
    fs::create_dir_all(&api_dir).unwrap();
    fs::create_dir_all(&web_dir).unwrap();

    fs::write(
        api_dir.join(".env.silo"),
        "DB=api_${SILO_NAME}",
    )
    .unwrap();
    fs::write(
        web_dir.join(".env.silo"),
        "DB=web_${SILO_NAME}",
    )
    .unwrap();

    let count = render::render_templates(dir.path(), &test_vars()).unwrap();
    assert_eq!(count, 2);

    assert_eq!(
        fs::read_to_string(api_dir.join(".env")).unwrap(),
        "DB=api_feature-a"
    );
    assert_eq!(
        fs::read_to_string(web_dir.join(".env")).unwrap(),
        "DB=web_feature-a"
    );
}

#[test]
fn skips_existing_output() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".env.silo"), "NEW=${SILO_NAME}").unwrap();
    fs::write(dir.path().join(".env"), "EXISTING").unwrap();

    let count = render::render_templates(dir.path(), &test_vars()).unwrap();
    assert_eq!(count, 0);

    // Original file preserved
    assert_eq!(fs::read_to_string(dir.path().join(".env")).unwrap(), "EXISTING");
}

#[test]
fn returns_zero_when_no_templates() {
    let dir = tempfile::tempdir().unwrap();
    let count = render::render_templates(dir.path(), &test_vars()).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn renders_file_without_variables() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("config.yml.silo"), "key: value\n").unwrap();

    let count = render::render_templates(dir.path(), &test_vars()).unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        fs::read_to_string(dir.path().join("config.yml")).unwrap(),
        "key: value\n"
    );
}

#[test]
fn renders_non_env_file_types() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("docker-compose.override.yml.silo"),
        "services:\n  db:\n    ports:\n      - ${SILO_IP}:5432:5432\n",
    )
    .unwrap();

    let count = render::render_templates(dir.path(), &test_vars()).unwrap();
    assert_eq!(count, 1);

    let output = fs::read_to_string(dir.path().join("docker-compose.override.yml")).unwrap();
    assert!(output.contains("127.0.1.1:5432:5432"));
}
