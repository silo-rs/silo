use std::collections::HashMap;
use std::fs;

use silo::render;

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
    fs::write(
        dir.path().join(".env.silo"),
        "DATABASE_URL=postgres://localhost/myapp_${SILO_NAME}\nHOST=${SILO_IP}\n",
    )
    .unwrap();

    let count = render::apply_silo_env(dir.path(), &test_vars()).unwrap();
    assert_eq!(count, 1);

    let output = fs::read_to_string(dir.path().join(".env")).unwrap();
    assert_eq!(
        output,
        "DATABASE_URL=postgres://localhost/myapp_feature-a\nHOST=127.1.0.42\n"
    );
}

#[test]
fn apply_appends_new_keys_to_existing_env() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join(".env"),
        "SECRET_KEY=abc123\nSTRIPE_KEY=sk_test_xxx\n",
    )
    .unwrap();
    fs::write(
        dir.path().join(".env.silo"),
        "DATABASE_URL=postgres://localhost/myapp_${SILO_NAME}",
    )
    .unwrap();

    let count = render::apply_silo_env(dir.path(), &test_vars()).unwrap();
    assert_eq!(count, 1);

    let output = fs::read_to_string(dir.path().join(".env")).unwrap();
    assert_eq!(
        output,
        "SECRET_KEY=abc123\nSTRIPE_KEY=sk_test_xxx\nDATABASE_URL=postgres://localhost/myapp_feature-a\n"
    );
}

#[test]
fn apply_replaces_existing_keys() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join(".env"),
        "SECRET_KEY=abc123\nDATABASE_URL=postgres://localhost/myapp\nSTRIPE_KEY=sk_test_xxx\n",
    )
    .unwrap();
    fs::write(
        dir.path().join(".env.silo"),
        "DATABASE_URL=postgres://localhost/myapp_${SILO_NAME}",
    )
    .unwrap();

    let count = render::apply_silo_env(dir.path(), &test_vars()).unwrap();
    assert_eq!(count, 1);

    let output = fs::read_to_string(dir.path().join(".env")).unwrap();
    assert_eq!(
        output,
        "SECRET_KEY=abc123\nDATABASE_URL=postgres://localhost/myapp_feature-a\nSTRIPE_KEY=sk_test_xxx\n"
    );
}

#[test]
fn apply_skips_comments_and_blanks() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join(".env.silo"),
        "# this is a comment\n\nKEY=value\n  # another comment\n",
    )
    .unwrap();

    let count = render::apply_silo_env(dir.path(), &test_vars()).unwrap();
    assert_eq!(count, 1);

    let output = fs::read_to_string(dir.path().join(".env")).unwrap();
    assert_eq!(output, "KEY=value\n");
}

#[test]
fn apply_nested_dirs() {
    let dir = tempfile::tempdir().unwrap();
    let api_dir = dir.path().join("packages/api");
    let web_dir = dir.path().join("packages/web");
    fs::create_dir_all(&api_dir).unwrap();
    fs::create_dir_all(&web_dir).unwrap();

    fs::write(api_dir.join(".env.silo"), "DB=api_${SILO_NAME}").unwrap();
    fs::write(web_dir.join(".env.silo"), "DB=web_${SILO_NAME}").unwrap();

    let count = render::apply_silo_env(dir.path(), &test_vars()).unwrap();
    assert_eq!(count, 2);

    assert_eq!(
        fs::read_to_string(api_dir.join(".env")).unwrap(),
        "DB=api_feature-a\n"
    );
    assert_eq!(
        fs::read_to_string(web_dir.join(".env")).unwrap(),
        "DB=web_feature-a\n"
    );
}

#[test]
fn apply_no_silo_files() {
    let dir = tempfile::tempdir().unwrap();
    let count = render::apply_silo_env(dir.path(), &test_vars()).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn apply_preserves_equals_in_value() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join(".env.silo"),
        "DATABASE_URL=postgres://user:pass@host/db?sslmode=require",
    )
    .unwrap();

    render::apply_silo_env(dir.path(), &test_vars()).unwrap();

    let output = fs::read_to_string(dir.path().join(".env")).unwrap();
    assert!(output.contains("DATABASE_URL=postgres://user:pass@host/db?sslmode=require"));
}

#[test]
fn apply_only_comments_produces_nothing() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".env.silo"), "# only comments\n\n").unwrap();

    let count = render::apply_silo_env(dir.path(), &test_vars()).unwrap();
    assert_eq!(count, 0);
    assert!(!dir.path().join(".env").exists());
}
