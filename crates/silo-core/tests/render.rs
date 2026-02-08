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

// --- apply_silo_env tests ---

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
        "DATABASE_URL=postgres://localhost/myapp_feature-a\nHOST=127.0.1.1\n"
    );
}

#[test]
fn apply_appends_new_keys_to_existing_env() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".env"), "SECRET_KEY=abc123\nSTRIPE_KEY=sk_test_xxx\n").unwrap();
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

// --- copy_files tests ---

#[test]
fn copy_files_basic() {
    let repo = tempfile::tempdir().unwrap();
    let worktree = tempfile::tempdir().unwrap();

    fs::write(repo.path().join(".env"), "SECRET=abc123").unwrap();

    let count = render::copy_files(
        repo.path(),
        worktree.path(),
        &[".env".into()],
    )
    .unwrap();

    assert_eq!(count, 1);
    assert_eq!(
        fs::read_to_string(worktree.path().join(".env")).unwrap(),
        "SECRET=abc123"
    );
}

#[test]
fn copy_files_glob_pattern() {
    let repo = tempfile::tempdir().unwrap();
    let worktree = tempfile::tempdir().unwrap();

    fs::write(repo.path().join(".env"), "A=1").unwrap();
    fs::write(repo.path().join(".env.local"), "B=2").unwrap();

    let count = render::copy_files(
        repo.path(),
        worktree.path(),
        &[".env*".into()],
    )
    .unwrap();

    assert_eq!(count, 2);
    assert!(worktree.path().join(".env").exists());
    assert!(worktree.path().join(".env.local").exists());
}

#[test]
fn copy_files_skips_existing() {
    let repo = tempfile::tempdir().unwrap();
    let worktree = tempfile::tempdir().unwrap();

    fs::write(repo.path().join(".env"), "NEW").unwrap();
    fs::write(worktree.path().join(".env"), "EXISTING").unwrap();

    let count = render::copy_files(
        repo.path(),
        worktree.path(),
        &[".env".into()],
    )
    .unwrap();

    assert_eq!(count, 0);
    assert_eq!(
        fs::read_to_string(worktree.path().join(".env")).unwrap(),
        "EXISTING"
    );
}

#[test]
fn copy_files_empty_patterns() {
    let repo = tempfile::tempdir().unwrap();
    let worktree = tempfile::tempdir().unwrap();

    let count = render::copy_files(repo.path(), worktree.path(), &[]).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn copy_files_nested() {
    let repo = tempfile::tempdir().unwrap();
    let worktree = tempfile::tempdir().unwrap();

    let nested = repo.path().join("config");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("secrets.yml"), "key: value").unwrap();

    let count = render::copy_files(
        repo.path(),
        worktree.path(),
        &["config/secrets.yml".into()],
    )
    .unwrap();

    assert_eq!(count, 1);
    assert_eq!(
        fs::read_to_string(worktree.path().join("config/secrets.yml")).unwrap(),
        "key: value"
    );
}

// --- copy + apply integration ---

#[test]
fn copy_then_apply_replaces_keys_in_copied_env() {
    let repo = tempfile::tempdir().unwrap();
    let worktree = tempfile::tempdir().unwrap();

    // Main repo has .env with secrets + default DATABASE_URL
    fs::write(
        repo.path().join(".env"),
        "SECRET_KEY=abc123\nDATABASE_URL=postgres://localhost/myapp\n",
    )
    .unwrap();

    // Worktree has .env.silo (tracked in git, so it's already there)
    fs::write(
        worktree.path().join(".env.silo"),
        "DATABASE_URL=postgres://localhost/myapp_${SILO_NAME}\nREDIS_URL=redis://${SILO_IP}:6379",
    )
    .unwrap();

    // Step 1: copy .env
    render::copy_files(repo.path(), worktree.path(), &[".env".into()]).unwrap();

    // Step 2: apply .silo overrides
    render::apply_silo_env(worktree.path(), &test_vars()).unwrap();

    let output = fs::read_to_string(worktree.path().join(".env")).unwrap();
    // DATABASE_URL replaced in-place (no duplicate), REDIS_URL appended
    assert_eq!(
        output,
        "SECRET_KEY=abc123\nDATABASE_URL=postgres://localhost/myapp_feature-a\nREDIS_URL=redis://127.0.1.1:6379\n"
    );
}
