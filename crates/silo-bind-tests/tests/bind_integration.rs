//! Integration tests for silo-bind syscall interception.
//!
//! Each test spawns the `bind-helper` binary with the silo-bind library
//! injected via DYLD_INSERT_LIBRARIES (macOS) or LD_PRELOAD (Linux), and
//! SILO_IP set to a test loopback address. The helper performs the syscall
//! and prints the result; we verify it was rewritten.
//!
//! Platform note: on macOS, only 127.0.0.1 is available on lo0 without creating
//! an alias (which requires sudo). On Linux, the entire 127.0.0.0/8 is usable.
//! We use 127.0.0.1 as SILO_IP on macOS and 127.0.99.1 on Linux.

use std::path::PathBuf;
use std::process::Command;

/// On macOS only 127.0.0.1 is bindable without sudo alias setup.
/// On Linux the entire 127.0.0.0/8 is available.
#[cfg(target_os = "macos")]
const TEST_IP: &str = "127.0.0.1";
#[cfg(target_os = "linux")]
const TEST_IP: &str = "127.0.99.1";

fn helper_path() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_BIN_EXE_bind-helper"));
    assert!(path.exists(), "bind-helper not found at {}", path.display());
    path
}

fn dylib_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = manifest_dir.parent().unwrap().parent().unwrap();

    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    #[cfg(target_os = "macos")]
    let name = "libsilo_bind.dylib";
    #[cfg(target_os = "linux")]
    let name = "libsilo_bind.so";

    let path = workspace_dir.join("target").join(profile).join(name);
    assert!(
        path.exists(),
        "silo-bind library not found at {}. Run `cargo build -p silo-bind` first.",
        path.display()
    );
    path
}

#[cfg(target_os = "macos")]
const INJECT_KEY: &str = "DYLD_INSERT_LIBRARIES";
#[cfg(target_os = "linux")]
const INJECT_KEY: &str = "LD_PRELOAD";

fn run_helper(command: &str, silo_ip: Option<&str>) -> (String, String, bool) {
    let mut cmd = Command::new(helper_path());
    cmd.arg(command);
    cmd.env(INJECT_KEY, dylib_path().to_str().unwrap());

    if let Some(ip) = silo_ip {
        cmd.env("SILO_IP", ip);
    }

    let output = cmd.output().expect("failed to spawn bind-helper");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();

    if !success {
        eprintln!("--- helper stderr ---\n{stderr}--- end stderr ---");
    }

    (stdout, stderr, success)
}

// ── bind() tests ──

/// bind(0.0.0.0) should be rewritten to SILO_IP.
/// On macOS this verifies INADDR_ANY → 127.0.0.1.
/// On Linux this verifies INADDR_ANY → 127.0.99.1.
#[test]
fn bind_inaddr_any_is_rewritten() {
    let (stdout, _, success) = run_helper("bind_any", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains(TEST_IP),
        "expected bind to {TEST_IP}, got: {stdout}"
    );
    // On both platforms, it should NOT contain 0.0.0.0 (it was rewritten)
    assert!(
        !stdout.contains("0.0.0.0"),
        "INADDR_ANY should have been rewritten, got: {stdout}"
    );
}

/// bind(127.0.0.1) should be rewritten to SILO_IP.
#[test]
fn bind_localhost_is_rewritten() {
    let (stdout, _, success) = run_helper("bind_localhost", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains(TEST_IP),
        "expected bind to {TEST_IP}, got: {stdout}"
    );
}

// ── connect() tests ──

/// connect(127.0.0.1) should be rewritten to SILO_IP.
#[test]
fn connect_localhost_is_rewritten() {
    let (stdout, _, success) = run_helper("connect_localhost", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains(TEST_IP),
        "expected connect to {TEST_IP}, got: {stdout}"
    );
}

// ── getaddrinfo() tests ──

/// getaddrinfo("localhost") results should have 127.0.0.1 rewritten to SILO_IP.
#[test]
fn getaddrinfo_localhost_is_rewritten() {
    let (stdout, _, success) = run_helper("getaddrinfo", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains(TEST_IP),
        "expected getaddrinfo to resolve to {TEST_IP}, got: {stdout}"
    );
}

// ── sendto() tests ──

/// UDP bind(0.0.0.0) used for sendto should be rewritten to SILO_IP.
#[test]
fn sendto_udp_bind_is_rewritten() {
    let (stdout, _, success) = run_helper("sendto_any", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains(TEST_IP),
        "expected UDP bind to {TEST_IP}, got: {stdout}"
    );
}

// ── passthrough tests (no SILO_IP) ──

/// Without SILO_IP set, bind(0.0.0.0) should pass through unchanged.
#[test]
fn no_silo_ip_passes_through() {
    let (stdout, _, success) = run_helper("passthrough", None);
    assert!(success, "helper failed");
    assert!(
        stdout.contains("0.0.0.0"),
        "expected passthrough to 0.0.0.0, got: {stdout}"
    );
}

/// With an invalid SILO_IP, bind(0.0.0.0) should pass through unchanged.
#[test]
fn invalid_silo_ip_passes_through() {
    let (stdout, _, success) = run_helper("passthrough", Some("not-an-ip"));
    assert!(success, "helper failed");
    assert!(
        stdout.contains("0.0.0.0"),
        "expected passthrough with invalid IP, got: {stdout}"
    );
}
