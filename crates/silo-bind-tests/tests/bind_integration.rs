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

/// getaddrinfo("localhost") should pass through without rewriting (DNS
/// interception has been removed). On Linux (where SILO_IP != 127.0.0.1),
/// this verifies that getaddrinfo returns the real system result.
#[test]
fn getaddrinfo_localhost_passes_through() {
    let (stdout, _, success) = run_helper("getaddrinfo", Some(TEST_IP));
    assert!(success, "helper failed");
    // getaddrinfo should return the real system result (127.0.0.1), not SILO_IP
    assert!(
        stdout.contains("127.0.0.1"),
        "expected getaddrinfo to return real 127.0.0.1, got: {stdout}"
    );
}

/// On Linux where SILO_IP is 127.0.99.1, verify getaddrinfo does NOT return SILO_IP.
#[test]
#[cfg(target_os = "linux")]
fn getaddrinfo_localhost_not_rewritten_to_silo_ip() {
    let (stdout, _, success) = run_helper("getaddrinfo", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        !stdout.contains(TEST_IP),
        "getaddrinfo should NOT rewrite to SILO_IP ({TEST_IP}), got: {stdout}"
    );
}

// ── connect() probe tests ──

/// When no listener exists on SILO_IP:port, connect(127.0.0.1:port) should
/// NOT be rewritten — the connection should be refused (no listener anywhere).
#[test]
fn connect_to_unbound_port_not_rewritten() {
    let (stdout, _, _) = run_helper("connect_no_listener", Some(TEST_IP));
    assert!(
        stdout.contains("connect_result=refused"),
        "expected ECONNREFUSED for unbound port, got: {stdout}"
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

// ── sendmsg() tests ──

/// sendmsg() with msg_name pointing to 127.0.0.1 should have the destination
/// rewritten to SILO_IP. We verify by sending to ourselves (bind was also
/// rewritten to SILO_IP) and successfully receiving the packet.
#[test]
fn sendmsg_localhost_is_rewritten() {
    let (stdout, _, success) = run_helper("sendmsg_localhost", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains(TEST_IP),
        "expected bind to {TEST_IP}, got: {stdout}"
    );
    assert!(
        stdout.contains("sendmsg=ok"),
        "sendmsg should have delivered the packet (address rewritten), got: {stdout}"
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

// ── IPv6→IPv4 socket option preservation (macOS only) ──

/// When silo-bind replaces an IPv6 socket with an IPv4 one (macOS only),
/// socket options like SO_REUSEADDR and fd flags like O_NONBLOCK must survive.
#[test]
#[cfg(target_os = "macos")]
fn bind_v6_preserves_socket_options() {
    let (stdout, _, success) = run_helper("bind_v6_opts", Some(TEST_IP));
    assert!(success, "helper failed");

    // Socket should have been replaced to IPv4
    assert!(
        stdout.contains("family=v4"),
        "expected IPv6→IPv4 replacement, got: {stdout}"
    );
    assert!(
        stdout.contains(&format!("bound={TEST_IP}")),
        "expected bind to {TEST_IP}, got: {stdout}"
    );

    // SO_REUSEADDR must be preserved (macOS may return a non-zero value other than 1)
    let reuseaddr_line = stdout
        .lines()
        .find(|l| l.starts_with("reuseaddr="))
        .expect("missing reuseaddr line");
    let reuseaddr_val: i32 = reuseaddr_line
        .strip_prefix("reuseaddr=")
        .unwrap()
        .trim()
        .parse()
        .expect("bad reuseaddr value");
    assert!(
        reuseaddr_val != 0,
        "SO_REUSEADDR was lost during socket replacement (got 0)"
    );

    // O_NONBLOCK must be preserved
    assert!(
        stdout.contains("nonblock=true"),
        "O_NONBLOCK was lost during socket replacement, got: {stdout}"
    );
}

// ── shell-mediated tests (macOS SIP scenario) ──

/// Simulates what config scripts (e.g. `silo dev`) do: runs bind-helper through `sh -c`.
/// On macOS, this verifies that DYLD_INSERT_LIBRARIES works when the shell
/// is NOT SIP-protected. The test finds a non-SIP shell (e.g. Homebrew bash)
/// and runs the helper through it.
#[test]
#[cfg(target_os = "macos")]
fn bind_through_non_sip_shell() {
    // Find a non-SIP shell, similar to what resolve_program now does
    let shell = find_non_sip_shell();
    let Some(shell) = shell else {
        eprintln!("SKIP: no non-SIP shell available (install Homebrew bash/zsh)");
        return;
    };

    let helper = helper_path();
    let lib = dylib_path();

    let output = std::process::Command::new(&shell)
        .args(["-c", &format!("{} bind_any", helper.display())])
        .env(INJECT_KEY, lib.to_str().unwrap())
        .env("SILO_IP", TEST_IP)
        .output()
        .expect("failed to run shell");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "shell command failed. stderr: {stderr}"
    );
    assert!(
        stdout.contains(TEST_IP),
        "bind interception failed through non-SIP shell ({shell}), got: {stdout}"
    );
    assert!(
        !stdout.contains("0.0.0.0"),
        "INADDR_ANY should have been rewritten through shell, got: {stdout}"
    );
}

/// Verifies that DYLD_INSERT_LIBRARIES is stripped when using a SIP-protected
/// shell (/bin/sh), causing bind interception to NOT work. This documents the
/// known limitation that motivates the SIP resolution in shebang.rs.
#[test]
#[cfg(target_os = "macos")]
fn bind_through_sip_shell_is_stripped() {
    let helper = helper_path();
    let lib = dylib_path();

    let output = std::process::Command::new("/bin/sh")
        .args(["-c", &format!("{} bind_any", helper.display())])
        .env(INJECT_KEY, lib.to_str().unwrap())
        .env("SILO_IP", TEST_IP)
        .output()
        .expect("failed to run /bin/sh");

    let stdout = String::from_utf8_lossy(&output.stdout);

    if output.status.success() {
        // With SIP shell, DYLD_INSERT_LIBRARIES gets stripped.
        // bind(0.0.0.0) should NOT be rewritten — it stays as 0.0.0.0
        assert!(
            stdout.contains("0.0.0.0"),
            "expected SIP shell to strip DYLD_INSERT_LIBRARIES, but interception worked: {stdout}"
        );
    }
    // If the process failed, that's also acceptable — SIP can cause issues
}

#[cfg(target_os = "macos")]
fn find_non_sip_shell() -> Option<String> {
    for name in &["bash", "zsh", "sh"] {
        if let Ok(path) = which::which(name) {
            let s = path.to_string_lossy();
            if !s.starts_with("/usr/bin/")
                && !s.starts_with("/bin/")
                && !s.starts_with("/sbin/")
                && !s.starts_with("/usr/sbin/")
            {
                return Some(s.into_owned());
            }
        }
    }
    None
}
