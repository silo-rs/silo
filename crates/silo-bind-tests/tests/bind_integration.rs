use std::path::PathBuf;
use std::process::Command;
use std::sync::Once;

const TEST_IP: &str = "127.0.99.1";

static SETUP: Once = Once::new();

fn ensure_loopback_alias() {
    SETUP.call_once(|| {
        #[cfg(target_os = "macos")]
        {
            let output = Command::new("ifconfig")
                .arg("lo0")
                .output()
                .expect("ifconfig failed");
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.contains(TEST_IP) {
                let status = Command::new("sudo")
                    .args([
                        "-n",
                        "ifconfig",
                        "lo0",
                        "alias",
                        TEST_IP,
                        "netmask",
                        "255.0.0.0",
                    ])
                    .status()
                    .expect("failed to run sudo ifconfig");
                assert!(
                    status.success(),
                    "cannot add loopback alias for {TEST_IP}. \
                     Run: sudo ifconfig lo0 alias {TEST_IP} netmask 255.0.0.0"
                );
            }
        }
    });
}

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
    if silo_ip.is_some() {
        ensure_loopback_alias();
    }
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

#[test]
fn bind_inaddr_any_is_rewritten() {
    let (stdout, _, success) = run_helper("bind_any", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains(TEST_IP),
        "expected bind to {TEST_IP}, got: {stdout}"
    );
    assert!(
        !stdout.contains("0.0.0.0"),
        "INADDR_ANY should have been rewritten, got: {stdout}"
    );
}

#[test]
fn bind_localhost_is_rewritten() {
    let (stdout, _, success) = run_helper("bind_localhost", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains(TEST_IP),
        "expected bind to {TEST_IP}, got: {stdout}"
    );
}

#[test]
fn connect_localhost_is_rewritten() {
    let (stdout, _, success) = run_helper("connect_localhost", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains(TEST_IP),
        "expected connect to {TEST_IP}, got: {stdout}"
    );
}

#[test]
fn getaddrinfo_localhost_passes_through() {
    let (stdout, _, success) = run_helper("getaddrinfo", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains("127.0.0.1"),
        "expected getaddrinfo to return real 127.0.0.1, got: {stdout}"
    );
}

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

#[test]
fn connect_to_unbound_port_not_rewritten() {
    let (stdout, _, _) = run_helper("connect_no_listener", Some(TEST_IP));
    assert!(
        stdout.contains("connect_result=refused"),
        "expected ECONNREFUSED for unbound port, got: {stdout}"
    );
}

#[test]
fn sendto_udp_bind_is_rewritten() {
    let (stdout, _, success) = run_helper("sendto_any", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains(TEST_IP),
        "expected UDP bind to {TEST_IP}, got: {stdout}"
    );
}

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

#[test]
fn no_silo_ip_passes_through() {
    let (stdout, _, success) = run_helper("passthrough", None);
    assert!(success, "helper failed");
    assert!(
        stdout.contains("0.0.0.0"),
        "expected passthrough to 0.0.0.0, got: {stdout}"
    );
}

#[test]
fn invalid_silo_ip_passes_through() {
    let (stdout, _, success) = run_helper("passthrough", Some("not-an-ip"));
    assert!(success, "helper failed");
    assert!(
        stdout.contains("0.0.0.0"),
        "expected passthrough with invalid IP, got: {stdout}"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn bind_v6_preserves_socket_options() {
    let (stdout, _, success) = run_helper("bind_v6_opts", Some(TEST_IP));
    assert!(success, "helper failed");

    assert!(
        stdout.contains("family=v6"),
        "expected in-place IPv6 rewrite (dual-stack), got: {stdout}"
    );

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
    assert!(reuseaddr_val != 0, "SO_REUSEADDR was lost (got 0)");

    assert!(
        stdout.contains("nonblock=true"),
        "O_NONBLOCK was lost, got: {stdout}"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn bind_v6_dualstack_stays_ipv6() {
    let (stdout, _, success) = run_helper("bind_v6_dualstack", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains("v6only_before=0"),
        "expected dual-stack default (IPV6_V6ONLY=0), got: {stdout}"
    );
    assert!(
        stdout.contains("family=v6"),
        "dual-stack socket should stay AF_INET6 after in-place rewrite, got: {stdout}"
    );
    assert!(
        stdout.contains(&format!("::ffff:{TEST_IP}")),
        "expected bound to ::ffff:{TEST_IP}, got: {stdout}"
    );
    assert!(
        stdout.contains("accept=ok"),
        "IPv4 client should reach dual-stack listener via {TEST_IP}, got: {stdout}"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn bind_v6_v6only_falls_back_to_ipv4() {
    let (stdout, _, success) = run_helper("bind_v6_v6only", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains("family=v6"),
        "v6-only socket should stay AF_INET6 with V6ONLY cleared, got: {stdout}"
    );
    assert!(
        stdout.contains("v6only_after=0"),
        "V6ONLY should be cleared after rewrite, got: {stdout}"
    );
    assert!(
        stdout.contains(&format!("bound={TEST_IP}")),
        "expected bind to {TEST_IP} via IPv4-mapped IPv6, got: {stdout}"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn bind_v6_kqueue_survives_rewrite() {
    let (stdout, _, success) = run_helper("bind_v6_kqueue", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains("kqueue_events=1"),
        "kqueue should fire after in-place rewrite (fd preserved), got: {stdout}"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn bind_through_non_sip_shell() {
    ensure_loopback_alias();
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

fn run_injected(program: &str, args: &[&str], silo_ip: &str) -> (String, String, bool) {
    ensure_loopback_alias();
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.env(INJECT_KEY, dylib_path().to_str().unwrap());
    cmd.env("SILO_IP", silo_ip);

    let output = cmd.output().expect("failed to spawn process");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();

    if !success {
        eprintln!("--- injected stderr ---\n{stderr}--- end stderr ---");
    }

    (stdout, stderr, success)
}

#[test]
fn runtime_node_bind_is_rewritten() {
    if which::which("node").is_err() {
        eprintln!("SKIP: node not found");
        return;
    }

    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/node_helper.mjs");
    let (stdout, _, success) = run_injected("node", &[fixture.to_str().unwrap()], TEST_IP);
    assert!(success, "node helper failed");
    assert!(
        stdout.contains(TEST_IP),
        "expected bind to {TEST_IP}, got: {stdout}"
    );
    assert!(
        !stdout.contains("0.0.0.0"),
        "INADDR_ANY should have been rewritten, got: {stdout}"
    );
}

#[test]
fn runtime_go_bind_is_rewritten() {
    if which::which("go").is_err() {
        eprintln!("SKIP: go not found");
        return;
    }

    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/go_helper.go");
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let bin = tmp.path().join("go_helper");

    let build = Command::new("go")
        .args([
            "build",
            "-o",
            bin.to_str().unwrap(),
            fixture.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run go build");
    assert!(
        build.status.success(),
        "go build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let (stdout, _, success) = run_injected(bin.to_str().unwrap(), &[], TEST_IP);
    assert!(success, "go helper failed");

    if cfg!(target_os = "macos") {
        assert!(
            stdout.contains(TEST_IP),
            "expected bind to {TEST_IP} on macOS, got: {stdout}"
        );
    } else {
        assert!(
            stdout.contains("0.0.0.0"),
            "expected Go to bypass LD_PRELOAD on Linux, got: {stdout}"
        );
    }
}

#[test]
fn runtime_go_cgo_disabled_bind() {
    if which::which("go").is_err() {
        eprintln!("SKIP: go not found");
        return;
    }

    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/go_helper.go");
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let bin = tmp.path().join("go_helper_static");

    let build = Command::new("go")
        .env("CGO_ENABLED", "0")
        .args([
            "build",
            "-o",
            bin.to_str().unwrap(),
            fixture.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run go build");
    assert!(
        build.status.success(),
        "go build (CGO_ENABLED=0) failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let (stdout, _, success) = run_injected(bin.to_str().unwrap(), &[], TEST_IP);
    assert!(success, "go helper failed");

    if cfg!(target_os = "macos") {
        assert!(
            stdout.contains(TEST_IP),
            "expected bind to {TEST_IP} on macOS (libSystem), got: {stdout}"
        );
    } else {
        assert!(
            stdout.contains("0.0.0.0"),
            "expected static Go binary to bypass LD_PRELOAD on Linux, got: {stdout}"
        );
    }
}

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
        assert!(
            stdout.contains("0.0.0.0"),
            "expected SIP shell to strip DYLD_INSERT_LIBRARIES, but interception worked: {stdout}"
        );
    }
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

#[test]
fn bind_unix_passes_through() {
    let (stdout, _, success) = run_helper("bind_unix", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains("unix=ok"),
        "AF_UNIX bind should pass through without error, got: {stdout}"
    );
}

#[test]
fn errno_preserved_after_connect_probe() {
    let (stdout, _, success) = run_helper("errno_after_connect", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains("errno_preserved=true"),
        "errno should be preserved after connect probe, got: {stdout}"
    );
}

#[test]
fn concurrent_binds_all_rewritten() {
    let (stdout, _, success) = run_helper("concurrent_bind", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains("concurrent=ok"),
        "all concurrent binds should succeed, got: {stdout}"
    );
    for i in 0..10 {
        let key = format!("thread_{i}=");
        let line = stdout.lines().find(|l| l.starts_with(&key));
        assert!(
            line.is_some(),
            "missing output for thread {i}, got: {stdout}"
        );
        let line = line.unwrap();
        assert!(
            line.contains(TEST_IP),
            "thread {i} should bind to {TEST_IP}, got: {line}"
        );
    }
}

#[test]
fn bind_v6_any_is_rewritten() {
    let (stdout, _, success) = run_helper("bind_v6_any_linux", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains(TEST_IP) || stdout.contains("mapped=true"),
        "IPv6 any bind should be rewritten, got: {stdout}"
    );
}

#[test]
fn bind_v6_localhost_is_rewritten() {
    let (stdout, _, success) = run_helper("bind_v6_localhost_linux", Some(TEST_IP));
    assert!(success, "helper failed");
    assert!(
        stdout.contains(TEST_IP) || stdout.contains("mapped=true"),
        "IPv6 localhost bind should be rewritten, got: {stdout}"
    );
}

#[test]
fn silo_ip_with_whitespace_is_trimmed() {
    let (stdout, _, success) = run_helper("passthrough", Some(" 127.0.99.1"));
    assert!(success, "helper failed");
    assert!(
        !stdout.contains("0.0.0.0"),
        "SILO_IP with whitespace should be accepted after trimming, got: {stdout}"
    );
}

#[test]
fn silo_ip_ipv6_passes_through() {
    let (stdout, _, success) = run_helper("passthrough", Some("::1"));
    assert!(success, "helper failed");
    assert!(
        stdout.contains("0.0.0.0"),
        "SILO_IP set to IPv6 should be treated as invalid, got: {stdout}"
    );
}
