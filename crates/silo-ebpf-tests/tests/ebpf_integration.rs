#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;
use std::path::PathBuf;

use silo_ebpf_tests::harness::{self, EbpfTestHarness};

const TEST_IP: &str = "127.0.99.1";

fn test_ip() -> Ipv4Addr {
    TEST_IP.parse().unwrap()
}

fn helper_path() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_BIN_EXE_ebpf-helper"));
    assert!(path.exists(), "ebpf-helper not found at {}", path.display());
    path
}

macro_rules! skip_without_caps {
    () => {
        if !harness::can_run_ebpf_tests() {
            eprintln!("SKIP: need root or CAP_BPF+CAP_NET_ADMIN for eBPF tests");
            return;
        }
    };
}

#[test]
fn bind_inaddr_any_is_rewritten() {
    skip_without_caps!();
    let h = EbpfTestHarness::new("bind_any", Some(test_ip()), helper_path()).unwrap();
    let (stdout, _, success) = h.run_helper("bind_any");
    assert!(success, "helper failed");
    assert!(
        stdout.contains("127.0.0.1"),
        "expected getsockname to return 127.0.0.1, got: {stdout}"
    );
    assert!(
        !stdout.contains("0.0.0.0"),
        "INADDR_ANY should have been rewritten, got: {stdout}"
    );
}

#[test]
fn bind_localhost_is_rewritten() {
    skip_without_caps!();
    let h = EbpfTestHarness::new("bind_localhost", Some(test_ip()), helper_path()).unwrap();
    let (stdout, _, success) = h.run_helper("bind_localhost");
    assert!(success, "helper failed");
    assert!(
        stdout.contains("127.0.0.1"),
        "expected transparent round-trip to 127.0.0.1, got: {stdout}"
    );
}

#[test]
fn bind_v6_any_is_rewritten() {
    skip_without_caps!();
    let h = EbpfTestHarness::new("bind_v6_any", Some(test_ip()), helper_path()).unwrap();
    let (stdout, _, success) = h.run_helper("bind_v6_any");
    assert!(success, "helper failed");
    assert!(
        stdout.contains("::1]"),
        "expected getsockname to return [::1], got: {stdout}"
    );
}

#[test]
fn bind_v6_loopback_is_rewritten() {
    skip_without_caps!();
    let h = EbpfTestHarness::new("bind_v6_loopback", Some(test_ip()), helper_path()).unwrap();
    let (stdout, _, success) = h.run_helper("bind_v6_loopback");
    assert!(success, "helper failed");
    assert!(
        stdout.contains("::1]"),
        "expected transparent round-trip to [::1], got: {stdout}"
    );
}

#[test]
fn connect_localhost_is_rewritten() {
    skip_without_caps!();
    let h = EbpfTestHarness::new("connect_localhost", Some(test_ip()), helper_path()).unwrap();
    let (stdout, _, success) = h.run_helper("connect_localhost");
    assert!(success, "helper failed");
    assert!(
        stdout.contains("127.0.0.1"),
        "expected getpeername to return 127.0.0.1, got: {stdout}"
    );
}

#[test]
fn sendmsg_and_recvmsg_reverse_maps() {
    skip_without_caps!();
    let h = EbpfTestHarness::new("sendmsg_recvmsg", Some(test_ip()), helper_path()).unwrap();
    let (stdout, _, success) = h.run_helper("sendmsg_recvmsg");
    assert!(success, "helper failed");

    assert!(
        stdout.contains("bound=127.0.0.1:"),
        "expected getsockname to return 127.0.0.1, got: {stdout}"
    );

    assert!(
        stdout.contains("recvmsg_src=127.0.0.1"),
        "expected recvmsg source to be reverse-mapped to 127.0.0.1, got: {stdout}"
    );
}

#[test]
fn getpeername_reverse_maps() {
    skip_without_caps!();
    let h = EbpfTestHarness::new("getpeername", Some(test_ip()), helper_path()).unwrap();
    let (stdout, _, success) = h.run_helper("connect_getpeername");
    assert!(success, "helper failed");

    assert!(
        stdout.contains("getpeername=127.0.0.1:"),
        "expected getpeername to be reverse-mapped to 127.0.0.1, got: {stdout}"
    );
}

#[test]
fn passthrough_without_config() {
    skip_without_caps!();
    let h = EbpfTestHarness::new("passthrough", None, helper_path()).unwrap();
    let (stdout, _, success) = h.run_helper("bind_any");
    assert!(success, "helper failed");
    assert!(
        stdout.contains("0.0.0.0"),
        "expected passthrough to 0.0.0.0, got: {stdout}"
    );
}

#[test]
fn cgroup_cleanup_on_drop() {
    skip_without_caps!();
    let cgroup_path;
    {
        let h = EbpfTestHarness::new("cleanup_test", Some(test_ip()), helper_path()).unwrap();
        cgroup_path = h.cgroup_path().to_path_buf();
        assert!(cgroup_path.exists(), "cgroup should exist during session");
    }
    assert!(
        !cgroup_path.exists(),
        "cgroup should be cleaned up after drop"
    );
}
