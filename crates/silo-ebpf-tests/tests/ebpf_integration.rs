//! Integration tests for silo-ebpf cgroup/sock_addr programs.
//!
//! These tests require Linux with root or CAP_BPF + CAP_NET_ADMIN.
//! Run with: `sudo -E cargo test -p silo-ebpf-tests -- --test-threads=1`
#![cfg(target_os = "linux")]

use std::net::Ipv4Addr;

use silo_ebpf_tests::harness::{self, EbpfTestHarness};

/// On Linux the entire 127.0.0.0/8 is available without configuration.
const TEST_IP: &str = "127.0.99.1";

fn test_ip() -> Ipv4Addr {
    TEST_IP.parse().unwrap()
}

macro_rules! skip_without_caps {
    () => {
        if !harness::can_run_ebpf_tests() {
            eprintln!("SKIP: need root or CAP_BPF+CAP_NET_ADMIN for eBPF tests");
            return;
        }
    };
}

// ── bind() tests ──

#[test]
fn bind_inaddr_any_is_rewritten() {
    skip_without_caps!();
    let h = EbpfTestHarness::new("bind_any", Some(test_ip())).unwrap();
    let (stdout, _, success) = h.run_helper("bind_any");
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
    skip_without_caps!();
    let h = EbpfTestHarness::new("bind_localhost", Some(test_ip())).unwrap();
    let (stdout, _, success) = h.run_helper("bind_localhost");
    assert!(success, "helper failed");
    assert!(
        stdout.contains(TEST_IP),
        "expected bind to {TEST_IP}, got: {stdout}"
    );
}

// ── IPv6 bind() tests ──

#[test]
fn bind_v6_any_is_rewritten() {
    skip_without_caps!();
    let h = EbpfTestHarness::new("bind_v6_any", Some(test_ip())).unwrap();
    let (stdout, _, success) = h.run_helper("bind_v6_any");
    assert!(success, "helper failed");
    let expected = format!("::ffff:{TEST_IP}");
    assert!(
        stdout.contains(&expected),
        "expected bind to {expected}, got: {stdout}"
    );
}

#[test]
fn bind_v6_loopback_is_rewritten() {
    skip_without_caps!();
    let h = EbpfTestHarness::new("bind_v6_loopback", Some(test_ip())).unwrap();
    let (stdout, _, success) = h.run_helper("bind_v6_loopback");
    assert!(success, "helper failed");
    let expected = format!("::ffff:{TEST_IP}");
    assert!(
        stdout.contains(&expected),
        "expected bind to {expected}, got: {stdout}"
    );
}

// ── connect() tests ──

#[test]
fn connect_localhost_is_rewritten() {
    skip_without_caps!();
    let h = EbpfTestHarness::new("connect_localhost", Some(test_ip())).unwrap();
    let (stdout, _, success) = h.run_helper("connect_localhost");
    assert!(success, "helper failed");
    assert!(
        stdout.contains(TEST_IP),
        "expected connect to {TEST_IP}, got: {stdout}"
    );
}

// ── sendmsg + recvmsg reverse mapping ──

#[test]
fn sendmsg_and_recvmsg_reverse_maps() {
    skip_without_caps!();
    let h = EbpfTestHarness::new("sendmsg_recvmsg", Some(test_ip())).unwrap();
    let (stdout, _, success) = h.run_helper("sendmsg_recvmsg");
    assert!(success, "helper failed");

    // bind(0.0.0.0) should be rewritten to SILO_IP
    assert!(
        stdout.contains(&format!("bound={TEST_IP}:")),
        "expected bind to {TEST_IP}, got: {stdout}"
    );

    // recvmsg source should be reverse-mapped from SILO_IP back to 127.0.0.1
    assert!(
        stdout.contains("recvmsg_src=127.0.0.1"),
        "expected recvmsg source to be reverse-mapped to 127.0.0.1, got: {stdout}"
    );
}

// ── getpeername reverse mapping ──

#[test]
fn getpeername_reverse_maps() {
    skip_without_caps!();
    let h = EbpfTestHarness::new("getpeername", Some(test_ip())).unwrap();
    let (stdout, _, success) = h.run_helper("connect_getpeername");
    assert!(success, "helper failed");

    // getpeername should return 127.0.0.1 (reverse-mapped from SILO_IP)
    assert!(
        stdout.contains("getpeername=127.0.0.1:"),
        "expected getpeername to be reverse-mapped to 127.0.0.1, got: {stdout}"
    );
}

// ── passthrough (no config) ──

#[test]
fn passthrough_without_config() {
    skip_without_caps!();
    // Load programs but don't write to config map (IP stays 0)
    let h = EbpfTestHarness::new("passthrough", None).unwrap();
    let (stdout, _, success) = h.run_helper("bind_any");
    assert!(success, "helper failed");
    assert!(
        stdout.contains("0.0.0.0"),
        "expected passthrough to 0.0.0.0, got: {stdout}"
    );
}

// ── cgroup cleanup ──

#[test]
fn cgroup_cleanup_on_drop() {
    skip_without_caps!();
    let cgroup_path;
    {
        let h = EbpfTestHarness::new("cleanup_test", Some(test_ip())).unwrap();
        cgroup_path = h.cgroup_path().to_path_buf();
        assert!(cgroup_path.exists(), "cgroup should exist during session");
    }
    // After drop, cgroup should be removed
    assert!(
        !cgroup_path.exists(),
        "cgroup should be cleaned up after drop"
    );
}
