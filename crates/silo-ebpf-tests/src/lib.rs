// This crate exists solely to host integration tests for silo-ebpf.
// The actual test logic lives in tests/ebpf_integration.rs and src/bin/ebpf_helper.rs.

#[cfg(target_os = "linux")]
pub mod harness;
