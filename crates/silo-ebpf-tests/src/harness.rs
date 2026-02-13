//! Test harness for eBPF integration tests.
//!
//! Manages loading BPF programs, creating cgroups, and running the helper
//! binary inside the cgroup for verification.
#![allow(unsafe_code)]

use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use aya::Ebpf;
use aya::maps::HashMap;
use aya::programs::{CgroupAttachMode, CgroupSockAddr};

const CGROUP_BASE: &str = "/sys/fs/cgroup/silo-test";

const PROGRAM_NAMES: &[&str] = &[
    "silo_bind4",
    "silo_bind6",
    "silo_connect4",
    "silo_connect6",
    "silo_sendmsg4",
    "silo_sendmsg6",
    "silo_recvmsg4",
    "silo_recvmsg6",
    "silo_getpeername4",
    "silo_getpeername6",
    "silo_getsockname4",
    "silo_getsockname6",
];

static EBPF_BYTES: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/silo-ebpf"));

pub struct EbpfTestHarness {
    cgroup_path: PathBuf,
    helper_binary: PathBuf,
    _bpf: Ebpf,
}

impl EbpfTestHarness {
    /// Create a test harness with eBPF programs attached to a unique cgroup.
    ///
    /// `helper_binary` is the path to the ebpf-helper binary (use
    /// `env!("CARGO_BIN_EXE_ebpf-helper")` from integration tests).
    ///
    /// If `silo_ip` is `Some`, the IP is written to the config map keyed by cgroup ID.
    /// If `None`, the map stays empty (passthrough mode).
    pub fn new(
        test_name: &str,
        silo_ip: Option<Ipv4Addr>,
        helper_binary: PathBuf,
    ) -> eyre::Result<Self> {
        let cgroup_path = PathBuf::from(CGROUP_BASE).join(test_name);
        fs::create_dir_all(&cgroup_path)?;

        let cgroup_id = fs::metadata(&cgroup_path)?.ino();
        let cgroup_fd = fs::File::open(&cgroup_path)?;
        let mut bpf = Ebpf::load(EBPF_BYTES)?;

        if let Some(ip) = silo_ip {
            let ip_nbo = u32::from(ip).to_be();
            let mut config: HashMap<_, u64, u32> =
                HashMap::try_from(bpf.map_mut("SILO_CONFIG").unwrap()).unwrap();
            config.insert(cgroup_id, ip_nbo, 0)?;
        }

        for name in PROGRAM_NAMES {
            let prog: &mut CgroupSockAddr = bpf.program_mut(name).unwrap().try_into().unwrap();
            prog.load()?;
            prog.attach(&cgroup_fd, CgroupAttachMode::Single)?;
        }

        Ok(Self {
            cgroup_path,
            helper_binary,
            _bpf: bpf,
        })
    }

    /// Run the helper binary inside this harness's cgroup.
    ///
    /// Returns (stdout, stderr, success).
    pub fn run_helper(&self, command: &str) -> (String, String, bool) {
        let procs_path = self.cgroup_path.join("cgroup.procs");

        let mut cmd = Command::new(&self.helper_binary);
        cmd.arg(command);

        // Move child into cgroup after fork() but before exec().
        // This ensures the helper process is in the cgroup before any
        // socket operations, with no race condition.
        unsafe {
            cmd.pre_exec(move || {
                fs::write(&procs_path, std::process::id().to_string())
                    .map_err(|e| std::io::Error::other(e))
            });
        }

        let output = cmd.output().expect("failed to spawn ebpf-helper");
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let success = output.status.success();

        if !success {
            eprintln!("--- helper stderr ---\n{stderr}--- end stderr ---");
        }

        (stdout, stderr, success)
    }

    pub fn cgroup_path(&self) -> &Path {
        &self.cgroup_path
    }
}

impl Drop for EbpfTestHarness {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.cgroup_path);
    }
}

/// Check if we have the capabilities needed to run eBPF tests.
pub fn can_run_ebpf_tests() -> bool {
    // Need valid eBPF bytecode (build.rs may create an empty stub on failure)
    if EBPF_BYTES.is_empty() {
        eprintln!("SKIP: eBPF bytecode is empty (build may have failed)");
        return false;
    }

    // Sanity-check: bytecode must be a valid ELF (starts with \x7fELF)
    if EBPF_BYTES.len() < 4 || &EBPF_BYTES[..4] != b"\x7fELF" {
        eprintln!(
            "SKIP: eBPF bytecode is not valid ELF ({} bytes, magic: {:02x?})",
            EBPF_BYTES.len(),
            &EBPF_BYTES[..EBPF_BYTES.len().min(4)]
        );
        return false;
    }

    // ELF machine type must be EM_BPF (247)
    if EBPF_BYTES.len() >= 20 {
        let e_machine = u16::from_le_bytes([EBPF_BYTES[18], EBPF_BYTES[19]]);
        if e_machine != 247 {
            eprintln!(
                "SKIP: eBPF binary has wrong machine type {e_machine} (expected EM_BPF=247, {} bytes)",
                EBPF_BYTES.len()
            );
            return false;
        }
    }

    // Need root or CAP_BPF + CAP_NET_ADMIN
    unsafe { libc::geteuid() == 0 }
}
