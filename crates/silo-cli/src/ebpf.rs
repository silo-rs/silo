//! eBPF backend: cgroup/sock_addr program management (Linux only).
//!
//! This module loads BPF programs that intercept socket operations at the kernel
//! level, providing address rewriting that works with all binaries regardless of
//! linking strategy (static Go, musl Rust, io_uring, etc.).
//!
//! Two loading modes:
//! - **Embedded**: Load programs from bytes compiled into the binary (requires CAP_BPF).
//! - **Pinned**: Attach pre-pinned programs from `/sys/fs/bpf/silo/` (rootless).
#![allow(unsafe_code)]

use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use aya::Ebpf;
use aya::maps::HashMap;
use aya::programs::{CgroupAttachMode, CgroupSockAddr, CgroupSockAddrAttachType};
use eyre::{Context, ContextCompat};

/// Base path for silo per-session cgroups.
const CGROUP_BASE: &str = "/sys/fs/cgroup/silo";

/// Base path for pinned BPF programs.
const PIN_BASE: &str = "/sys/fs/bpf/silo";

/// All BPF program names (must match function names in silo-ebpf/src/main.rs).
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
];

fn attach_type_for(name: &str) -> CgroupSockAddrAttachType {
    use CgroupSockAddrAttachType::*;
    match name {
        "silo_bind4" => Bind4,
        "silo_bind6" => Bind6,
        "silo_connect4" => Connect4,
        "silo_connect6" => Connect6,
        "silo_sendmsg4" => UDPSendMsg4,
        "silo_sendmsg6" => UDPSendMsg6,
        "silo_recvmsg4" => UDPRecvMsg4,
        "silo_recvmsg6" => UDPRecvMsg6,
        "silo_getpeername4" => GetPeerName4,
        "silo_getpeername6" => GetPeerName6,
        _ => unreachable!("unknown BPF program name: {name}"),
    }
}

/// Internal state depending on how programs were loaded.
enum SessionMode {
    /// Programs loaded from embedded bytes. Ebpf object owns everything.
    /// When dropped, programs are unloaded and maps are destroyed.
    Embedded(Ebpf),
    /// Programs loaded from pinned paths. Config map handle for cleanup.
    /// On drop, removes our cgroup_id entry from the shared config map.
    Pinned {
        _programs: Vec<CgroupSockAddr>,
        config_map: Option<HashMap<aya::maps::MapData, u64, u32>>,
    },
}

/// Manages an eBPF session: cgroup + attached BPF programs + config map.
pub struct EbpfSession {
    cgroup_path: PathBuf,
    cgroup_id: u64,
    mode: SessionMode,
}

impl EbpfSession {
    /// Create a new eBPF session.
    ///
    /// 1. Creates a cgroup under `/sys/fs/cgroup/silo/{session_id}/`
    /// 2. Loads BPF programs (from pinned paths or embedded bytes)
    /// 3. Writes `(cgroup_id, silo_ip)` to the BPF config map
    /// 4. Attaches all programs to the cgroup
    pub fn new(session_id: &str, silo_ip: Ipv4Addr) -> eyre::Result<Self> {
        let cgroup_path = PathBuf::from(CGROUP_BASE).join(session_id);
        fs::create_dir_all(&cgroup_path)
            .with_context(|| format!("failed to create cgroup at {}", cgroup_path.display()))?;

        let cgroup_id = fs::metadata(&cgroup_path)
            .with_context(|| format!("failed to stat cgroup {}", cgroup_path.display()))?
            .ino();

        let cgroup_fd = fs::File::open(&cgroup_path)
            .with_context(|| format!("failed to open cgroup {}", cgroup_path.display()))?;

        let ip_nbo = u32::from(silo_ip).to_be();

        if pinned_programs_exist() {
            Self::new_from_pinned(cgroup_path, cgroup_id, &cgroup_fd, ip_nbo)
        } else {
            Self::new_from_embedded(cgroup_path, cgroup_id, &cgroup_fd, ip_nbo)
        }
    }

    /// Load programs from embedded bytes (requires CAP_BPF + CAP_NET_ADMIN).
    fn new_from_embedded(
        cgroup_path: PathBuf,
        cgroup_id: u64,
        cgroup_fd: &fs::File,
        ip_nbo: u32,
    ) -> eyre::Result<Self> {
        let mut bpf = Ebpf::load(EBPF_BYTES).context("failed to load eBPF programs")?;

        // Write (cgroup_id, silo_ip) to the config map
        let mut config: HashMap<_, u64, u32> = HashMap::try_from(
            bpf.map_mut("SILO_CONFIG")
                .context("BPF map SILO_CONFIG not found")?,
        )
        .context("failed to create HashMap from SILO_CONFIG")?;
        config
            .insert(cgroup_id, ip_nbo, 0)
            .context("failed to write silo IP to BPF map")?;

        // Attach all programs to the cgroup
        for name in PROGRAM_NAMES {
            let prog: &mut CgroupSockAddr = bpf
                .program_mut(name)
                .with_context(|| format!("BPF program {name} not found"))?
                .try_into()
                .with_context(|| format!("BPF program {name} is not a CgroupSockAddr program"))?;
            prog.load()
                .with_context(|| format!("failed to load BPF program {name}"))?;
            prog.attach(cgroup_fd, CgroupAttachMode::Single)
                .with_context(|| format!("failed to attach BPF program {name}"))?;
        }

        Ok(Self {
            cgroup_path,
            cgroup_id,
            mode: SessionMode::Embedded(bpf),
        })
    }

    /// Load programs from pinned paths (rootless after `silo setup-ebpf`).
    fn new_from_pinned(
        cgroup_path: PathBuf,
        cgroup_id: u64,
        cgroup_fd: &fs::File,
        ip_nbo: u32,
    ) -> eyre::Result<Self> {
        // Open the pinned config map and write our (cgroup_id, silo_ip) entry
        let map_data = aya::maps::MapData::from_pin(PathBuf::from(PIN_BASE).join("SILO_CONFIG"))
            .context("failed to open pinned SILO_CONFIG map")?;
        let map = aya::maps::Map::HashMap(map_data);
        let mut config: HashMap<_, u64, u32> =
            HashMap::try_from(map).context("failed to create HashMap from pinned map")?;
        config
            .insert(cgroup_id, ip_nbo, 0)
            .context("failed to write silo IP to pinned BPF map")?;

        // Open and attach each pinned program
        let mut programs = Vec::new();
        for name in PROGRAM_NAMES {
            let pin_path = PathBuf::from(PIN_BASE).join(name);
            let mut prog = CgroupSockAddr::from_pin(&pin_path, attach_type_for(name))
                .with_context(|| format!("failed to open pinned BPF program {name}"))?;
            prog.attach(cgroup_fd, CgroupAttachMode::Single)
                .with_context(|| format!("failed to attach pinned BPF program {name}"))?;
            programs.push(prog);
        }

        Ok(Self {
            cgroup_path,
            cgroup_id,
            mode: SessionMode::Pinned {
                _programs: programs,
                config_map: Some(config),
            },
        })
    }

    /// Write a PID into this session's cgroup, making it (and its children)
    /// subject to the attached BPF programs.
    pub fn add_pid(&self, pid: u32) -> eyre::Result<()> {
        let procs_path = self.cgroup_path.join("cgroup.procs");
        fs::write(&procs_path, pid.to_string())
            .with_context(|| format!("failed to write PID to {}", procs_path.display()))
    }

    /// The cgroup directory for this session.
    pub fn cgroup_path(&self) -> &Path {
        &self.cgroup_path
    }
}

impl Drop for EbpfSession {
    fn drop(&mut self) {
        // For pinned mode, remove our entry from the shared config map
        if let SessionMode::Pinned { config_map, .. } = &mut self.mode {
            if let Some(mut config) = config_map.take() {
                let _ = config.remove(&self.cgroup_id);
            }
        }
        // For embedded mode, the Ebpf object drop destroys maps and programs.

        // Links are dropped automatically, detaching programs.
        // Try to remove the cgroup directory (only succeeds if empty).
        let _ = fs::remove_dir(&self.cgroup_path);
    }
}

// --- Detection ---

/// Check if the eBPF backend is available on this system.
///
/// Requires: Linux, kernel >= 5.8, cgroup v2 mounted.
/// Also needs CAP_BPF + CAP_NET_ADMIN, or pre-pinned BPF programs.
pub fn ebpf_available() -> bool {
    // No embedded bytecode (built without nightly toolchain)
    if EBPF_BYTES.is_empty() {
        return false;
    }

    // cgroup v2 must be mounted
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return false;
    }

    // Kernel >= 5.8 for full cgroup/sock_addr support
    if !kernel_version_sufficient() {
        return false;
    }

    // Either pinned programs exist or we have capabilities
    pinned_programs_exist() || has_bpf_caps()
}

/// Check if programs are pinned at /sys/fs/bpf/silo/.
fn pinned_programs_exist() -> bool {
    Path::new(PIN_BASE).join("silo_bind4").exists()
}

/// Select the appropriate backend based on environment and availability.
pub fn select_backend() -> silo::Backend {
    // Check for explicit override
    if let Ok(val) = std::env::var("SILO_BACKEND") {
        match val.as_str() {
            "ebpf" => return silo::Backend::Ebpf,
            "preload" => {
                return match super::commands::run::find_bind_lib() {
                    Ok(lib_path) => silo::Backend::LdPreload { lib_path },
                    Err(_) => silo::Backend::None,
                };
            }
            _ => {} // ignore invalid values, fall through to auto-detect
        }
    }

    if ebpf_available() {
        silo::Backend::Ebpf
    } else {
        match super::commands::run::find_bind_lib() {
            Ok(lib_path) => silo::Backend::LdPreload { lib_path },
            Err(_) => silo::Backend::None,
        }
    }
}

// --- Setup (pinning) ---

/// Load BPF programs and pin them to `/sys/fs/bpf/silo/`.
///
/// This allows subsequent `silo run` invocations to attach programs
/// without root privileges.
pub fn setup_pinned() -> eyre::Result<()> {
    fs::create_dir_all(PIN_BASE).with_context(|| format!("failed to create {PIN_BASE}"))?;

    let mut bpf = Ebpf::load(EBPF_BYTES).context("failed to load eBPF programs")?;

    for name in PROGRAM_NAMES {
        let prog: &mut CgroupSockAddr = bpf
            .program_mut(name)
            .with_context(|| format!("BPF program {name} not found"))?
            .try_into()
            .with_context(|| format!("BPF program {name} is not a CgroupSockAddr program"))?;
        prog.load()
            .with_context(|| format!("failed to load BPF program {name}"))?;
        let pin_path = PathBuf::from(PIN_BASE).join(name);
        prog.pin(&pin_path)
            .with_context(|| format!("failed to pin BPF program {name}"))?;
    }

    // Pin the config map too
    let map = bpf
        .map_mut("SILO_CONFIG")
        .context("BPF map SILO_CONFIG not found")?;
    map.pin(PathBuf::from(PIN_BASE).join("SILO_CONFIG"))
        .context("failed to pin SILO_CONFIG map")?;

    Ok(())
}

// --- Helpers ---

fn kernel_version_sufficient() -> bool {
    let Ok(ver) = fs::read_to_string("/proc/version") else {
        return false;
    };
    let Some(rest) = ver.strip_prefix("Linux version ") else {
        return false;
    };
    let parts: Vec<&str> = rest.split(|c: char| !c.is_ascii_digit()).collect();
    if parts.len() < 2 {
        return false;
    }
    let major: u32 = parts[0].parse().unwrap_or(0);
    let minor: u32 = parts[1].parse().unwrap_or(0);
    (major, minor) >= (5, 8)
}

fn has_bpf_caps() -> bool {
    // Simple check: are we root?
    // A more thorough check would parse /proc/self/status for CapEff
    // and check CAP_BPF (bit 39) + CAP_NET_ADMIN (bit 12).
    unsafe { libc::geteuid() == 0 }
}

/// Embedded eBPF bytecode, compiled from crates/silo-ebpf.
/// On macOS this constant is never used (the module is cfg-gated).
static EBPF_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/silo-ebpf"));
