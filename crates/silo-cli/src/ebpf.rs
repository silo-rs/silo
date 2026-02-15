#![allow(unsafe_code)]

use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use aya::Ebpf;
use aya::maps::HashMap;
use aya::programs::{CgroupAttachMode, CgroupSockAddr, CgroupSockAddrAttachType};
use eyre::{Context, ContextCompat};

const CGROUP_BASE: &str = "/sys/fs/cgroup/silo";
const PIN_BASE: &str = "/sys/fs/bpf/silo";
pub const PROGRAM_NAMES: &[&str] = &[
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
        "silo_getsockname4" => GetSockName4,
        "silo_getsockname6" => GetSockName6,
        _ => unreachable!("unknown BPF program name: {name}"),
    }
}

enum SessionMode {
    Embedded(#[allow(dead_code)] Ebpf),
    Pinned {
        _programs: Vec<CgroupSockAddr>,
        config_map: Option<HashMap<aya::maps::MapData, u64, u32>>,
    },
}

pub struct EbpfSession {
    cgroup_path: PathBuf,
    cgroup_id: u64,
    mode: SessionMode,
}

impl EbpfSession {
    pub fn new(session_id: &str, silo_ip: Ipv4Addr) -> eyre::Result<Self> {
        auto_prune();

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

    fn new_from_embedded(
        cgroup_path: PathBuf,
        cgroup_id: u64,
        cgroup_fd: &fs::File,
        ip_nbo: u32,
    ) -> eyre::Result<Self> {
        let mut bpf = Ebpf::load(EBPF_BYTES).context("failed to load eBPF programs")?;

        let mut config: HashMap<_, u64, u32> = HashMap::try_from(
            bpf.map_mut("SILO_CONFIG")
                .context("BPF map SILO_CONFIG not found")?,
        )
        .context("failed to create HashMap from SILO_CONFIG")?;
        config
            .insert(cgroup_id, ip_nbo, 0)
            .context("failed to write silo IP to BPF map")?;

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

    fn new_from_pinned(
        cgroup_path: PathBuf,
        cgroup_id: u64,
        cgroup_fd: &fs::File,
        ip_nbo: u32,
    ) -> eyre::Result<Self> {
        let map_data = aya::maps::MapData::from_pin(PathBuf::from(PIN_BASE).join("SILO_CONFIG"))
            .context("failed to open pinned SILO_CONFIG map")?;
        let map = aya::maps::Map::HashMap(map_data);
        let mut config: HashMap<_, u64, u32> =
            HashMap::try_from(map).context("failed to create HashMap from pinned map")?;
        config
            .insert(cgroup_id, ip_nbo, 0)
            .context("failed to write silo IP to pinned BPF map")?;

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

    pub fn add_pid(&self, pid: u32) -> eyre::Result<()> {
        let procs_path = self.cgroup_path.join("cgroup.procs");
        fs::write(&procs_path, pid.to_string())
            .with_context(|| format!("failed to write PID to {}", procs_path.display()))
    }

    #[allow(dead_code)]
    pub fn cgroup_path(&self) -> &Path {
        &self.cgroup_path
    }
}

impl silo::BackendSession for EbpfSession {
    fn prepare(&self, _cmd: &mut std::process::Command) -> silo::error::Result<()> {
        self.add_pid(std::process::id())
            .map_err(|e| silo::Error::Backend(e.into()))
    }

    fn name(&self) -> &str {
        "ebpf"
    }
}

impl Drop for EbpfSession {
    fn drop(&mut self) {
        if let SessionMode::Pinned { config_map, .. } = &mut self.mode
            && let Some(mut config) = config_map.take()
        {
            let _ = config.remove(&self.cgroup_id);
        }
        let _ = fs::remove_dir(&self.cgroup_path);
    }
}

pub fn ebpf_available() -> bool {
    if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return false;
    }

    if !kernel_version_sufficient() {
        return false;
    }

    if pinned_programs_exist() {
        return true;
    }

    !EBPF_BYTES.is_empty() && has_bpf_caps()
}

fn pinned_programs_exist() -> bool {
    Path::new(PIN_BASE).join("silo_bind4").exists()
}

pub enum SelectedBackend {
    Ebpf,
    Preload(PathBuf),
    None,
}

pub fn select_backend() -> SelectedBackend {
    if let Ok(val) = std::env::var("SILO_BACKEND") {
        match val.as_str() {
            "ebpf" => {
                if ebpf_available() {
                    return SelectedBackend::Ebpf;
                }
                tracing::warn!(
                    "SILO_BACKEND=ebpf requested but eBPF is not available, falling back to auto-detect"
                );
            }
            "preload" => {
                return super::commands::run::find_bind_lib()
                    .map_or(SelectedBackend::None, SelectedBackend::Preload);
            }
            other => {
                tracing::warn!("unknown SILO_BACKEND={other:?}, falling back to auto-detect");
            }
        }
    }

    if ebpf_available() {
        SelectedBackend::Ebpf
    } else {
        super::commands::run::find_bind_lib()
            .map_or(SelectedBackend::None, SelectedBackend::Preload)
    }
}

pub fn setup_pinned() -> eyre::Result<()> {
    eyre::ensure!(
        !EBPF_BYTES.is_empty(),
        "no embedded eBPF bytecode. Rebuild silo with nightly toolchain and bpf-linker installed"
    );

    if pinned_programs_exist() {
        teardown_pinned_inner();
    }

    setup_cgroup_base().context("failed to set up cgroup delegation")?;

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

    let map = bpf
        .map_mut("SILO_CONFIG")
        .context("BPF map SILO_CONFIG not found")?;
    map.pin(PathBuf::from(PIN_BASE).join("SILO_CONFIG"))
        .context("failed to pin SILO_CONFIG map")?;

    set_pin_permissions();

    Ok(())
}

pub fn teardown_pinned() -> eyre::Result<()> {
    eyre::ensure!(
        pinned_programs_exist(),
        "no pinned eBPF programs found at {PIN_BASE}"
    );
    teardown_pinned_inner();
    Ok(())
}

fn set_pin_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let (uid, gid) = sudo_caller_ids();

    let _ = fs::set_permissions(PIN_BASE, fs::Permissions::from_mode(0o755));
    let _ = chown_path(PIN_BASE, uid, gid);

    for name in PROGRAM_NAMES {
        let _ = fs::set_permissions(
            PathBuf::from(PIN_BASE).join(name),
            fs::Permissions::from_mode(0o644),
        );
    }

    let config_path = PathBuf::from(PIN_BASE).join("SILO_CONFIG");
    let _ = fs::set_permissions(&config_path, fs::Permissions::from_mode(0o660));
    let _ = chown_path(&config_path, uid, gid);
}

fn teardown_pinned_inner() {
    for name in PROGRAM_NAMES {
        let _ = fs::remove_file(PathBuf::from(PIN_BASE).join(name));
    }
    let _ = fs::remove_file(PathBuf::from(PIN_BASE).join("SILO_CONFIG"));
    let _ = fs::remove_dir(PIN_BASE);
}

pub fn prune_config_map() -> usize {
    if !pinned_programs_exist() {
        return 0;
    }

    let Ok(map_data) = aya::maps::MapData::from_pin(PathBuf::from(PIN_BASE).join("SILO_CONFIG"))
    else {
        return 0;
    };
    let map = aya::maps::Map::HashMap(map_data);
    let Ok(mut config) = HashMap::<_, u64, u32>::try_from(map) else {
        return 0;
    };

    let live_cgroups = live_cgroup_ids(Path::new(CGROUP_BASE));
    let stale_keys: Vec<u64> = config
        .keys()
        .flatten()
        .filter(|cgroup_id| !live_cgroups.contains(cgroup_id))
        .collect();

    let count = stale_keys.len();
    for key in stale_keys {
        let _ = config.remove(&key);
    }
    count
}

fn live_cgroup_ids(base: &Path) -> HashSet<u64> {
    let Ok(entries) = fs::read_dir(base) else {
        return HashSet::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_dir() {
                return None;
            }
            let procs = path.join("cgroup.procs");
            let has_procs = fs::read_to_string(&procs)
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
            if !has_procs {
                return None;
            }
            fs::metadata(&path).ok().map(|m| m.ino())
        })
        .collect()
}

fn setup_cgroup_base() -> eyre::Result<()> {
    fs::create_dir_all(CGROUP_BASE).with_context(|| format!("failed to create {CGROUP_BASE}"))?;

    let (uid, gid) = sudo_caller_ids();
    chown_path(CGROUP_BASE, uid, gid).with_context(|| format!("failed to chown {CGROUP_BASE}"))?;

    for name in &["cgroup.procs", "cgroup.threads"] {
        let path = PathBuf::from(CGROUP_BASE).join(name);
        if path.exists() {
            let _ = chown_path(&path, uid, gid);
        }
    }

    Ok(())
}

pub fn prune_stale_cgroups() -> usize {
    let cgroup_base = Path::new(CGROUP_BASE);
    if !cgroup_base.exists() {
        return 0;
    }

    let Ok(entries) = fs::read_dir(cgroup_base) else {
        return 0;
    };

    let mut removed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let procs = path.join("cgroup.procs");
        let is_empty = fs::read_to_string(&procs)
            .map(|s| s.trim().is_empty())
            .unwrap_or(false);
        if is_empty && fs::remove_dir(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

fn auto_prune() {
    prune_stale_cgroups();
    prune_config_map();
}

pub fn embedded_bytes_empty() -> bool {
    EBPF_BYTES.is_empty()
}

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
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }

    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return false;
    };
    let Some(cap_line) = status.lines().find(|l| l.starts_with("CapEff:\t")) else {
        return false;
    };
    let Some(hex) = cap_line.strip_prefix("CapEff:\t") else {
        return false;
    };
    let Ok(caps) = u64::from_str_radix(hex.trim(), 16) else {
        return false;
    };

    const CAP_NET_ADMIN: u64 = 1 << 12;
    const CAP_BPF: u64 = 1 << 39;
    caps & (CAP_NET_ADMIN | CAP_BPF) == (CAP_NET_ADMIN | CAP_BPF)
}

fn sudo_caller_ids() -> (u32, u32) {
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    (uid, gid)
}

fn chown_path<P: AsRef<Path>>(path: P, uid: u32, gid: u32) -> eyre::Result<()> {
    let c_path =
        CString::new(path.as_ref().as_os_str().as_bytes()).context("path contains null byte")?;
    let ret = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if ret != 0 {
        Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to chown {}", path.as_ref().display()))?;
    }
    Ok(())
}

static EBPF_BYTES: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/silo-ebpf"));
