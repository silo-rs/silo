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

#[derive(Debug, Clone, Copy)]
pub enum BpfProgram {
    Bind4,
    Bind6,
    Connect4,
    Connect6,
    SendMsg4,
    SendMsg6,
    RecvMsg4,
    RecvMsg6,
    GetPeerName4,
    GetPeerName6,
    GetSockName4,
    GetSockName6,
}

impl BpfProgram {
    pub const ALL: &[Self] = &[
        Self::Bind4,
        Self::Bind6,
        Self::Connect4,
        Self::Connect6,
        Self::SendMsg4,
        Self::SendMsg6,
        Self::RecvMsg4,
        Self::RecvMsg6,
        Self::GetPeerName4,
        Self::GetPeerName6,
        Self::GetSockName4,
        Self::GetSockName6,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Bind4 => "silo_bind4",
            Self::Bind6 => "silo_bind6",
            Self::Connect4 => "silo_connect4",
            Self::Connect6 => "silo_connect6",
            Self::SendMsg4 => "silo_sendmsg4",
            Self::SendMsg6 => "silo_sendmsg6",
            Self::RecvMsg4 => "silo_recvmsg4",
            Self::RecvMsg6 => "silo_recvmsg6",
            Self::GetPeerName4 => "silo_getpeername4",
            Self::GetPeerName6 => "silo_getpeername6",
            Self::GetSockName4 => "silo_getsockname4",
            Self::GetSockName6 => "silo_getsockname6",
        }
    }

    pub const fn attach_type(self) -> CgroupSockAddrAttachType {
        use CgroupSockAddrAttachType::*;
        match self {
            Self::Bind4 => Bind4,
            Self::Bind6 => Bind6,
            Self::Connect4 => Connect4,
            Self::Connect6 => Connect6,
            Self::SendMsg4 => UDPSendMsg4,
            Self::SendMsg6 => UDPSendMsg6,
            Self::RecvMsg4 => UDPRecvMsg4,
            Self::RecvMsg6 => UDPRecvMsg6,
            Self::GetPeerName4 => GetPeerName4,
            Self::GetPeerName6 => GetPeerName6,
            Self::GetSockName4 => GetSockName4,
            Self::GetSockName6 => GetSockName6,
        }
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

        for &prog_kind in BpfProgram::ALL {
            let name = prog_kind.name();
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
        for &prog_kind in BpfProgram::ALL {
            let name = prog_kind.name();
            let pin_path = PathBuf::from(PIN_BASE).join(name);
            let mut prog = CgroupSockAddr::from_pin(&pin_path, prog_kind.attach_type())
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

    for &prog_kind in BpfProgram::ALL {
        let name = prog_kind.name();
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
    let Ok((uid, gid)) = sudo_caller_ids() else {
        return;
    };

    let _ = fs::set_permissions(PIN_BASE, fs::Permissions::from_mode(0o755));
    let _ = chown_path(PIN_BASE, uid, gid);

    for &prog_kind in BpfProgram::ALL {
        let _ = fs::set_permissions(
            PathBuf::from(PIN_BASE).join(prog_kind.name()),
            fs::Permissions::from_mode(0o644),
        );
    }

    let config_path = PathBuf::from(PIN_BASE).join("SILO_CONFIG");
    let _ = fs::set_permissions(&config_path, fs::Permissions::from_mode(0o660));
    let _ = chown_path(&config_path, uid, gid);
}

fn teardown_pinned_inner() {
    for &prog_kind in BpfProgram::ALL {
        let _ = fs::remove_file(PathBuf::from(PIN_BASE).join(prog_kind.name()));
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

    let (uid, gid) = sudo_caller_ids().context("failed to determine caller identity")?;
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

fn sudo_caller_ids() -> eyre::Result<(u32, u32)> {
    let euid = unsafe { libc::geteuid() };
    let uid = match std::env::var("SUDO_UID") {
        Ok(s) => s
            .parse::<u32>()
            .with_context(|| format!("SUDO_UID={s:?} is not a valid uid"))?,
        Err(_) if euid == 0 => 0,
        Err(_) => eyre::bail!("not running as root and SUDO_UID is not set"),
    };
    let gid = match std::env::var("SUDO_GID") {
        Ok(s) => s
            .parse::<u32>()
            .with_context(|| format!("SUDO_GID={s:?} is not a valid gid"))?,
        Err(_) if euid == 0 => 0,
        Err(_) => eyre::bail!("not running as root and SUDO_GID is not set"),
    };
    Ok((uid, gid))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpf_program_all_is_exhaustive() {
        assert_eq!(BpfProgram::ALL.len(), 12);
        let names: Vec<&str> = BpfProgram::ALL.iter().map(|p| p.name()).collect();
        let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
        assert_eq!(names.len(), unique.len(), "duplicate program names");
    }

    #[test]
    fn bpf_program_names_match_convention() {
        for &prog in BpfProgram::ALL {
            assert!(
                prog.name().starts_with("silo_"),
                "program name {:?} must start with silo_",
                prog.name()
            );
        }
    }

    #[test]
    fn sudo_caller_ids_no_sudo_non_root() {
        // When not running as root and SUDO_UID is not set, should error
        if unsafe { libc::geteuid() } != 0 {
            unsafe {
                std::env::remove_var("SUDO_UID");
                std::env::remove_var("SUDO_GID");
            }
            let result = sudo_caller_ids();
            assert!(
                result.is_err(),
                "should error when not root and no SUDO_UID"
            );
        }
    }

    #[test]
    fn sudo_caller_ids_with_valid_env() {
        unsafe {
            std::env::set_var("SUDO_UID", "1000");
            std::env::set_var("SUDO_GID", "1000");
        }
        let result = sudo_caller_ids();
        assert_eq!(result.unwrap(), (1000, 1000));
        unsafe {
            std::env::remove_var("SUDO_UID");
            std::env::remove_var("SUDO_GID");
        }
    }

    #[test]
    fn sudo_caller_ids_with_invalid_env() {
        unsafe {
            std::env::set_var("SUDO_UID", "notanumber");
            std::env::set_var("SUDO_GID", "1000");
        }
        let result = sudo_caller_ids();
        assert!(result.is_err(), "should error on unparsable SUDO_UID");
        unsafe {
            std::env::remove_var("SUDO_UID");
            std::env::remove_var("SUDO_GID");
        }
    }
}
