pub mod rewrite;

pub(crate) mod addr;
mod platform;
pub(crate) mod probe;

#[cfg(target_os = "macos")]
pub(crate) mod sip;

use std::env;
use std::os::raw::c_int;
use std::sync::OnceLock;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    #[link_name = "bind"]
    pub(crate) fn real_bind(fd: c_int, addr: *const libc::sockaddr, len: libc::socklen_t) -> c_int;

    #[link_name = "connect"]
    pub(crate) fn real_connect(
        fd: c_int,
        addr: *const libc::sockaddr,
        len: libc::socklen_t,
    ) -> c_int;

    #[link_name = "getifaddrs"]
    pub(crate) fn real_getifaddrs(ifap: *mut *mut libc::ifaddrs) -> c_int;

    #[link_name = "posix_spawn"]
    pub(crate) fn real_posix_spawn(
        pid: *mut libc::pid_t,
        path: *const libc::c_char,
        file_actions: *const libc::c_void,
        attrp: *const libc::c_void,
        argv: *const *mut libc::c_char,
        envp: *const *mut libc::c_char,
    ) -> c_int;

    #[link_name = "posix_spawnp"]
    pub(crate) fn real_posix_spawnp(
        pid: *mut libc::pid_t,
        file: *const libc::c_char,
        file_actions: *const libc::c_void,
        attrp: *const libc::c_void,
        argv: *const *mut libc::c_char,
        envp: *const *mut libc::c_char,
    ) -> c_int;

    #[link_name = "execve"]
    pub(crate) fn real_execve(
        path: *const libc::c_char,
        argv: *const *const libc::c_char,
        envp: *const *const libc::c_char,
    ) -> c_int;

    #[link_name = "sendto"]
    pub(crate) fn real_sendto(
        fd: c_int,
        buf: *const libc::c_void,
        len: libc::size_t,
        flags: c_int,
        dest_addr: *const libc::sockaddr,
        addrlen: libc::socklen_t,
    ) -> libc::ssize_t;

    #[link_name = "sendmsg"]
    pub(crate) fn real_sendmsg(fd: c_int, msg: *const libc::msghdr, flags: c_int) -> libc::ssize_t;
}

static SILO_IP: OnceLock<Option<u32>> = OnceLock::new();
static CONNECT_ENABLED: OnceLock<bool> = OnceLock::new();

#[cfg(target_os = "macos")]
static DEBUG: OnceLock<bool> = OnceLock::new();

pub(crate) fn get_silo_ip() -> Option<u32> {
    *SILO_IP.get_or_init(|| {
        let val = env::var("SILO_IP").ok()?;
        rewrite::parse_silo_ip(&val)
    })
}

pub(crate) fn connect_enabled() -> bool {
    *CONNECT_ENABLED.get_or_init(|| env::var("SILO_CONNECT").map(|v| v != "0").unwrap_or(true))
}

#[cfg(target_os = "macos")]
pub(crate) fn debug_enabled() -> bool {
    *DEBUG.get_or_init(|| env::var("SILO_BIND_DEBUG").is_ok())
}

pub(crate) unsafe fn errno_ptr() -> *mut c_int {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::__errno_location() }
    }
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::__error() }
    }
}

#[cfg(target_os = "macos")]
#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static INIT_FN: unsafe extern "C" fn() = {
    unsafe extern "C" fn init() {
        let _ = get_silo_ip();
        let _ = debug_enabled();

        if debug_enabled() {
            let pid = std::process::id();
            let silo_ip = env::var("SILO_IP").unwrap_or_default();
            eprintln!("[silo-bind] loaded pid={pid} SILO_IP={silo_ip}");
        }
    }
    init
};
