pub mod rewrite;

use std::env;
use std::net::Ipv4Addr;
use std::os::raw::c_int;
use std::sync::OnceLock;

#[cfg(target_os = "macos")]
use std::ffi::{CStr, CString};

use libc::{AF_INET, sockaddr, sockaddr_in, socklen_t};

static SILO_IP: OnceLock<Option<u32>> = OnceLock::new();

#[cfg(target_os = "macos")]
static DEBUG: OnceLock<bool> = OnceLock::new();

#[cfg(target_os = "macos")]
unsafe extern "C" {
    #[link_name = "bind"]
    fn real_bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int;

    #[link_name = "connect"]
    fn real_connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int;

    #[link_name = "getifaddrs"]
    fn real_getifaddrs(ifap: *mut *mut libc::ifaddrs) -> c_int;
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    #[link_name = "posix_spawn"]
    fn real_posix_spawn(
        pid: *mut libc::pid_t,
        path: *const libc::c_char,
        file_actions: *const libc::c_void,
        attrp: *const libc::c_void,
        argv: *const *mut libc::c_char,
        envp: *const *mut libc::c_char,
    ) -> c_int;

    #[link_name = "posix_spawnp"]
    fn real_posix_spawnp(
        pid: *mut libc::pid_t,
        file: *const libc::c_char,
        file_actions: *const libc::c_void,
        attrp: *const libc::c_void,
        argv: *const *mut libc::c_char,
        envp: *const *mut libc::c_char,
    ) -> c_int;

    #[link_name = "execve"]
    fn real_execve(
        path: *const libc::c_char,
        argv: *const *const libc::c_char,
        envp: *const *const libc::c_char,
    ) -> c_int;

    #[link_name = "sendto"]
    fn real_sendto(
        fd: c_int,
        buf: *const libc::c_void,
        len: libc::size_t,
        flags: c_int,
        dest_addr: *const sockaddr,
        addrlen: socklen_t,
    ) -> libc::ssize_t;

    #[link_name = "sendmsg"]
    fn real_sendmsg(fd: c_int, msg: *const libc::msghdr, flags: c_int) -> libc::ssize_t;
}

unsafe fn read_sa_family(addr: *const sockaddr) -> Option<c_int> {
    if addr.is_null() {
        return None;
    }
    Some(unsafe { (*addr).sa_family } as c_int)
}

unsafe fn rewrite_sockaddr_v4(addr: *const sockaddr, silo_ip: u32, match_any: bool) {
    let sin = addr as *mut sockaddr_in;
    let s_addr = unsafe { (*sin).sin_addr.s_addr };
    if let Some(new_addr) = rewrite::rewrite_ipv4_addr(s_addr, silo_ip, match_any) {
        unsafe { (*sin).sin_addr.s_addr = new_addr };
    }
}

unsafe fn rewrite_sockaddr_v6(addr: *const sockaddr, silo_ip: u32, match_any: bool) {
    let sin6 = addr as *mut libc::sockaddr_in6;
    let s6_addr = unsafe { (*sin6).sin6_addr.s6_addr };
    if let Some(new_addr) = rewrite::rewrite_ipv6_addr(s6_addr, silo_ip, match_any) {
        unsafe { (*sin6).sin6_addr.s6_addr = new_addr };
    }
}

unsafe fn rewrite_addr(addr: *const sockaddr, match_any: bool) {
    let Some(family) = (unsafe { read_sa_family(addr) }) else {
        return;
    };
    let Some(silo_ip) = get_silo_ip() else {
        return;
    };

    if family == AF_INET {
        unsafe { rewrite_sockaddr_v4(addr, silo_ip, match_any) };
    }

    if family == libc::AF_INET6 as c_int {
        unsafe { rewrite_sockaddr_v6(addr, silo_ip, match_any) };
    }
}

unsafe fn errno_ptr() -> *mut c_int {
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
unsafe fn call_real_bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    unsafe { real_bind(fd, addr, len) }
}

#[cfg(target_os = "linux")]
unsafe fn call_real_bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    static REAL_BIND: OnceLock<unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int> =
        OnceLock::new();
    let f = *REAL_BIND.get_or_init(|| unsafe {
        let ptr = libc::dlsym(libc::RTLD_NEXT, c"bind".as_ptr());
        assert!(!ptr.is_null(), "silo-bind: dlsym failed to resolve bind");
        std::mem::transmute(ptr)
    });
    unsafe { f(fd, addr, len) }
}

unsafe fn probe_has_listener(fd: c_int, silo_ip: u32, port: u16) -> bool {
    let saved_errno = unsafe { *errno_ptr() };

    let mut sock_type: c_int = libc::SOCK_STREAM;
    let mut optlen: socklen_t = std::mem::size_of::<c_int>() as socklen_t;
    unsafe {
        if libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut sock_type as *mut _ as *mut libc::c_void,
            &mut optlen,
        ) != 0
        {
            sock_type = libc::SOCK_STREAM;
        }
    }

    let probe_fd = unsafe { libc::socket(AF_INET, sock_type, 0) };
    if probe_fd < 0 {
        unsafe { *errno_ptr() = saved_errno };
        return false;
    }

    let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "macos")]
    {
        sin.sin_len = std::mem::size_of::<sockaddr_in>() as u8;
    }
    sin.sin_family = AF_INET as _;
    sin.sin_port = port;
    sin.sin_addr.s_addr = silo_ip;

    let ret = unsafe {
        call_real_bind(
            probe_fd,
            &sin as *const sockaddr_in as *const sockaddr,
            std::mem::size_of::<sockaddr_in>() as socklen_t,
        )
    };

    let has_listener = ret < 0 && unsafe { *errno_ptr() } == libc::EADDRINUSE;
    unsafe { libc::close(probe_fd) };
    unsafe { *errno_ptr() = saved_errno };

    has_listener
}

unsafe fn rewrite_connect_addr(fd: c_int, addr: *const sockaddr) {
    let Some(family) = (unsafe { read_sa_family(addr) }) else {
        return;
    };
    let Some(silo_ip) = get_silo_ip() else {
        return;
    };

    if family == AF_INET {
        let sin = addr as *mut sockaddr_in;
        let s_addr = unsafe { (*sin).sin_addr.s_addr };
        let localhost_be = u32::from(Ipv4Addr::LOCALHOST).to_be();
        if s_addr == localhost_be {
            let port = unsafe { (*sin).sin_port };
            if unsafe { probe_has_listener(fd, silo_ip, port) } {
                unsafe { (*sin).sin_addr.s_addr = silo_ip };
            }
        }
    }

    #[cfg(target_os = "linux")]
    if family == libc::AF_INET6 as c_int {
        let sin6 = addr as *mut libc::sockaddr_in6;
        let s6_addr = unsafe { (*sin6).sin6_addr.s6_addr };
        if s6_addr == rewrite::V6_LOOPBACK {
            let port = unsafe { (*sin6).sin6_port };
            if unsafe { probe_has_listener(fd, silo_ip, port) } {
                let new_addr = rewrite::ipv4_mapped_v6(silo_ip);
                unsafe { (*sin6).sin6_addr.s6_addr = new_addr };
            }
        }
    }
}

fn get_silo_ip() -> Option<u32> {
    *SILO_IP.get_or_init(|| {
        let val = env::var("SILO_IP").ok()?;
        rewrite::parse_silo_ip(&val)
    })
}

unsafe fn hide_other_silo_aliases(ifap: *mut libc::ifaddrs) {
    let Some(silo_ip) = get_silo_ip() else {
        return;
    };

    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            let family = unsafe { (*ifa.ifa_addr).sa_family } as c_int;
            if family == AF_INET {
                let sin = ifa.ifa_addr as *mut sockaddr_in;
                let s_addr = unsafe { (*sin).sin_addr.s_addr };
                if let Some(new_addr) = rewrite::hide_alias(s_addr, silo_ip) {
                    unsafe { (*sin).sin_addr.s_addr = new_addr };
                }
            }
        }
        cur = unsafe { (*cur).ifa_next };
    }
}

#[cfg(target_os = "macos")]
fn debug_enabled() -> bool {
    *DEBUG.get_or_init(|| env::var("SILO_BIND_DEBUG").is_ok())
}

#[cfg(target_os = "macos")]
fn is_sip_path(path: &str) -> bool {
    path.starts_with("/usr/bin/")
        || path.starts_with("/bin/")
        || path.starts_with("/sbin/")
        || path.starts_with("/usr/sbin/")
}

#[cfg(target_os = "macos")]
fn find_non_sip_in_path(name: &str) -> Option<CString> {
    let fallbacks: &[&str] = match name {
        "sh" => &["sh", "bash", "zsh"],
        _ => &[],
    };
    let names = if fallbacks.is_empty() {
        std::slice::from_ref(&name)
    } else {
        fallbacks
    };

    let path_var = env::var("PATH").ok()?;
    for try_name in names {
        for dir in path_var.split(':') {
            if dir.is_empty() {
                continue;
            }
            if dir.starts_with("/usr/bin")
                || dir.starts_with("/bin")
                || dir.starts_with("/sbin")
                || dir.starts_with("/usr/sbin")
            {
                continue;
            }
            let candidate = format!("{}/{}", dir, try_name);
            if let Ok(c) = CString::new(candidate)
                && unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0
            {
                return Some(c);
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
unsafe fn read_shebang_of(path: *const libc::c_char) -> Option<(String, Option<String>)> {
    let fd = unsafe { libc::open(path, libc::O_RDONLY) };
    if fd < 0 {
        return None;
    }

    let mut buf = [0u8; 256];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    unsafe { libc::close(fd) };

    if n < 4 {
        return None;
    }
    let n = n as usize;
    if buf[0] != b'#' || buf[1] != b'!' {
        return None;
    }

    let end = buf[2..n]
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| p + 2)
        .unwrap_or(n);
    let line = std::str::from_utf8(&buf[2..end]).ok()?.trim();
    if line.is_empty() {
        return None;
    }

    let mut parts = line.splitn(2, |c: char| c.is_ascii_whitespace());
    let interpreter = parts.next()?.to_string();
    let arg = parts
        .next()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    Some((interpreter, arg))
}

#[cfg(target_os = "macos")]
unsafe fn resolve_sip_exec(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
) -> Option<(CString, Vec<CString>, Vec<*const libc::c_char>)> {
    if path.is_null() {
        return None;
    }

    let path_str = unsafe { CStr::from_ptr(path) }.to_str().ok()?;

    if is_sip_path(path_str) {
        let basename = path_str.rsplit('/').next()?;
        let resolved = find_non_sip_in_path(basename)?;
        return Some((resolved, Vec::new(), Vec::new()));
    }

    let (interpreter, arg) = (unsafe { read_shebang_of(path) })?;
    if !is_sip_path(&interpreter) {
        return None;
    }

    let is_env = interpreter.ends_with("/env");
    let resolved = if is_env {
        let cmd = arg.as_deref()?;
        let stripped = cmd
            .strip_prefix("-S")
            .map(|s| s.trim_start())
            .unwrap_or(cmd);
        let actual = stripped.split_whitespace().next()?;
        find_non_sip_in_path(actual)?
    } else {
        find_non_sip_in_path(interpreter.rsplit('/').next()?)?
    };

    let mut owned: Vec<CString> = Vec::new();
    let mut ptrs: Vec<*const libc::c_char> = Vec::new();

    ptrs.push(resolved.as_ptr());

    if !is_env
        && let Some(ref a) = arg
        && let Ok(c) = CString::new(a.as_bytes())
    {
        ptrs.push(c.as_ptr());
        owned.push(c);
    }

    ptrs.push(path);

    if !argv.is_null() {
        unsafe {
            let mut p = argv.offset(1);
            while !(*p).is_null() {
                ptrs.push(*p);
                p = p.offset(1);
            }
        }
    }
    ptrs.push(std::ptr::null());

    Some((resolved, owned, ptrs))
}

#[cfg(target_os = "macos")]
#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
// SAFETY: This static places `init` into the __mod_init_func section, which
// dyld calls exactly once when the library is loaded. The function only reads
// environment variables and initializes OnceLock statics, which is safe during
// library initialization.
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

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    unsafe fn is_v6only(fd: c_int) -> bool {
        let mut optval: c_int = 0;
        let mut optlen: socklen_t = std::mem::size_of::<c_int>() as socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &mut optval as *mut _ as *mut libc::c_void,
                &mut optlen,
            )
        };
        ret == 0 && optval != 0
    }

    #[repr(C)]
    struct Interpose {
        replacement: unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int,
        original: unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int,
    }

    #[unsafe(no_mangle)]
    #[used]
    #[unsafe(link_section = "__DATA,__interpose")]
    static INTERPOSE_BIND: Interpose = Interpose {
        replacement: silo_bind_entry,
        original: real_bind,
    };

    #[unsafe(no_mangle)]
    #[used]
    #[unsafe(link_section = "__DATA,__interpose")]
    static INTERPOSE_CONNECT: Interpose = Interpose {
        replacement: silo_connect_entry,
        original: real_connect,
    };

    unsafe fn debug_read_port(addr: *const sockaddr, family: c_int) -> u16 {
        if family == AF_INET {
            unsafe { u16::from_be((*(addr as *const sockaddr_in)).sin_port) }
        } else if family == libc::AF_INET6 as c_int {
            unsafe { u16::from_be((*(addr as *const libc::sockaddr_in6)).sin6_port) }
        } else {
            0
        }
    }

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_bind_entry(
        fd: c_int,
        addr: *const sockaddr,
        len: socklen_t,
    ) -> c_int {
        if !addr.is_null() {
            let family = unsafe { (*addr).sa_family } as c_int;

            if debug_enabled() {
                let port = unsafe { debug_read_port(addr, family) };
                let silo_ip = get_silo_ip()
                    .map(|ip| Ipv4Addr::from(u32::from_be(ip)).to_string())
                    .unwrap_or_default();
                eprintln!(
                    "[silo-bind] pid={} bind fd={} family={} port={} SILO_IP={}",
                    std::process::id(),
                    fd,
                    family,
                    port,
                    silo_ip
                );
            }

            if family == libc::AF_INET6 as c_int {
                let sin6 = addr as *const libc::sockaddr_in6;
                let v6_addr = unsafe { (*sin6).sin6_addr.s6_addr };
                if let Some(ip) = get_silo_ip()
                    && rewrite::rewrite_ipv6_addr(v6_addr, ip, true).is_some()
                {
                    let kind = if v6_addr == rewrite::V6_ANY {
                        "::"
                    } else {
                        "::1"
                    };

                    // Dual-stack socket (IPV6_V6ONLY=0, the default): rewrite
                    // in-place to ::ffff:SILO_IP. This preserves the original
                    // fd, keeping kqueue/kevent registrations and async runtime
                    // state intact.
                    if !unsafe { is_v6only(fd) } {
                        unsafe { rewrite_sockaddr_v6(addr, ip, true) };
                        let ret = unsafe { real_bind(fd, addr, len) };
                        if debug_enabled() {
                            eprintln!(
                                "[silo-bind] pid={} bind {} → ::ffff:SILO_IP (in-place) → {}",
                                std::process::id(),
                                kind,
                                ret
                            );
                        }
                        return ret;
                    }

                    // V6-only socket: must replace with an IPv4 socket.
                    let port = unsafe { (*sin6).sin6_port };
                    let ret = unsafe { rebind_as_ipv4(fd, port, ip) };
                    if debug_enabled() {
                        eprintln!(
                            "[silo-bind] pid={} bind {} → rebind_as_ipv4 (v6only) → {}",
                            std::process::id(),
                            kind,
                            ret
                        );
                    }
                    return ret;
                }
            }
        }

        unsafe {
            rewrite_addr(addr, true);
            real_bind(fd, addr, len)
        }
    }

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_connect_entry(
        fd: c_int,
        addr: *const sockaddr,
        len: socklen_t,
    ) -> c_int {
        if !addr.is_null() {
            let family = unsafe { (*addr).sa_family } as c_int;

            if family == libc::AF_INET6 as c_int {
                let sin6 = addr as *const libc::sockaddr_in6;
                let v6_addr = unsafe { (*sin6).sin6_addr.s6_addr };
                if v6_addr == rewrite::V6_LOOPBACK {
                    if let Some(ip) = get_silo_ip() {
                        let port = unsafe { (*sin6).sin6_port };
                        if unsafe { probe_has_listener(fd, ip, port) } {
                            // Dual-stack: rewrite in-place to ::ffff:SILO_IP
                            if !unsafe { is_v6only(fd) } {
                                unsafe { rewrite_sockaddr_v6(addr, ip, false) };
                                return unsafe { real_connect(fd, addr, len) };
                            }
                            // V6-only: must replace socket
                            return unsafe { reconnect_as_ipv4(fd, port, ip) };
                        }
                    }
                    return unsafe { real_connect(fd, addr, len) };
                }
            }
        }

        unsafe {
            rewrite_connect_addr(fd, addr);
            real_connect(fd, addr, len)
        }
    }

    unsafe fn rebind_as_ipv4(fd: c_int, port: u16, ip: u32) -> c_int {
        if unsafe { replace_with_ipv4(fd) }.is_err() {
            return -1;
        }

        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_len = std::mem::size_of::<sockaddr_in>() as u8;
        sin.sin_family = AF_INET as u8;
        sin.sin_port = port;
        sin.sin_addr.s_addr = ip;

        unsafe {
            real_bind(
                fd,
                &sin as *const sockaddr_in as *const sockaddr,
                std::mem::size_of::<sockaddr_in>() as socklen_t,
            )
        }
    }

    unsafe fn reconnect_as_ipv4(fd: c_int, port: u16, ip: u32) -> c_int {
        if unsafe { replace_with_ipv4(fd) }.is_err() {
            return -1;
        }

        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_len = std::mem::size_of::<sockaddr_in>() as u8;
        sin.sin_family = AF_INET as u8;
        sin.sin_port = port;
        sin.sin_addr.s_addr = ip;

        unsafe {
            real_connect(
                fd,
                &sin as *const sockaddr_in as *const sockaddr,
                std::mem::size_of::<sockaddr_in>() as socklen_t,
            )
        }
    }

    type PosixSpawnFn = unsafe extern "C" fn(
        *mut libc::pid_t,
        *const libc::c_char,
        *const libc::c_void,
        *const libc::c_void,
        *const *mut libc::c_char,
        *const *mut libc::c_char,
    ) -> c_int;

    #[repr(C)]
    struct InterposePosixSpawn {
        replacement: PosixSpawnFn,
        original: PosixSpawnFn,
    }

    #[unsafe(no_mangle)]
    #[used]
    #[unsafe(link_section = "__DATA,__interpose")]
    static INTERPOSE_POSIX_SPAWN: InterposePosixSpawn = InterposePosixSpawn {
        replacement: silo_posix_spawn_entry,
        original: real_posix_spawn,
    };

    #[unsafe(no_mangle)]
    #[used]
    #[unsafe(link_section = "__DATA,__interpose")]
    static INTERPOSE_POSIX_SPAWNP: InterposePosixSpawn = InterposePosixSpawn {
        replacement: silo_posix_spawnp_entry,
        original: real_posix_spawnp,
    };

    type ExecveFn = unsafe extern "C" fn(
        *const libc::c_char,
        *const *const libc::c_char,
        *const *const libc::c_char,
    ) -> c_int;

    #[repr(C)]
    struct InterposeExecve {
        replacement: ExecveFn,
        original: ExecveFn,
    }

    #[unsafe(no_mangle)]
    #[used]
    #[unsafe(link_section = "__DATA,__interpose")]
    static INTERPOSE_EXECVE: InterposeExecve = InterposeExecve {
        replacement: silo_execve_entry,
        original: real_execve,
    };

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_posix_spawn_entry(
        pid: *mut libc::pid_t,
        path: *const libc::c_char,
        file_actions: *const libc::c_void,
        attrp: *const libc::c_void,
        argv: *const *mut libc::c_char,
        envp: *const *mut libc::c_char,
    ) -> c_int {
        if debug_enabled() && !path.is_null() {
            let p = unsafe { CStr::from_ptr(path) }.to_string_lossy();
            eprintln!("[silo-bind] posix_spawn called: {}", p);
        }
        if let Some((resolved, _owned, new_argv)) =
            unsafe { resolve_sip_exec(path, argv as *const *const libc::c_char) }
        {
            if debug_enabled() {
                let orig = unsafe { CStr::from_ptr(path) }.to_string_lossy();
                eprintln!(
                    "[silo-bind] posix_spawn: {} → {}",
                    orig,
                    resolved.to_string_lossy()
                );
            }
            if new_argv.is_empty() {
                return unsafe {
                    real_posix_spawn(pid, resolved.as_ptr(), file_actions, attrp, argv, envp)
                };
            }
            return unsafe {
                real_posix_spawn(
                    pid,
                    resolved.as_ptr(),
                    file_actions,
                    attrp,
                    new_argv.as_ptr() as *const *mut libc::c_char,
                    envp,
                )
            };
        }
        unsafe { real_posix_spawn(pid, path, file_actions, attrp, argv, envp) }
    }

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_posix_spawnp_entry(
        pid: *mut libc::pid_t,
        file: *const libc::c_char,
        file_actions: *const libc::c_void,
        attrp: *const libc::c_void,
        argv: *const *mut libc::c_char,
        envp: *const *mut libc::c_char,
    ) -> c_int {
        if debug_enabled() && !file.is_null() {
            let p = unsafe { CStr::from_ptr(file) }.to_string_lossy();
            eprintln!("[silo-bind] posix_spawnp called: {}", p);
        }
        if let Some((resolved, _owned, new_argv)) =
            unsafe { resolve_sip_exec(file, argv as *const *const libc::c_char) }
        {
            if debug_enabled() {
                let orig = unsafe { CStr::from_ptr(file) }.to_string_lossy();
                eprintln!(
                    "[silo-bind] posix_spawnp: {} → {}",
                    orig,
                    resolved.to_string_lossy()
                );
            }
            if new_argv.is_empty() {
                return unsafe {
                    real_posix_spawn(pid, resolved.as_ptr(), file_actions, attrp, argv, envp)
                };
            }
            return unsafe {
                real_posix_spawn(
                    pid,
                    resolved.as_ptr(),
                    file_actions,
                    attrp,
                    new_argv.as_ptr() as *const *mut libc::c_char,
                    envp,
                )
            };
        }
        unsafe { real_posix_spawnp(pid, file, file_actions, attrp, argv, envp) }
    }

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_execve_entry(
        path: *const libc::c_char,
        argv: *const *const libc::c_char,
        envp: *const *const libc::c_char,
    ) -> c_int {
        if debug_enabled() && !path.is_null() {
            let p = unsafe { CStr::from_ptr(path) }.to_string_lossy();
            eprintln!("[silo-bind] execve called: {}", p);
        }
        if let Some((resolved, _owned, new_argv)) = unsafe { resolve_sip_exec(path, argv) } {
            if debug_enabled() {
                let orig = unsafe { CStr::from_ptr(path) }.to_string_lossy();
                eprintln!(
                    "[silo-bind] execve: {} → {}",
                    orig,
                    resolved.to_string_lossy()
                );
            }
            if new_argv.is_empty() {
                return unsafe { real_execve(resolved.as_ptr(), argv, envp) };
            }
            return unsafe { real_execve(resolved.as_ptr(), new_argv.as_ptr(), envp) };
        }
        unsafe { real_execve(path, argv, envp) }
    }

    type SendtoFn = unsafe extern "C" fn(
        c_int,
        *const libc::c_void,
        libc::size_t,
        c_int,
        *const sockaddr,
        socklen_t,
    ) -> libc::ssize_t;

    #[repr(C)]
    struct InterposeSendto {
        replacement: SendtoFn,
        original: SendtoFn,
    }

    #[unsafe(no_mangle)]
    #[used]
    #[unsafe(link_section = "__DATA,__interpose")]
    static INTERPOSE_SENDTO: InterposeSendto = InterposeSendto {
        replacement: silo_sendto_entry,
        original: real_sendto,
    };

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_sendto_entry(
        fd: c_int,
        buf: *const libc::c_void,
        len: libc::size_t,
        flags: c_int,
        dest_addr: *const sockaddr,
        addrlen: socklen_t,
    ) -> libc::ssize_t {
        unsafe { rewrite_addr(dest_addr, true) };
        unsafe { real_sendto(fd, buf, len, flags, dest_addr, addrlen) }
    }

    type GetifaddrsFn = unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> c_int;

    #[repr(C)]
    struct InterposeGetifaddrs {
        replacement: GetifaddrsFn,
        original: GetifaddrsFn,
    }

    #[unsafe(no_mangle)]
    #[used]
    #[unsafe(link_section = "__DATA,__interpose")]
    static INTERPOSE_GETIFADDRS: InterposeGetifaddrs = InterposeGetifaddrs {
        replacement: silo_getifaddrs_entry,
        original: real_getifaddrs,
    };

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_getifaddrs_entry(ifap: *mut *mut libc::ifaddrs) -> c_int {
        let ret = unsafe { real_getifaddrs(ifap) };
        if ret == 0 && !ifap.is_null() && !(unsafe { *ifap }).is_null() {
            if debug_enabled() {
                eprintln!("[silo-bind] getifaddrs intercepted, filtering aliases");
            }
            unsafe { hide_other_silo_aliases(*ifap) };
        }
        ret
    }

    type SendmsgFn = unsafe extern "C" fn(c_int, *const libc::msghdr, c_int) -> libc::ssize_t;

    #[repr(C)]
    struct InterposeSendmsg {
        replacement: SendmsgFn,
        original: SendmsgFn,
    }

    #[unsafe(no_mangle)]
    #[used]
    #[unsafe(link_section = "__DATA,__interpose")]
    static INTERPOSE_SENDMSG: InterposeSendmsg = InterposeSendmsg {
        replacement: silo_sendmsg_entry,
        original: real_sendmsg,
    };

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_sendmsg_entry(
        fd: c_int,
        msg: *const libc::msghdr,
        flags: c_int,
    ) -> libc::ssize_t {
        if !msg.is_null() {
            let msg_ref = unsafe { &*msg };
            if !msg_ref.msg_name.is_null() && msg_ref.msg_namelen > 0 {
                unsafe { rewrite_addr(msg_ref.msg_name as *const sockaddr, true) };
            }
        }
        unsafe { real_sendmsg(fd, msg, flags) }
    }

    unsafe fn get_int_sockopt(fd: c_int, level: c_int, optname: c_int) -> Option<c_int> {
        let mut optval: c_int = 0;
        let mut optlen: socklen_t = std::mem::size_of::<c_int>() as socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                level,
                optname,
                &mut optval as *mut _ as *mut libc::c_void,
                &mut optlen,
            )
        };
        if ret == 0 { Some(optval) } else { None }
    }

    unsafe fn set_int_sockopt(fd: c_int, level: c_int, optname: c_int, val: c_int) {
        unsafe {
            libc::setsockopt(
                fd,
                level,
                optname,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<c_int>() as socklen_t,
            );
        }
    }

    unsafe fn copy_bool_sockopt(old_fd: c_int, new_fd: c_int, optname: c_int) {
        if let Some(val) = unsafe { get_int_sockopt(old_fd, libc::SOL_SOCKET, optname) }
            && val != 0
        {
            unsafe { set_int_sockopt(new_fd, libc::SOL_SOCKET, optname, val) };
        }
    }

    unsafe fn copy_int_sockopt(old_fd: c_int, new_fd: c_int, optname: c_int) {
        if let Some(val) = unsafe { get_int_sockopt(old_fd, libc::SOL_SOCKET, optname) } {
            unsafe { set_int_sockopt(new_fd, libc::SOL_SOCKET, optname, val) };
        }
    }

    unsafe fn replace_with_ipv4(fd: c_int) -> Result<c_int, c_int> {
        let sock_type = unsafe { get_int_sockopt(fd, libc::SOL_SOCKET, libc::SO_TYPE) }
            .unwrap_or(libc::SOCK_STREAM);

        let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };

        let new_fd = unsafe { libc::socket(AF_INET, sock_type, 0) };
        if new_fd < 0 {
            return Err(-1);
        }

        for opt in [
            libc::SO_REUSEADDR,
            libc::SO_REUSEPORT,
            libc::SO_KEEPALIVE,
            libc::SO_NOSIGPIPE,
            libc::SO_OOBINLINE,
        ] {
            unsafe { copy_bool_sockopt(fd, new_fd, opt) };
        }

        for opt in [
            libc::SO_RCVBUF,
            libc::SO_SNDBUF,
            libc::SO_RCVLOWAT,
            libc::SO_SNDLOWAT,
        ] {
            unsafe { copy_int_sockopt(fd, new_fd, opt) };
        }

        {
            let mut linger_val: libc::linger = unsafe { std::mem::zeroed() };
            let mut optlen = std::mem::size_of::<libc::linger>() as socklen_t;
            unsafe {
                if libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    &mut linger_val as *mut _ as *mut libc::c_void,
                    &mut optlen,
                ) == 0
                    && linger_val.l_onoff != 0
                {
                    libc::setsockopt(
                        new_fd,
                        libc::SOL_SOCKET,
                        libc::SO_LINGER,
                        &linger_val as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::linger>() as socklen_t,
                    );
                }
            }
        }

        for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
            let mut optlen = std::mem::size_of::<libc::timeval>() as socklen_t;
            unsafe {
                if libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    opt,
                    &mut tv as *mut _ as *mut libc::c_void,
                    &mut optlen,
                ) == 0
                    && (tv.tv_sec != 0 || tv.tv_usec != 0)
                {
                    libc::setsockopt(
                        new_fd,
                        libc::SOL_SOCKET,
                        opt,
                        &tv as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::timeval>() as socklen_t,
                    );
                }
            }
        }

        if sock_type == libc::SOCK_STREAM {
            for opt in [libc::TCP_NODELAY, libc::TCP_KEEPALIVE] {
                if let Some(val) = unsafe { get_int_sockopt(fd, libc::IPPROTO_TCP, opt) }
                    && val != 0
                {
                    unsafe { set_int_sockopt(new_fd, libc::IPPROTO_TCP, opt, val) };
                }
            }
        }

        unsafe {
            libc::dup2(new_fd, fd);
            libc::close(new_fd);
        }

        if fd_flags >= 0 {
            unsafe { libc::fcntl(fd, libc::F_SETFL, fd_flags) };
        }

        Ok(fd)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    macro_rules! real {
        ($sym:literal, $ty:ty) => {{
            static REAL: OnceLock<$ty> = OnceLock::new();
            *REAL.get_or_init(|| unsafe {
                let ptr = libc::dlsym(libc::RTLD_NEXT, concat!($sym, "\0").as_ptr().cast());
                assert!(
                    !ptr.is_null(),
                    concat!("silo-bind: dlsym failed to resolve ", $sym)
                );
                std::mem::transmute(ptr)
            })
        }};
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
        let real_fn = real!(
            "bind",
            unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int
        );
        unsafe { rewrite_addr(addr, true) };
        unsafe { real_fn(fd, addr, len) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
        let real_fn = real!(
            "connect",
            unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int
        );
        unsafe { rewrite_connect_addr(fd, addr) };
        unsafe { real_fn(fd, addr, len) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn getifaddrs(ifap: *mut *mut libc::ifaddrs) -> c_int {
        let real_fn = real!(
            "getifaddrs",
            unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> c_int
        );
        let ret = unsafe { real_fn(ifap) };
        if ret == 0 && !ifap.is_null() && !(unsafe { *ifap }).is_null() {
            unsafe { hide_other_silo_aliases(*ifap) };
        }
        ret
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sendto(
        fd: c_int,
        buf: *const libc::c_void,
        len: libc::size_t,
        flags: c_int,
        dest_addr: *const sockaddr,
        addrlen: socklen_t,
    ) -> libc::ssize_t {
        let real_fn = real!(
            "sendto",
            unsafe extern "C" fn(
                c_int,
                *const libc::c_void,
                libc::size_t,
                c_int,
                *const sockaddr,
                socklen_t,
            ) -> libc::ssize_t
        );

        unsafe { rewrite_addr(dest_addr, true) };
        unsafe { real_fn(fd, buf, len, flags, dest_addr, addrlen) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sendmsg(
        fd: c_int,
        msg: *const libc::msghdr,
        flags: c_int,
    ) -> libc::ssize_t {
        let real_fn = real!(
            "sendmsg",
            unsafe extern "C" fn(c_int, *const libc::msghdr, c_int) -> libc::ssize_t
        );
        if !msg.is_null() {
            let msg_ref = unsafe { &*msg };
            if !msg_ref.msg_name.is_null() && msg_ref.msg_namelen > 0 {
                unsafe { rewrite_addr(msg_ref.msg_name as *const sockaddr, true) };
            }
        }
        unsafe { real_fn(fd, msg, flags) }
    }
}
