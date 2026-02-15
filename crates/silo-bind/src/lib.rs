pub mod rewrite;

use std::env;
use std::mem::MaybeUninit;
#[cfg(target_os = "macos")]
use std::net::Ipv4Addr;
use std::os::raw::c_int;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "macos")]
use std::ffi::{CStr, CString};

use libc::{AF_INET, sockaddr, sockaddr_in, socklen_t};

static SILO_IP: OnceLock<Option<u32>> = OnceLock::new();
static CONNECT_ENABLED: OnceLock<bool> = OnceLock::new();

static LISTENER_CACHE: [AtomicU64; 1024] = [const { AtomicU64::new(0) }; 1024];

fn cache_has_listener(port: u16) -> bool {
    let idx = (port as usize) / 64;
    let bit = (port as usize) % 64;
    LISTENER_CACHE[idx].load(Ordering::Acquire) & (1u64 << bit) != 0
}

fn cache_set_listener(port: u16) {
    let idx = (port as usize) / 64;
    let bit = (port as usize) % 64;
    LISTENER_CACHE[idx].fetch_or(1u64 << bit, Ordering::Release);
}

fn cache_clear_listener(port: u16) {
    let idx = (port as usize) / 64;
    let bit = (port as usize) % 64;
    LISTENER_CACHE[idx].fetch_and(!(1u64 << bit), Ordering::Release);
}

unsafe fn read_port(addr: *const sockaddr, len: socklen_t) -> Option<u16> {
    let family = unsafe { read_sa_family(addr) }?;
    if family == AF_INET && (len as usize) >= std::mem::size_of::<sockaddr_in>() {
        Some(unsafe { (*(addr as *const sockaddr_in)).sin_port })
    } else if family == libc::AF_INET6 as c_int
        && (len as usize) >= std::mem::size_of::<libc::sockaddr_in6>()
    {
        Some(unsafe { (*(addr as *const libc::sockaddr_in6)).sin6_port })
    } else {
        None
    }
}

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

const unsafe fn read_sa_family(addr: *const sockaddr) -> Option<c_int> {
    if addr.is_null() {
        return None;
    }
    Some(unsafe { (*addr).sa_family } as c_int)
}

#[repr(C)]
union SockaddrStorage {
    sa: sockaddr,
    v4: sockaddr_in,
    v6: libc::sockaddr_in6,
}

unsafe fn maybe_rewrite_addr(
    addr: *const sockaddr,
    len: socklen_t,
    match_any: bool,
    storage: &mut MaybeUninit<SockaddrStorage>,
) -> (*const sockaddr, socklen_t) {
    let Some(family) = (unsafe { read_sa_family(addr) }) else {
        return (addr, len);
    };
    let Some(silo_ip) = get_silo_ip() else {
        return (addr, len);
    };

    if family == AF_INET && (len as usize) >= std::mem::size_of::<sockaddr_in>() {
        let sin = unsafe { &*(addr as *const sockaddr_in) };
        if let Some(new_addr) = rewrite::rewrite_ipv4_addr(sin.sin_addr.s_addr, silo_ip, match_any)
        {
            let ptr = storage.as_mut_ptr();
            unsafe {
                (*ptr).v4 = *sin;
                (*ptr).v4.sin_addr.s_addr = new_addr;
            }
            return (unsafe { &(*ptr).sa as *const sockaddr }, len);
        }
    }

    if family == libc::AF_INET6 as c_int
        && (len as usize) >= std::mem::size_of::<libc::sockaddr_in6>()
    {
        let sin6 = unsafe { &*(addr as *const libc::sockaddr_in6) };
        if let Some(new_addr) =
            rewrite::rewrite_ipv6_addr(sin6.sin6_addr.s6_addr, silo_ip, match_any)
        {
            let ptr = storage.as_mut_ptr();
            unsafe {
                (*ptr).v6 = *sin6;
                (*ptr).v6.sin6_addr.s6_addr = new_addr;
            }
            return (unsafe { &(*ptr).sa as *const sockaddr }, len);
        }
    }

    (addr, len)
}

unsafe fn maybe_rewrite_connect_addr(
    fd: c_int,
    addr: *const sockaddr,
    len: socklen_t,
    storage: &mut MaybeUninit<SockaddrStorage>,
) -> (*const sockaddr, socklen_t) {
    if !connect_enabled() {
        return (addr, len);
    }
    let Some(family) = (unsafe { read_sa_family(addr) }) else {
        return (addr, len);
    };
    let Some(silo_ip) = get_silo_ip() else {
        return (addr, len);
    };

    if family == AF_INET && (len as usize) >= std::mem::size_of::<sockaddr_in>() {
        let sin = unsafe { &*(addr as *const sockaddr_in) };
        if sin.sin_addr.s_addr == rewrite::LOCALHOST_NBO
            && unsafe { probe_has_listener(fd, silo_ip, sin.sin_port) }
        {
            let ptr = storage.as_mut_ptr();
            unsafe {
                (*ptr).v4 = *sin;
                (*ptr).v4.sin_addr.s_addr = silo_ip;
            }
            return (unsafe { &(*ptr).sa as *const sockaddr }, len);
        }
    }

    #[cfg(target_os = "linux")]
    if family == libc::AF_INET6 as c_int
        && (len as usize) >= std::mem::size_of::<libc::sockaddr_in6>()
    {
        let sin6 = unsafe { &*(addr as *const libc::sockaddr_in6) };
        if sin6.sin6_addr.s6_addr == rewrite::V6_LOOPBACK
            && unsafe { probe_has_listener(fd, silo_ip, sin6.sin6_port) }
        {
            let ptr = storage.as_mut_ptr();
            unsafe {
                (*ptr).v6 = *sin6;
                (*ptr).v6.sin6_addr.s6_addr = rewrite::ipv4_mapped_v6(silo_ip);
            }
            return (unsafe { &(*ptr).sa as *const sockaddr }, len);
        }
    }

    (addr, len)
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
    static REAL_BIND: OnceLock<
        Option<unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int>,
    > = OnceLock::new();
    let f = *REAL_BIND.get_or_init(|| unsafe {
        let ptr = libc::dlsym(libc::RTLD_NEXT, c"bind".as_ptr());
        if ptr.is_null() {
            eprintln!("silo-bind: dlsym failed to resolve bind");
            return None;
        }
        Some(std::mem::transmute(ptr))
    });
    match f {
        Some(f) => unsafe { f(fd, addr, len) },
        None => {
            unsafe { *errno_ptr() = libc::ENOSYS };
            -1
        }
    }
}

unsafe fn probe_has_listener(fd: c_int, silo_ip: u32, port: u16) -> bool {
    if cache_has_listener(port) {
        return true;
    }

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

    if has_listener {
        cache_set_listener(port);
    }

    has_listener
}

fn get_silo_ip() -> Option<u32> {
    *SILO_IP.get_or_init(|| {
        let val = env::var("SILO_IP").ok()?;
        rewrite::parse_silo_ip(&val)
    })
}

fn connect_enabled() -> bool {
    *CONNECT_ENABLED.get_or_init(|| env::var("SILO_CONNECT").map(|v| v != "0").unwrap_or(true))
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
        "sh" | "bash" | "zsh" | "dash" | "ksh" => &["bash", "zsh", "sh"],
        "make" => &["make", "gmake"],
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
            if dir.starts_with("/usr/bin/")
                || dir == "/usr/bin"
                || dir.starts_with("/bin/")
                || dir == "/bin"
                || dir.starts_with("/sbin/")
                || dir == "/sbin"
                || dir.starts_with("/usr/sbin/")
                || dir == "/usr/sbin"
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

    const unsafe fn debug_read_port(addr: *const sockaddr, family: c_int, len: socklen_t) -> u16 {
        if family == AF_INET && (len as usize) >= std::mem::size_of::<sockaddr_in>() {
            unsafe { u16::from_be((*(addr as *const sockaddr_in)).sin_port) }
        } else if family == libc::AF_INET6 as c_int
            && (len as usize) >= std::mem::size_of::<libc::sockaddr_in6>()
        {
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
                let port = unsafe { debug_read_port(addr, family, len) };
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

            if family == libc::AF_INET6 as c_int
                && (len as usize) >= std::mem::size_of::<libc::sockaddr_in6>()
            {
                let sin6 = addr as *const libc::sockaddr_in6;
                let v6_addr = unsafe { (*sin6).sin6_addr.s6_addr };
                if let Some(ip) = get_silo_ip()
                    && let Some(new_v6) = rewrite::rewrite_ipv6_addr(v6_addr, ip, true)
                {
                    if unsafe { is_v6only(fd) } {
                        let optval: c_int = 0;
                        unsafe {
                            libc::setsockopt(
                                fd,
                                libc::IPPROTO_IPV6,
                                libc::IPV6_V6ONLY,
                                &optval as *const _ as *const libc::c_void,
                                std::mem::size_of::<c_int>() as socklen_t,
                            );
                        }
                    }
                    let kind = if v6_addr == rewrite::V6_ANY {
                        "::"
                    } else {
                        "::1"
                    };

                    let mut sin6_copy: libc::sockaddr_in6 = unsafe { *sin6 };
                    sin6_copy.sin6_addr.s6_addr = new_v6;
                    let ret = unsafe {
                        real_bind(
                            fd,
                            &sin6_copy as *const libc::sockaddr_in6 as *const sockaddr,
                            len,
                        )
                    };
                    if debug_enabled() {
                        eprintln!(
                            "[silo-bind] pid={} bind {} → ::ffff:SILO_IP → {}",
                            std::process::id(),
                            kind,
                            ret
                        );
                    }
                    return ret;
                }
            }
        }

        let mut storage = std::mem::MaybeUninit::<SockaddrStorage>::uninit();
        let (addr, len) = unsafe { maybe_rewrite_addr(addr, len, true, &mut storage) };
        unsafe { real_bind(fd, addr, len) }
    }

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_connect_entry(
        fd: c_int,
        addr: *const sockaddr,
        len: socklen_t,
    ) -> c_int {
        if !addr.is_null() && connect_enabled() {
            let family = unsafe { (*addr).sa_family } as c_int;

            if family == libc::AF_INET6 as c_int
                && (len as usize) >= std::mem::size_of::<libc::sockaddr_in6>()
            {
                let sin6 = addr as *const libc::sockaddr_in6;
                let v6_addr = unsafe { (*sin6).sin6_addr.s6_addr };
                if v6_addr == rewrite::V6_LOOPBACK && !unsafe { is_v6only(fd) } {
                    if let Some(ip) = get_silo_ip() {
                        let port = unsafe { (*sin6).sin6_port };
                        if unsafe { probe_has_listener(fd, ip, port) } {
                            let mut sin6_copy: libc::sockaddr_in6 = unsafe { *sin6 };
                            sin6_copy.sin6_addr.s6_addr = rewrite::ipv4_mapped_v6(ip);
                            let ret = unsafe {
                                real_connect(
                                    fd,
                                    &sin6_copy as *const libc::sockaddr_in6 as *const sockaddr,
                                    len,
                                )
                            };
                            if ret == -1 && unsafe { *errno_ptr() } == libc::ECONNREFUSED {
                                cache_clear_listener(port);
                            }
                            return ret;
                        }
                    }
                    return unsafe { real_connect(fd, addr, len) };
                }
            }
        }

        let mut storage = std::mem::MaybeUninit::<SockaddrStorage>::uninit();
        let (new_addr, new_len) =
            unsafe { maybe_rewrite_connect_addr(fd, addr, len, &mut storage) };
        let ret = unsafe { real_connect(fd, new_addr, new_len) };
        if new_addr != addr
            && ret == -1
            && unsafe { *errno_ptr() } == libc::ECONNREFUSED
            && let Some(port) = unsafe { read_port(addr, len) }
        {
            cache_clear_listener(port);
        }
        ret
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
        let mut storage = std::mem::MaybeUninit::<SockaddrStorage>::uninit();
        let (dest_addr, addrlen) =
            unsafe { maybe_rewrite_addr(dest_addr, addrlen, true, &mut storage) };
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
                let mut storage = std::mem::MaybeUninit::<SockaddrStorage>::uninit();
                let (new_addr, new_len) = unsafe {
                    maybe_rewrite_addr(
                        msg_ref.msg_name as *const sockaddr,
                        msg_ref.msg_namelen,
                        true,
                        &mut storage,
                    )
                };
                if new_addr != msg_ref.msg_name as *const sockaddr {
                    let mut msg_copy: libc::msghdr = *msg_ref;
                    msg_copy.msg_name = new_addr as *mut libc::c_void;
                    msg_copy.msg_namelen = new_len;
                    return unsafe { real_sendmsg(fd, &msg_copy as *const libc::msghdr, flags) };
                }
            }
        }
        unsafe { real_sendmsg(fd, msg, flags) }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    macro_rules! real {
        ($sym:literal, $ty:ty) => {{
            static REAL: OnceLock<Option<$ty>> = OnceLock::new();
            *REAL.get_or_init(|| unsafe {
                let ptr = libc::dlsym(libc::RTLD_NEXT, concat!($sym, "\0").as_ptr().cast());
                if ptr.is_null() {
                    eprintln!(concat!("silo-bind: dlsym failed to resolve ", $sym));
                    return None;
                }
                Some(std::mem::transmute(ptr))
            })
        }};
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
        let Some(real_fn) = real!(
            "bind",
            unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int
        ) else {
            unsafe { *errno_ptr() = libc::ENOSYS };
            return -1;
        };
        let mut storage = std::mem::MaybeUninit::<SockaddrStorage>::uninit();
        let (addr, len) = unsafe { maybe_rewrite_addr(addr, len, true, &mut storage) };
        unsafe { real_fn(fd, addr, len) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
        let Some(real_fn) = real!(
            "connect",
            unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int
        ) else {
            unsafe { *errno_ptr() = libc::ENOSYS };
            return -1;
        };
        let mut storage = std::mem::MaybeUninit::<SockaddrStorage>::uninit();
        let (new_addr, new_len) =
            unsafe { maybe_rewrite_connect_addr(fd, addr, len, &mut storage) };
        let ret = unsafe { real_fn(fd, new_addr, new_len) };
        if new_addr != addr
            && ret == -1
            && unsafe { *errno_ptr() } == libc::ECONNREFUSED
            && let Some(port) = unsafe { read_port(addr, len) }
        {
            cache_clear_listener(port);
        }
        ret
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn getifaddrs(ifap: *mut *mut libc::ifaddrs) -> c_int {
        let Some(real_fn) = real!(
            "getifaddrs",
            unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> c_int
        ) else {
            unsafe { *errno_ptr() = libc::ENOSYS };
            return -1;
        };
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
        let Some(real_fn) = real!(
            "sendto",
            unsafe extern "C" fn(
                c_int,
                *const libc::c_void,
                libc::size_t,
                c_int,
                *const sockaddr,
                socklen_t,
            ) -> libc::ssize_t
        ) else {
            unsafe { *errno_ptr() = libc::ENOSYS };
            return -1;
        };

        let mut storage = std::mem::MaybeUninit::<SockaddrStorage>::uninit();
        let (dest_addr, addrlen) =
            unsafe { maybe_rewrite_addr(dest_addr, addrlen, true, &mut storage) };
        unsafe { real_fn(fd, buf, len, flags, dest_addr, addrlen) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sendmsg(
        fd: c_int,
        msg: *const libc::msghdr,
        flags: c_int,
    ) -> libc::ssize_t {
        let Some(real_fn) = real!(
            "sendmsg",
            unsafe extern "C" fn(c_int, *const libc::msghdr, c_int) -> libc::ssize_t
        ) else {
            unsafe { *errno_ptr() = libc::ENOSYS };
            return -1;
        };
        if !msg.is_null() {
            let msg_ref = unsafe { &*msg };
            if !msg_ref.msg_name.is_null() && msg_ref.msg_namelen > 0 {
                let mut storage = std::mem::MaybeUninit::<SockaddrStorage>::uninit();
                let (new_addr, new_len) = unsafe {
                    maybe_rewrite_addr(
                        msg_ref.msg_name as *const sockaddr,
                        msg_ref.msg_namelen,
                        true,
                        &mut storage,
                    )
                };
                if new_addr != msg_ref.msg_name as *const sockaddr {
                    let mut msg_copy: libc::msghdr = *msg_ref;
                    msg_copy.msg_name = new_addr as *mut libc::c_void;
                    msg_copy.msg_namelen = new_len;
                    return unsafe { real_fn(fd, &msg_copy as *const libc::msghdr, flags) };
                }
            }
        }
        unsafe { real_fn(fd, msg, flags) }
    }
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod shebang_tests {
    use super::*;

    #[test]
    fn read_shebang_of_normal() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("test.sh");
        std::fs::write(&script, "#!/bin/bash\necho hello\n").unwrap();
        let cpath = CString::new(script.to_str().unwrap()).unwrap();
        let result = unsafe { read_shebang_of(cpath.as_ptr()) };
        let (interp, arg) = result.unwrap();
        assert_eq!(interp, "/bin/bash");
        assert!(arg.is_none());
    }

    #[test]
    fn read_shebang_of_with_arg() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("test.sh");
        std::fs::write(&script, "#!/usr/bin/env bash\necho hello\n").unwrap();
        let cpath = CString::new(script.to_str().unwrap()).unwrap();
        let result = unsafe { read_shebang_of(cpath.as_ptr()) };
        let (interp, arg) = result.unwrap();
        assert_eq!(interp, "/usr/bin/env");
        assert_eq!(arg.as_deref(), Some("bash"));
    }

    #[test]
    fn read_shebang_of_with_env_s_flag() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("test.py");
        std::fs::write(&script, "#!/usr/bin/env -S python3 -u\nimport sys\n").unwrap();
        let cpath = CString::new(script.to_str().unwrap()).unwrap();
        let result = unsafe { read_shebang_of(cpath.as_ptr()) };
        let (interp, arg) = result.unwrap();
        assert_eq!(interp, "/usr/bin/env");
        assert_eq!(arg.as_deref(), Some("-S python3 -u"));
    }

    #[test]
    fn read_shebang_of_binary_file() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("binary");
        std::fs::write(&bin, [0x7f, 0x45, 0x4c, 0x46, 0x00, 0x00]).unwrap();
        let cpath = CString::new(bin.to_str().unwrap()).unwrap();
        let result = unsafe { read_shebang_of(cpath.as_ptr()) };
        assert!(result.is_none());
    }

    #[test]
    fn read_shebang_of_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        std::fs::write(&empty, "").unwrap();
        let cpath = CString::new(empty.to_str().unwrap()).unwrap();
        let result = unsafe { read_shebang_of(cpath.as_ptr()) };
        assert!(result.is_none());
    }

    #[test]
    fn read_shebang_of_empty_shebang() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("test.sh");
        std::fs::write(&script, "#!\n").unwrap();
        let cpath = CString::new(script.to_str().unwrap()).unwrap();
        let result = unsafe { read_shebang_of(cpath.as_ptr()) };
        assert!(result.is_none());
    }

    #[test]
    fn read_shebang_of_nonexistent() {
        let cpath = CString::new("/tmp/nonexistent-silo-test-file-12345").unwrap();
        let result = unsafe { read_shebang_of(cpath.as_ptr()) };
        assert!(result.is_none());
    }

    #[test]
    fn is_sip_path_known_dirs() {
        assert!(is_sip_path("/usr/bin/env"));
        assert!(is_sip_path("/usr/bin/bash"));
        assert!(is_sip_path("/bin/sh"));
        assert!(is_sip_path("/bin/bash"));
        assert!(is_sip_path("/sbin/mount"));
        assert!(is_sip_path("/usr/sbin/something"));
    }

    #[test]
    fn is_sip_path_non_sip() {
        assert!(!is_sip_path("/opt/homebrew/bin/bash"));
        assert!(!is_sip_path("/usr/local/bin/node"));
        assert!(!is_sip_path("/nix/store/xyz/bin/bash"));
        assert!(!is_sip_path("/home/user/bin/script"));
    }

    #[test]
    fn find_non_sip_in_path_shell_coverage() {
        for name in &["sh", "bash", "zsh", "dash", "ksh"] {
            let result = find_non_sip_in_path(name);
            if let Some(ref path) = result {
                let path_str = path.to_str().unwrap();
                assert!(
                    !is_sip_path(path_str),
                    "find_non_sip_in_path({name}) returned SIP path: {path_str}"
                );
            }
        }
    }

    #[test]
    fn find_non_sip_in_path_make() {
        let result = find_non_sip_in_path("make");
        if let Some(ref path) = result {
            let path_str = path.to_str().unwrap();
            assert!(
                !is_sip_path(path_str),
                "find_non_sip_in_path(\"make\") returned SIP path: {path_str}"
            );
        }
    }

    #[test]
    fn find_non_sip_in_path_nonexistent() {
        assert!(find_non_sip_in_path("nonexistent-binary-xyz-12345").is_none());
    }

    #[test]
    fn find_non_sip_in_path_never_returns_sip() {
        for name in &["sh", "bash", "zsh", "make", "python3"] {
            if let Some(ref path) = find_non_sip_in_path(name) {
                let path_str = path.to_str().unwrap();
                assert!(
                    !is_sip_path(path_str),
                    "find_non_sip_in_path({name}) returned SIP path: {path_str}"
                );
            }
        }
    }
}
