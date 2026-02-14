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

// ---------------------------------------------------------------------------
// Safe sockaddr helpers
// ---------------------------------------------------------------------------

/// Read the address family from a sockaddr pointer.
///
/// Returns `None` if `addr` is null.
///
/// # Safety
///
/// If non-null, `addr` must point to a valid `sockaddr` whose `sa_family`
/// field is initialized and the pointer must be valid for reads.
unsafe fn read_sa_family(addr: *const sockaddr) -> Option<c_int> {
    if addr.is_null() {
        return None;
    }
    // SAFETY: Caller guarantees `addr` is non-null and points to a valid
    // sockaddr with `sa_family` initialized.
    Some(unsafe { (*addr).sa_family } as c_int)
}

/// Rewrite the IPv4 address inside a `sockaddr_in` in-place.
///
/// # Safety
///
/// `addr` must point to a valid, mutable `sockaddr_in` (i.e. `sa_family`
/// has already been verified as `AF_INET`).
unsafe fn rewrite_sockaddr_v4(addr: *const sockaddr, silo_ip: u32, match_any: bool) {
    let sin = addr as *mut sockaddr_in;
    // SAFETY: Caller verified sa_family == AF_INET, so the pointer is a valid
    // sockaddr_in. Reading sin_addr.s_addr is within bounds of the struct.
    let s_addr = unsafe { (*sin).sin_addr.s_addr };
    if let Some(new_addr) = rewrite::rewrite_ipv4_addr(s_addr, silo_ip, match_any) {
        // SAFETY: Same validity as above; writing back to the same field.
        unsafe { (*sin).sin_addr.s_addr = new_addr };
    }
}

/// Rewrite the IPv6 address inside a `sockaddr_in6` in-place.
///
/// # Safety
///
/// `addr` must point to a valid, mutable `sockaddr_in6` (i.e. `sa_family`
/// has already been verified as `AF_INET6`).
#[cfg(target_os = "linux")]
unsafe fn rewrite_sockaddr_v6(addr: *const sockaddr, silo_ip: u32, match_any: bool) {
    let sin6 = addr as *mut libc::sockaddr_in6;
    // SAFETY: Caller verified sa_family == AF_INET6, so the pointer is a valid
    // sockaddr_in6. Reading sin6_addr.s6_addr is within bounds of the struct.
    let s6_addr = unsafe { (*sin6).sin6_addr.s6_addr };
    if let Some(new_addr) = rewrite::rewrite_ipv6_addr(s6_addr, silo_ip, match_any) {
        // SAFETY: Same validity as above; writing back to the same field.
        unsafe { (*sin6).sin6_addr.s6_addr = new_addr };
    }
}

/// Rewrite a sockaddr in-place to point at `SILO_IP`.
///
/// When `match_any` is true, INADDR_ANY (`0.0.0.0`) and `::` are also
/// rewritten (appropriate for `bind`/`sendto`). When false, only
/// localhost (`127.0.0.1` / `::1`) is rewritten (appropriate for `connect`).
///
/// # Safety
///
/// `addr` must be either null or point to a valid, mutable `sockaddr` whose
/// `sa_family` is initialized. If `sa_family == AF_INET`, the underlying
/// storage must be a valid `sockaddr_in`. If `AF_INET6`, a valid
/// `sockaddr_in6`.
unsafe fn rewrite_addr(addr: *const sockaddr, match_any: bool) {
    // SAFETY: Caller guarantees `addr` is null or a valid sockaddr.
    let Some(family) = (unsafe { read_sa_family(addr) }) else {
        return;
    };
    let Some(silo_ip) = get_silo_ip() else {
        return;
    };

    if family == AF_INET {
        // SAFETY: family == AF_INET verified; caller guarantees valid sockaddr_in.
        unsafe { rewrite_sockaddr_v4(addr, silo_ip, match_any) };
    }

    #[cfg(target_os = "linux")]
    if family == libc::AF_INET6 as c_int {
        // SAFETY: family == AF_INET6 verified; caller guarantees valid sockaddr_in6.
        unsafe { rewrite_sockaddr_v6(addr, silo_ip, match_any) };
    }
}

// ---------------------------------------------------------------------------
// Bind probe: check if SILO_IP:port has an active listener
// ---------------------------------------------------------------------------

/// Get a pointer to errno (platform-specific).
///
/// # Safety
///
/// The returned pointer is valid for the calling thread's errno location.
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

/// Call the real (non-intercepted) `bind(2)`.
///
/// On macOS this uses the FFI declaration (dyld interpose doesn't affect
/// calls within the same library). On Linux we must resolve the real symbol
/// via `dlsym(RTLD_NEXT)` because our `bind` IS the LD_PRELOAD override.
///
/// # Safety
///
/// Same contract as `bind(2)`: `fd` must be a valid socket, `addr` must
/// point to a valid sockaddr of at least `len` bytes (or be null).
#[cfg(target_os = "macos")]
unsafe fn call_real_bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    unsafe { real_bind(fd, addr, len) }
}

#[cfg(target_os = "linux")]
unsafe fn call_real_bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    static REAL_BIND: OnceLock<unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int> =
        OnceLock::new();
    let f = *REAL_BIND.get_or_init(|| {
        // SAFETY: Resolving the real bind(2) from libc via RTLD_NEXT.
        // The null-terminated literal is valid for dlsym. transmute is safe
        // because we assert non-null and the type matches bind(2) ABI.
        unsafe {
            let ptr = libc::dlsym(libc::RTLD_NEXT, "bind\0".as_ptr().cast());
            assert!(!ptr.is_null(), "silo-bind: dlsym failed to resolve bind");
            std::mem::transmute(ptr)
        }
    });
    unsafe { f(fd, addr, len) }
}

/// Probe whether `silo_ip:port` has an active listener by attempting to bind
/// a temporary socket to the same address.
///
/// Returns `true` if `EADDRINUSE` is returned (meaning something is already
/// listening on that port at `silo_ip`). Returns `false` for any other
/// result, including success (no listener) or other errors.
///
/// Saves and restores `errno` so the probe is transparent to the caller.
///
/// # Safety
///
/// `fd` must be a valid socket file descriptor (used to read `SO_TYPE`).
/// `port` must be in network byte order.
unsafe fn probe_has_listener(fd: c_int, silo_ip: u32, port: u16) -> bool {
    // SAFETY: Reading thread-local errno location.
    let saved_errno = unsafe { *errno_ptr() };

    // Read socket type from the original fd so we probe with the same type.
    let mut sock_type: c_int = libc::SOCK_STREAM;
    let mut optlen: socklen_t = std::mem::size_of::<c_int>() as socklen_t;
    // SAFETY: fd is valid; getsockopt reads SO_TYPE into sock_type.
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

    // SAFETY: Creating a temporary AF_INET socket for the probe.
    let probe_fd = unsafe { libc::socket(AF_INET, sock_type, 0) };
    if probe_fd < 0 {
        // SAFETY: Restoring saved errno.
        unsafe { *errno_ptr() = saved_errno };
        return false;
    }

    // SAFETY: zeroed sockaddr_in is valid; we set all relevant fields.
    let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
    #[cfg(target_os = "macos")]
    {
        sin.sin_len = std::mem::size_of::<sockaddr_in>() as u8;
    }
    sin.sin_family = AF_INET as _;
    sin.sin_port = port; // already in network byte order
    sin.sin_addr.s_addr = silo_ip;

    // SAFETY: probe_fd is a valid socket; sin is fully initialized.
    let ret = unsafe {
        call_real_bind(
            probe_fd,
            &sin as *const sockaddr_in as *const sockaddr,
            std::mem::size_of::<sockaddr_in>() as socklen_t,
        )
    };

    // SAFETY: Reading errno to check for EADDRINUSE.
    let has_listener = ret < 0 && unsafe { *errno_ptr() } == libc::EADDRINUSE;

    // SAFETY: Closing the temporary probe socket.
    unsafe { libc::close(probe_fd) };

    // SAFETY: Restoring the caller's errno.
    unsafe { *errno_ptr() = saved_errno };

    has_listener
}

/// Conditionally rewrite a connect(2) sockaddr to SILO_IP, but only if
/// the target port has an active listener on SILO_IP.
///
/// Unlike `rewrite_addr` (used for bind/sendto), this function probes the
/// kernel before rewriting, so connections to external services on
/// `127.0.0.1` (e.g. PostgreSQL, Redis) are not hijacked.
///
/// # Safety
///
/// `fd` must be a valid socket. `addr` must be null or a valid, mutable
/// sockaddr whose `sa_family` is initialized. If `AF_INET`, the underlying
/// storage must be a valid `sockaddr_in`. If `AF_INET6`, a valid
/// `sockaddr_in6`.
unsafe fn rewrite_connect_addr(fd: c_int, addr: *const sockaddr) {
    // SAFETY: Caller guarantees addr is null or valid sockaddr.
    let Some(family) = (unsafe { read_sa_family(addr) }) else {
        return;
    };
    let Some(silo_ip) = get_silo_ip() else {
        return;
    };

    if family == AF_INET {
        let sin = addr as *mut sockaddr_in;
        // SAFETY: family == AF_INET; addr is a valid sockaddr_in.
        let s_addr = unsafe { (*sin).sin_addr.s_addr };
        let localhost_be = u32::from(Ipv4Addr::LOCALHOST).to_be();
        if s_addr == localhost_be {
            // SAFETY: Reading port from the valid sockaddr_in.
            let port = unsafe { (*sin).sin_port };
            // SAFETY: fd is valid; port is in network byte order.
            if unsafe { probe_has_listener(fd, silo_ip, port) } {
                // SAFETY: Writing back to the same valid sockaddr_in.
                unsafe { (*sin).sin_addr.s_addr = silo_ip };
            }
        }
    }

    #[cfg(target_os = "linux")]
    if family == libc::AF_INET6 as c_int {
        let sin6 = addr as *mut libc::sockaddr_in6;
        // SAFETY: family == AF_INET6; addr is a valid sockaddr_in6.
        let s6_addr = unsafe { (*sin6).sin6_addr.s6_addr };
        if s6_addr == rewrite::V6_LOOPBACK {
            // SAFETY: Reading port from the valid sockaddr_in6.
            let port = unsafe { (*sin6).sin6_port };
            // SAFETY: fd is valid; port is in network byte order.
            if unsafe { probe_has_listener(fd, silo_ip, port) } {
                let new_addr = rewrite::ipv4_mapped_v6(silo_ip);
                // SAFETY: Writing back to the same valid sockaddr_in6.
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

/// Hide other silo loopback aliases from getifaddrs results.
///
/// For any AF_INET entry whose address is 127.x.x.x but is neither
/// 127.0.0.1 nor SILO_IP, rewrite the address to 127.0.0.1 so that
/// `os.networkInterfaces()` (Node.js etc.) only sees the current session's IP.
///
/// # Safety
///
/// `ifap` must point to a valid `ifaddrs` linked list (as returned by
/// `getifaddrs(3)`). Each node must have a valid `ifa_addr` (or null).
unsafe fn hide_other_silo_aliases(ifap: *mut libc::ifaddrs) {
    let Some(silo_ip) = get_silo_ip() else {
        return;
    };

    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: `cur` is non-null; the linked list is well-formed as
        // guaranteed by getifaddrs(3).
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            // SAFETY: ifa_addr is non-null; reading sa_family is safe on a
            // valid sockaddr.
            let family = unsafe { (*ifa.ifa_addr).sa_family } as c_int;
            if family == AF_INET {
                let sin = ifa.ifa_addr as *mut sockaddr_in;
                // SAFETY: sa_family == AF_INET confirms this is a sockaddr_in.
                let s_addr = unsafe { (*sin).sin_addr.s_addr };
                if let Some(new_addr) = rewrite::hide_alias(s_addr, silo_ip) {
                    // SAFETY: Same pointer validity; writing back to the field.
                    unsafe { (*sin).sin_addr.s_addr = new_addr };
                }
            }
        }
        // SAFETY: ifa is a valid reference; ifa_next is either null or points
        // to the next valid node.
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
            if let Ok(c) = CString::new(candidate) {
                // SAFETY: `c` is a valid, null-terminated CString. access(2)
                // only reads the path and does not modify memory.
                if unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0 {
                    return Some(c);
                }
            }
        }
    }
    None
}

/// Parse the shebang line (`#!interpreter [arg]`) from a file.
///
/// # Safety
///
/// `path` must be a valid, null-terminated C string pointing to an existing
/// file path (or one that can be safely opened — open(2) will return -1 if
/// not found).
#[cfg(target_os = "macos")]
unsafe fn read_shebang_of(path: *const libc::c_char) -> Option<(String, Option<String>)> {
    // SAFETY: `path` is a valid C string. open(2) with O_RDONLY is safe and
    // will return -1 on failure.
    let fd = unsafe { libc::open(path, libc::O_RDONLY) };
    if fd < 0 {
        return None;
    }

    let mut buf = [0u8; 256];
    // SAFETY: `fd` is a valid file descriptor (>= 0). `buf` is a stack buffer
    // with known size. read(2) will write at most `buf.len()` bytes.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    // SAFETY: close(2) on a valid fd is always safe.
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

/// Resolve a SIP-protected executable to a non-SIP alternative.
///
/// If `path` points to a SIP-protected binary (under `/usr/bin/` etc.) or
/// a script with a SIP-protected shebang interpreter, find a non-SIP
/// replacement from `$PATH` and build a new argv if needed.
///
/// # Safety
///
/// - `path` must be a valid, null-terminated C string.
/// - `argv` must be either null or a valid, null-terminated array of C string
///   pointers (as passed to execve(2) / posix_spawn(3)).
#[cfg(target_os = "macos")]
unsafe fn resolve_sip_exec(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
) -> Option<(CString, Vec<CString>, Vec<*const libc::c_char>)> {
    if path.is_null() {
        return None;
    }

    // SAFETY: `path` is non-null and null-terminated (contract of execve/
    // posix_spawn). CStr::from_ptr reads until the null terminator.
    let path_str = unsafe { CStr::from_ptr(path) }.to_str().ok()?;

    if is_sip_path(path_str) {
        let basename = path_str.rsplit('/').next()?;
        let resolved = find_non_sip_in_path(basename)?;
        return Some((resolved, Vec::new(), Vec::new()));
    }

    // SAFETY: `path` is a valid C string; read_shebang_of opens and reads
    // the file safely.
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
        // SAFETY: argv is non-null and null-terminated (execve/posix_spawn
        // contract). We skip argv[0] (the original program name) and copy
        // the remaining arguments.
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

// ---------------------------------------------------------------------------
// macOS constructor: eagerly initialize SILO_IP and debug flag
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// macOS platform: dyld interpose tables and entry points
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    // -- Interpose table types ------------------------------------------------
    //
    // Each `Interpose*` struct is placed in the `__DATA,__interpose` Mach-O
    // section. dyld reads these at load time to replace `original` with
    // `replacement` in all images loaded after this library.

    #[repr(C)]
    struct Interpose {
        replacement: unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int,
        original: unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int,
    }

    // SAFETY: The __DATA,__interpose section is the documented dyld interpose
    // mechanism. The replacement function has the exact same signature as the
    // original, which is required for interposition to be safe.
    #[unsafe(no_mangle)]
    #[used]
    #[unsafe(link_section = "__DATA,__interpose")]
    static INTERPOSE_BIND: Interpose = Interpose {
        replacement: silo_bind_entry,
        original: real_bind,
    };

    // SAFETY: Same as INTERPOSE_BIND.
    #[unsafe(no_mangle)]
    #[used]
    #[unsafe(link_section = "__DATA,__interpose")]
    static INTERPOSE_CONNECT: Interpose = Interpose {
        replacement: silo_connect_entry,
        original: real_connect,
    };

    /// Read the port from a sockaddr, for debug logging.
    ///
    /// # Safety
    ///
    /// `addr` must point to a valid sockaddr matching `family`.
    unsafe fn debug_read_port(addr: *const sockaddr, family: c_int) -> u16 {
        if family == AF_INET {
            // SAFETY: family == AF_INET, addr points to a valid sockaddr_in.
            unsafe { u16::from_be((*(addr as *const sockaddr_in)).sin_port) }
        } else if family == libc::AF_INET6 as c_int {
            // SAFETY: family == AF_INET6, addr points to a valid sockaddr_in6.
            unsafe { u16::from_be((*(addr as *const libc::sockaddr_in6)).sin6_port) }
        } else {
            0
        }
    }

    // -- bind -----------------------------------------------------------------

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_bind_entry(
        fd: c_int,
        addr: *const sockaddr,
        len: socklen_t,
    ) -> c_int {
        if !addr.is_null() {
            // SAFETY: addr is non-null; reading sa_family is safe on any valid
            // sockaddr (guaranteed by the calling program's bind(2) contract).
            let family = unsafe { (*addr).sa_family } as c_int;

            if debug_enabled() {
                // SAFETY: addr is valid and family is known.
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
                // SAFETY: family == AF_INET6, so addr is a valid sockaddr_in6.
                let v6_addr = unsafe { (*sin6).sin6_addr.s6_addr };
                if let Some(ip) = get_silo_ip()
                    && rewrite::rewrite_ipv6_addr(v6_addr, ip, true).is_some()
                {
                    // SAFETY: sin6 is valid; reading sin6_port is safe.
                    let port = unsafe { (*sin6).sin6_port };
                    let ret = unsafe { rebind_as_ipv4(fd, port, ip) };
                    if debug_enabled() {
                        let kind = if v6_addr == rewrite::V6_ANY {
                            "::"
                        } else {
                            "::1"
                        };
                        eprintln!(
                            "[silo-bind] pid={} bind {} → rebind_as_ipv4 → {}",
                            std::process::id(),
                            kind,
                            ret
                        );
                    }
                    return ret;
                }
            }
        }

        // SAFETY: addr is a valid sockaddr (or null, handled by rewrite_addr).
        // Forwarding all arguments to the real bind(2).
        unsafe {
            rewrite_addr(addr, true);
            real_bind(fd, addr, len)
        }
    }

    // -- connect --------------------------------------------------------------

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_connect_entry(
        fd: c_int,
        addr: *const sockaddr,
        len: socklen_t,
    ) -> c_int {
        if !addr.is_null() {
            // SAFETY: addr is non-null; reading sa_family is safe.
            let family = unsafe { (*addr).sa_family } as c_int;

            if family == libc::AF_INET6 as c_int {
                let sin6 = addr as *const libc::sockaddr_in6;
                // SAFETY: family == AF_INET6; reading s6_addr and sin6_port
                // are within bounds of the valid sockaddr_in6.
                let v6_addr = unsafe { (*sin6).sin6_addr.s6_addr };
                if v6_addr == rewrite::V6_LOOPBACK {
                    if let Some(ip) = get_silo_ip() {
                        let port = unsafe { (*sin6).sin6_port };
                        // Only reconnect if SILO_IP:port has a listener.
                        // SAFETY: fd is valid; port is in network byte order.
                        if unsafe { probe_has_listener(fd, ip, port) } {
                            // SAFETY: Valid fd and port; reconnect_as_ipv4
                            // handles socket replacement safely.
                            return unsafe { reconnect_as_ipv4(fd, port, ip) };
                        }
                    }
                    // No listener on SILO_IP — pass through to real connect.
                    return unsafe { real_connect(fd, addr, len) };
                }
            }
        }

        // SAFETY: fd is valid; addr is valid or null. Probe-based rewrite
        // only rewrites if SILO_IP:port has a listener.
        unsafe {
            rewrite_connect_addr(fd, addr);
            real_connect(fd, addr, len)
        }
    }

    // -- IPv6→IPv4 socket replacement -----------------------------------------

    /// Replace an IPv6 socket with an IPv4 socket and bind to `ip:port`.
    ///
    /// Creates a new AF_INET socket, copies all socket options from `fd`,
    /// then uses `dup2` to replace `fd` with the new socket.
    ///
    /// # Safety
    ///
    /// `fd` must be a valid, open socket file descriptor.
    unsafe fn rebind_as_ipv4(fd: c_int, port: u16, ip: u32) -> c_int {
        // SAFETY: fd is a valid socket descriptor.
        if unsafe { replace_with_ipv4(fd) }.is_err() {
            return -1;
        }

        // SAFETY: zeroed sockaddr_in is a valid initial state; all fields
        // are then explicitly set.
        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_len = std::mem::size_of::<sockaddr_in>() as u8;
        sin.sin_family = AF_INET as u8;
        sin.sin_port = port;
        sin.sin_addr.s_addr = ip;

        // SAFETY: fd now refers to an AF_INET socket (via replace_with_ipv4),
        // and sin is a fully-initialized sockaddr_in.
        unsafe {
            real_bind(
                fd,
                &sin as *const sockaddr_in as *const sockaddr,
                std::mem::size_of::<sockaddr_in>() as socklen_t,
            )
        }
    }

    /// Replace an IPv6 socket with an IPv4 socket and connect to `ip:port`.
    ///
    /// # Safety
    ///
    /// `fd` must be a valid, open socket file descriptor.
    unsafe fn reconnect_as_ipv4(fd: c_int, port: u16, ip: u32) -> c_int {
        // SAFETY: fd is a valid socket descriptor.
        if unsafe { replace_with_ipv4(fd) }.is_err() {
            return -1;
        }

        // SAFETY: zeroed sockaddr_in is a valid initial state.
        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_len = std::mem::size_of::<sockaddr_in>() as u8;
        sin.sin_family = AF_INET as u8;
        sin.sin_port = port;
        sin.sin_addr.s_addr = ip;

        // SAFETY: fd is a valid AF_INET socket, sin is fully initialized.
        unsafe {
            real_connect(
                fd,
                &sin as *const sockaddr_in as *const sockaddr,
                std::mem::size_of::<sockaddr_in>() as socklen_t,
            )
        }
    }

    // -- posix_spawn / posix_spawnp / execve (SIP bypass) ---------------------

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

    // SAFETY: Interpose table entry; replacement has the same signature as
    // original, matching the posix_spawn(3) ABI.
    #[unsafe(no_mangle)]
    #[used]
    #[unsafe(link_section = "__DATA,__interpose")]
    static INTERPOSE_POSIX_SPAWN: InterposePosixSpawn = InterposePosixSpawn {
        replacement: silo_posix_spawn_entry,
        original: real_posix_spawn,
    };

    // SAFETY: Same as INTERPOSE_POSIX_SPAWN.
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

    // SAFETY: Interpose table entry; replacement has the same signature as
    // original, matching the execve(2) ABI.
    #[unsafe(no_mangle)]
    #[used]
    #[unsafe(link_section = "__DATA,__interpose")]
    static INTERPOSE_EXECVE: InterposeExecve = InterposeExecve {
        replacement: silo_execve_entry,
        original: real_execve,
    };

    /// Interpose entry for `posix_spawn(3)`.
    ///
    /// If the target binary is SIP-protected, resolve to a non-SIP alternative
    /// so that `DYLD_INSERT_LIBRARIES` is honored in the child process.
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
            // SAFETY: path is non-null and null-terminated (posix_spawn contract).
            let p = unsafe { CStr::from_ptr(path) }.to_string_lossy();
            eprintln!("[silo-bind] posix_spawn called: {}", p);
        }
        // SAFETY: path and argv are valid per posix_spawn(3) contract.
        if let Some((resolved, _owned, new_argv)) =
            unsafe { resolve_sip_exec(path, argv as *const *const libc::c_char) }
        {
            if debug_enabled() {
                // SAFETY: path is non-null (checked by resolve_sip_exec).
                let orig = unsafe { CStr::from_ptr(path) }.to_string_lossy();
                eprintln!(
                    "[silo-bind] posix_spawn: {} → {}",
                    orig,
                    resolved.to_string_lossy()
                );
            }
            // SAFETY: resolved is a valid CString; all other args forwarded
            // from the original call. _owned keeps CStrings alive while ptrs
            // reference them.
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
        // SAFETY: Forwarding all original arguments to real posix_spawn.
        unsafe { real_posix_spawn(pid, path, file_actions, attrp, argv, envp) }
    }

    /// Interpose entry for `posix_spawnp(3)`.
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
            // SAFETY: file is non-null and null-terminated.
            let p = unsafe { CStr::from_ptr(file) }.to_string_lossy();
            eprintln!("[silo-bind] posix_spawnp called: {}", p);
        }
        // SAFETY: file and argv are valid per posix_spawnp(3) contract.
        if let Some((resolved, _owned, new_argv)) =
            unsafe { resolve_sip_exec(file, argv as *const *const libc::c_char) }
        {
            if debug_enabled() {
                // SAFETY: file is non-null (checked by resolve_sip_exec).
                let orig = unsafe { CStr::from_ptr(file) }.to_string_lossy();
                eprintln!(
                    "[silo-bind] posix_spawnp: {} → {}",
                    orig,
                    resolved.to_string_lossy()
                );
            }
            // SAFETY: resolved is a valid CString; _owned keeps referenced
            // CStrings alive.
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
        // SAFETY: Forwarding all original arguments to real posix_spawnp.
        unsafe { real_posix_spawnp(pid, file, file_actions, attrp, argv, envp) }
    }

    /// Interpose entry for `execve(2)`.
    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_execve_entry(
        path: *const libc::c_char,
        argv: *const *const libc::c_char,
        envp: *const *const libc::c_char,
    ) -> c_int {
        if debug_enabled() && !path.is_null() {
            // SAFETY: path is non-null and null-terminated (execve contract).
            let p = unsafe { CStr::from_ptr(path) }.to_string_lossy();
            eprintln!("[silo-bind] execve called: {}", p);
        }
        // SAFETY: path and argv are valid per execve(2) contract.
        if let Some((resolved, _owned, new_argv)) = unsafe { resolve_sip_exec(path, argv) } {
            if debug_enabled() {
                // SAFETY: path is non-null.
                let orig = unsafe { CStr::from_ptr(path) }.to_string_lossy();
                eprintln!(
                    "[silo-bind] execve: {} → {}",
                    orig,
                    resolved.to_string_lossy()
                );
            }
            // SAFETY: resolved is a valid CString; forwarding valid args.
            if new_argv.is_empty() {
                return unsafe { real_execve(resolved.as_ptr(), argv, envp) };
            }
            return unsafe { real_execve(resolved.as_ptr(), new_argv.as_ptr(), envp) };
        }
        // SAFETY: Forwarding all original arguments to real execve.
        unsafe { real_execve(path, argv, envp) }
    }

    // -- sendto ---------------------------------------------------------------

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

    // SAFETY: Interpose table entry; signatures match sendto(2) ABI.
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
        // SAFETY: dest_addr is a valid sockaddr (or null) per sendto(2) contract.
        unsafe { rewrite_addr(dest_addr, true) };
        // SAFETY: Forwarding all arguments to real sendto(2).
        unsafe { real_sendto(fd, buf, len, flags, dest_addr, addrlen) }
    }

    // -- getifaddrs -----------------------------------------------------------

    type GetifaddrsFn = unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> c_int;

    #[repr(C)]
    struct InterposeGetifaddrs {
        replacement: GetifaddrsFn,
        original: GetifaddrsFn,
    }

    // SAFETY: Interpose table entry; signatures match getifaddrs(3) ABI.
    #[unsafe(no_mangle)]
    #[used]
    #[unsafe(link_section = "__DATA,__interpose")]
    static INTERPOSE_GETIFADDRS: InterposeGetifaddrs = InterposeGetifaddrs {
        replacement: silo_getifaddrs_entry,
        original: real_getifaddrs,
    };

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_getifaddrs_entry(ifap: *mut *mut libc::ifaddrs) -> c_int {
        // SAFETY: Forwarding argument to real getifaddrs(3).
        let ret = unsafe { real_getifaddrs(ifap) };
        // SAFETY: ret == 0 means getifaddrs succeeded; ifap and *ifap are
        // valid pointers to the ifaddrs linked list.
        if ret == 0 && !ifap.is_null() && !(unsafe { *ifap }).is_null() {
            if debug_enabled() {
                eprintln!("[silo-bind] getifaddrs intercepted, filtering aliases");
            }
            // SAFETY: *ifap is non-null and points to a valid ifaddrs list.
            unsafe { hide_other_silo_aliases(*ifap) };
        }
        ret
    }

    // -- sendmsg --------------------------------------------------------------

    type SendmsgFn = unsafe extern "C" fn(c_int, *const libc::msghdr, c_int) -> libc::ssize_t;

    #[repr(C)]
    struct InterposeSendmsg {
        replacement: SendmsgFn,
        original: SendmsgFn,
    }

    // SAFETY: Interpose table entry; signatures match sendmsg(2) ABI.
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
            // SAFETY: msg is non-null per our check; reading msg_name and
            // msg_namelen is safe on a valid msghdr (sendmsg(2) contract).
            let msg_ref = unsafe { &*msg };
            if !msg_ref.msg_name.is_null() && msg_ref.msg_namelen > 0 {
                // SAFETY: msg_name is non-null and msg_namelen > 0, so
                // msg_name points to a valid sockaddr.
                unsafe { rewrite_addr(msg_ref.msg_name as *const sockaddr, true) };
            }
        }
        // SAFETY: Forwarding all arguments to real sendmsg(2).
        unsafe { real_sendmsg(fd, msg, flags) }
    }

    // -- Socket replacement helpers -------------------------------------------

    /// Get a `c_int` socket option value.
    ///
    /// # Safety
    ///
    /// `fd` must be a valid socket file descriptor. `level` and `optname`
    /// must be valid for `getsockopt(2)`.
    unsafe fn get_int_sockopt(fd: c_int, level: c_int, optname: c_int) -> Option<c_int> {
        let mut optval: c_int = 0;
        let mut optlen: socklen_t = std::mem::size_of::<c_int>() as socklen_t;
        // SAFETY: fd is valid, optval and optlen are properly sized stack
        // variables. getsockopt reads into optval.
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

    /// Set a `c_int` socket option value.
    ///
    /// # Safety
    ///
    /// `fd` must be a valid socket file descriptor. `level` and `optname`
    /// must be valid for `setsockopt(2)`.
    unsafe fn set_int_sockopt(fd: c_int, level: c_int, optname: c_int, val: c_int) {
        // SAFETY: fd is valid; val is a properly sized stack variable.
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

    /// Copy a boolean socket option (only set on new_fd if non-zero on old_fd).
    ///
    /// # Safety
    ///
    /// Both `old_fd` and `new_fd` must be valid socket file descriptors.
    unsafe fn copy_bool_sockopt(old_fd: c_int, new_fd: c_int, optname: c_int) {
        // SAFETY: Caller guarantees both fds are valid.
        if let Some(val) = unsafe { get_int_sockopt(old_fd, libc::SOL_SOCKET, optname) }
            && val != 0
        {
            unsafe { set_int_sockopt(new_fd, libc::SOL_SOCKET, optname, val) };
        }
    }

    /// Copy an integer socket option unconditionally.
    ///
    /// # Safety
    ///
    /// Both `old_fd` and `new_fd` must be valid socket file descriptors.
    unsafe fn copy_int_sockopt(old_fd: c_int, new_fd: c_int, optname: c_int) {
        // SAFETY: Caller guarantees both fds are valid.
        if let Some(val) = unsafe { get_int_sockopt(old_fd, libc::SOL_SOCKET, optname) } {
            unsafe { set_int_sockopt(new_fd, libc::SOL_SOCKET, optname, val) };
        }
    }

    /// Replace an IPv6 socket `fd` with a new IPv4 socket, preserving all
    /// socket options.
    ///
    /// Uses `dup2(new_fd, fd)` so the file descriptor number is preserved
    /// (important for the caller who already has `fd` in scope).
    ///
    /// # Safety
    ///
    /// `fd` must be a valid, open socket file descriptor.
    unsafe fn replace_with_ipv4(fd: c_int) -> Result<c_int, c_int> {
        // SAFETY: fd is a valid socket. getsockopt reads SO_TYPE into sock_type.
        let sock_type = unsafe { get_int_sockopt(fd, libc::SOL_SOCKET, libc::SO_TYPE) }
            .unwrap_or(libc::SOCK_STREAM);

        // SAFETY: fd is valid; fcntl(F_GETFL) returns the file status flags.
        let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };

        // SAFETY: Creating a new AF_INET socket. Returns -1 on failure.
        let new_fd = unsafe { libc::socket(AF_INET, sock_type, 0) };
        if new_fd < 0 {
            return Err(-1);
        }

        // Copy boolean socket options (only set if non-zero on original)
        for opt in [
            libc::SO_REUSEADDR,
            libc::SO_REUSEPORT,
            libc::SO_KEEPALIVE,
            libc::SO_NOSIGPIPE,
            libc::SO_OOBINLINE,
        ] {
            // SAFETY: Both fd and new_fd are valid socket descriptors.
            unsafe { copy_bool_sockopt(fd, new_fd, opt) };
        }

        // Copy integer socket options unconditionally
        for opt in [
            libc::SO_RCVBUF,
            libc::SO_SNDBUF,
            libc::SO_RCVLOWAT,
            libc::SO_SNDLOWAT,
        ] {
            // SAFETY: Both fd and new_fd are valid socket descriptors.
            unsafe { copy_int_sockopt(fd, new_fd, opt) };
        }

        // SO_LINGER (struct linger)
        {
            // SAFETY: linger is zeroed (valid initial state); getsockopt
            // writes into it. Both fds are valid.
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

        // SO_RCVTIMEO / SO_SNDTIMEO (struct timeval)
        for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            // SAFETY: timeval is zeroed (valid initial state); getsockopt
            // writes into it. Both fds are valid.
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

        // TCP-level options (only for stream sockets)
        if sock_type == libc::SOCK_STREAM {
            for opt in [libc::TCP_NODELAY, libc::TCP_KEEPALIVE] {
                // SAFETY: Both fds are valid; reading/writing TCP-level options.
                if let Some(val) = unsafe { get_int_sockopt(fd, libc::IPPROTO_TCP, opt) }
                    && val != 0
                {
                    unsafe { set_int_sockopt(new_fd, libc::IPPROTO_TCP, opt, val) };
                }
            }
        }

        // SAFETY: Both fds are valid. dup2 atomically replaces fd with new_fd.
        // close releases the temporary new_fd number.
        unsafe {
            libc::dup2(new_fd, fd);
            libc::close(new_fd);
        }

        // SAFETY: fd is valid; restoring the original file status flags.
        if fd_flags >= 0 {
            unsafe { libc::fcntl(fd, libc::F_SETFL, fd_flags) };
        }

        Ok(fd)
    }
}

// ---------------------------------------------------------------------------
// Linux platform: LD_PRELOAD symbol overrides
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    /// Resolve a libc symbol via `dlsym(RTLD_NEXT)` once and cache the result
    /// in a `OnceLock`. Subsequent calls return the cached function pointer
    /// with only an atomic load (no dynamic-linker lock, no library-chain walk).
    ///
    /// # Safety contract
    ///
    /// The caller must ensure that `$ty` exactly matches the true ABI signature
    /// of the symbol named by `$sym`. A mismatch is instant undefined behavior.
    macro_rules! real {
        ($sym:literal, $ty:ty) => {{
            static REAL: OnceLock<$ty> = OnceLock::new();
            *REAL.get_or_init(|| {
                // SAFETY: RTLD_NEXT causes dlsym to search for the *next*
                // definition of `$sym` after this library in the load order,
                // i.e. the real libc implementation. The concat!(...) literal
                // is null-terminated. The transmute is safe because:
                // 1. We assert the pointer is non-null (dlsym succeeded).
                // 2. The caller guarantees $ty matches the real symbol's ABI.
                unsafe {
                    let ptr = libc::dlsym(libc::RTLD_NEXT, concat!($sym, "\0").as_ptr().cast());
                    assert!(
                        !ptr.is_null(),
                        concat!("silo-bind: dlsym failed to resolve ", $sym)
                    );
                    std::mem::transmute(ptr)
                }
            })
        }};
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
        let real_fn = real!(
            "bind",
            unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int
        );
        // SAFETY: addr is a valid sockaddr (or null) per bind(2) contract.
        unsafe { rewrite_addr(addr, true) };
        // SAFETY: Forwarding caller's arguments to the real bind(2).
        unsafe { real_fn(fd, addr, len) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
        let real_fn = real!(
            "connect",
            unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int
        );
        // SAFETY: fd is valid; addr is valid or null per connect(2) contract.
        // Probe-based rewrite only rewrites if SILO_IP:port has a listener.
        unsafe { rewrite_connect_addr(fd, addr) };
        // SAFETY: Forwarding caller's arguments to the real connect(2).
        unsafe { real_fn(fd, addr, len) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn getifaddrs(ifap: *mut *mut libc::ifaddrs) -> c_int {
        let real_fn = real!(
            "getifaddrs",
            unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> c_int
        );
        // SAFETY: Forwarding caller's argument to real getifaddrs(3).
        let ret = unsafe { real_fn(ifap) };
        // SAFETY: ret == 0 means success; ifap and *ifap are valid.
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

        // SAFETY: dest_addr is a valid sockaddr (or null) per sendto(2) contract.
        unsafe { rewrite_addr(dest_addr, true) };
        // SAFETY: Forwarding all arguments to real sendto(2).
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
            // SAFETY: msg is non-null; reading fields from a valid msghdr.
            let msg_ref = unsafe { &*msg };
            if !msg_ref.msg_name.is_null() && msg_ref.msg_namelen > 0 {
                // SAFETY: msg_name is non-null with namelen > 0, so it points
                // to a valid sockaddr per sendmsg(2) contract.
                unsafe { rewrite_addr(msg_ref.msg_name as *const sockaddr, true) };
            }
        }
        // SAFETY: Forwarding all arguments to real sendmsg(2).
        unsafe { real_fn(fd, msg, flags) }
    }
}
