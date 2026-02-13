#![allow(unsafe_op_in_unsafe_fn)]

mod rewrite;

use std::env;
#[cfg(target_os = "macos")]
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

    #[link_name = "gethostbyname"]
    fn real_gethostbyname(name: *const libc::c_char) -> *mut libc::hostent;

    #[link_name = "gethostbyname2"]
    fn real_gethostbyname2(name: *const libc::c_char, af: c_int) -> *mut libc::hostent;

    #[link_name = "getaddrinfo"]
    fn real_getaddrinfo(
        node: *const libc::c_char,
        service: *const libc::c_char,
        hints: *const libc::addrinfo,
        res: *mut *mut libc::addrinfo,
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

/// Rewrite a sockaddr in-place to point at `SILO_IP`.
///
/// When `match_any` is true, INADDR_ANY (`0.0.0.0`) and `::` are also
/// rewritten (appropriate for `bind`/`sendto`). When false, only
/// localhost (`127.0.0.1` / `::1`) is rewritten (appropriate for `connect`).
unsafe fn rewrite_addr(addr: *const sockaddr, match_any: bool) {
    if addr.is_null() {
        return;
    }
    let Some(silo_ip) = get_silo_ip() else {
        return;
    };

    let family = (*addr).sa_family as c_int;

    if family == AF_INET {
        let sin = addr as *mut sockaddr_in;
        if let Some(new_addr) =
            rewrite::rewrite_ipv4_addr((*sin).sin_addr.s_addr, silo_ip, match_any)
        {
            (*sin).sin_addr.s_addr = new_addr;
        }
    }

    #[cfg(target_os = "linux")]
    if family == libc::AF_INET6 as c_int {
        let sin6 = addr as *mut libc::sockaddr_in6;
        if let Some(new_addr) =
            rewrite::rewrite_ipv6_addr((*sin6).sin6_addr.s6_addr, silo_ip, match_any)
        {
            (*sin6).sin6_addr.s6_addr = new_addr;
        }
    }
}

/// Rewrite addresses in a `getaddrinfo` result linked list.
unsafe fn rewrite_addrinfo_results(res: *mut *mut libc::addrinfo) {
    let Some(silo_ip) = get_silo_ip() else {
        return;
    };
    let mut cur = *res;
    while !cur.is_null() {
        let ai = &mut *cur;
        if ai.ai_family == AF_INET && !ai.ai_addr.is_null() {
            let sin = ai.ai_addr as *mut sockaddr_in;
            if let Some(new_addr) = rewrite::rewrite_resolved_ipv4((*sin).sin_addr.s_addr, silo_ip)
            {
                (*sin).sin_addr.s_addr = new_addr;
            }
        } else if ai.ai_family == libc::AF_INET6 as c_int && !ai.ai_addr.is_null() {
            let sin6 = ai.ai_addr as *mut libc::sockaddr_in6;
            if let Some(new_addr) =
                rewrite::rewrite_resolved_ipv6((*sin6).sin6_addr.s6_addr, silo_ip)
            {
                (*sin6).sin6_addr.s6_addr = new_addr;
            }
        }
        cur = ai.ai_next;
    }
}

unsafe fn rewrite_hostent(hp: *mut libc::hostent) {
    if hp.is_null() {
        return;
    }
    let Some(silo_ip) = get_silo_ip() else {
        return;
    };

    // Use addr_of! to avoid creating a reference to a potentially misaligned
    // hostent struct (macOS gethostbyname may return misaligned pointers).
    let h_addrtype = std::ptr::addr_of!((*hp).h_addrtype).read_unaligned();
    let h_length = std::ptr::addr_of!((*hp).h_length).read_unaligned();
    let h_addr_list = std::ptr::addr_of!((*hp).h_addr_list).read_unaligned();

    if h_addrtype == AF_INET && h_length == 4 {
        let mut i = 0usize;
        loop {
            let entry = h_addr_list.add(i).read_unaligned();
            if entry.is_null() {
                break;
            }
            let addr = std::ptr::read_unaligned(entry as *const u32);
            if let Some(new_addr) = rewrite::rewrite_resolved_ipv4(addr, silo_ip) {
                std::ptr::write_unaligned(entry as *mut u32, new_addr);
            }
            i += 1;
        }
    } else if h_addrtype == libc::AF_INET6 && h_length == 16 {
        let mut i = 0usize;
        loop {
            let entry = h_addr_list.add(i).read_unaligned();
            if entry.is_null() {
                break;
            }
            let ptr = entry as *mut u8;
            let mut v6 = [0u8; 16];
            std::ptr::copy_nonoverlapping(ptr, v6.as_mut_ptr(), 16);
            if let Some(new_v6) = rewrite::rewrite_resolved_ipv6(v6, silo_ip) {
                std::ptr::copy_nonoverlapping(new_v6.as_ptr(), ptr, 16);
            }
            i += 1;
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
/// For any AF_INET entry on lo0 whose address is 127.x.x.x but is neither
/// 127.0.0.1 nor SILO_IP, rewrite the address to 127.0.0.1 so that
/// `os.networkInterfaces()` (Node.js etc.) only sees the current session's IP.
unsafe fn hide_other_silo_aliases(ifap: *mut libc::ifaddrs) {
    let Some(silo_ip) = get_silo_ip() else {
        return;
    };

    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = &*cur;
        if !ifa.ifa_addr.is_null() && (*ifa.ifa_addr).sa_family as c_int == AF_INET {
            let sin = ifa.ifa_addr as *mut sockaddr_in;
            if let Some(new_addr) = rewrite::hide_alias((*sin).sin_addr.s_addr, silo_ip) {
                (*sin).sin_addr.s_addr = new_addr;
            }
        }
        cur = (*cur).ifa_next;
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
    let fd = libc::open(path, libc::O_RDONLY);
    if fd < 0 {
        return None;
    }

    let mut buf = [0u8; 256];
    let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
    libc::close(fd);

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

    let path_str = CStr::from_ptr(path).to_str().ok()?;

    if is_sip_path(path_str) {
        let basename = path_str.rsplit('/').next()?;
        let resolved = find_non_sip_in_path(basename)?;
        return Some((resolved, Vec::new(), Vec::new()));
    }

    let (interpreter, arg) = read_shebang_of(path)?;
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
        let mut p = argv.offset(1);
        while !(*p).is_null() {
            ptrs.push(*p);
            p = p.offset(1);
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

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_bind_entry(
        fd: c_int,
        addr: *const sockaddr,
        len: socklen_t,
    ) -> c_int {
        if !addr.is_null() {
            let family = (*addr).sa_family as c_int;

            if debug_enabled() {
                let port = if family == AF_INET {
                    u16::from_be((*(addr as *const sockaddr_in)).sin_port)
                } else if family == libc::AF_INET6 as c_int {
                    u16::from_be((*(addr as *const libc::sockaddr_in6)).sin6_port)
                } else {
                    0
                };
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
                let v6_addr = (*sin6).sin6_addr.s6_addr;
                if let Some(ip) = get_silo_ip()
                    && rewrite::rewrite_ipv6_addr(v6_addr, ip, true).is_some()
                {
                    let ret = rebind_as_ipv4(fd, (*sin6).sin6_port, ip);
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

        rewrite_addr(addr, true);
        real_bind(fd, addr, len)
    }

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_connect_entry(
        fd: c_int,
        addr: *const sockaddr,
        len: socklen_t,
    ) -> c_int {
        if !addr.is_null() {
            let family = (*addr).sa_family as c_int;

            if family == libc::AF_INET6 as c_int {
                let sin6 = addr as *const libc::sockaddr_in6;
                if let Some(ip) = get_silo_ip()
                    && rewrite::rewrite_ipv6_addr((*sin6).sin6_addr.s6_addr, ip, false).is_some()
                {
                    return reconnect_as_ipv4(fd, (*sin6).sin6_port, ip);
                }
            }
        }

        rewrite_addr(addr, false);
        real_connect(fd, addr, len)
    }

    unsafe fn rebind_as_ipv4(fd: c_int, port: u16, ip: u32) -> c_int {
        if replace_with_ipv4(fd).is_err() {
            return -1;
        }

        let mut sin: sockaddr_in = std::mem::zeroed();
        sin.sin_len = std::mem::size_of::<sockaddr_in>() as u8;
        sin.sin_family = AF_INET as u8;
        sin.sin_port = port;
        sin.sin_addr.s_addr = ip;

        real_bind(
            fd,
            &sin as *const sockaddr_in as *const sockaddr,
            std::mem::size_of::<sockaddr_in>() as socklen_t,
        )
    }

    unsafe fn reconnect_as_ipv4(fd: c_int, port: u16, ip: u32) -> c_int {
        if replace_with_ipv4(fd).is_err() {
            return -1;
        }

        let mut sin: sockaddr_in = std::mem::zeroed();
        sin.sin_len = std::mem::size_of::<sockaddr_in>() as u8;
        sin.sin_family = AF_INET as u8;
        sin.sin_port = port;
        sin.sin_addr.s_addr = ip;

        real_connect(
            fd,
            &sin as *const sockaddr_in as *const sockaddr,
            std::mem::size_of::<sockaddr_in>() as socklen_t,
        )
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
            let p = CStr::from_ptr(path).to_string_lossy();
            eprintln!("[silo-bind] posix_spawn called: {}", p);
        }
        if let Some((resolved, _owned, new_argv)) =
            resolve_sip_exec(path, argv as *const *const libc::c_char)
        {
            if debug_enabled() {
                let orig = CStr::from_ptr(path).to_string_lossy();
                eprintln!(
                    "[silo-bind] posix_spawn: {} → {}",
                    orig,
                    resolved.to_string_lossy()
                );
            }
            if new_argv.is_empty() {
                return real_posix_spawn(pid, resolved.as_ptr(), file_actions, attrp, argv, envp);
            }
            return real_posix_spawn(
                pid,
                resolved.as_ptr(),
                file_actions,
                attrp,
                new_argv.as_ptr() as *const *mut libc::c_char,
                envp,
            );
        }
        real_posix_spawn(pid, path, file_actions, attrp, argv, envp)
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
            let p = CStr::from_ptr(file).to_string_lossy();
            eprintln!("[silo-bind] posix_spawnp called: {}", p);
        }
        if let Some((resolved, _owned, new_argv)) =
            resolve_sip_exec(file, argv as *const *const libc::c_char)
        {
            if debug_enabled() {
                let orig = CStr::from_ptr(file).to_string_lossy();
                eprintln!(
                    "[silo-bind] posix_spawnp: {} → {}",
                    orig,
                    resolved.to_string_lossy()
                );
            }
            if new_argv.is_empty() {
                return real_posix_spawn(pid, resolved.as_ptr(), file_actions, attrp, argv, envp);
            }
            return real_posix_spawn(
                pid,
                resolved.as_ptr(),
                file_actions,
                attrp,
                new_argv.as_ptr() as *const *mut libc::c_char,
                envp,
            );
        }
        real_posix_spawnp(pid, file, file_actions, attrp, argv, envp)
    }

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_execve_entry(
        path: *const libc::c_char,
        argv: *const *const libc::c_char,
        envp: *const *const libc::c_char,
    ) -> c_int {
        if debug_enabled() && !path.is_null() {
            let p = CStr::from_ptr(path).to_string_lossy();
            eprintln!("[silo-bind] execve called: {}", p);
        }
        if let Some((resolved, _owned, new_argv)) = resolve_sip_exec(path, argv) {
            if debug_enabled() {
                let orig = CStr::from_ptr(path).to_string_lossy();
                eprintln!(
                    "[silo-bind] execve: {} → {}",
                    orig,
                    resolved.to_string_lossy()
                );
            }
            if new_argv.is_empty() {
                return real_execve(resolved.as_ptr(), argv, envp);
            }
            return real_execve(resolved.as_ptr(), new_argv.as_ptr(), envp);
        }
        real_execve(path, argv, envp)
    }

    type GetaddrinfoFn = unsafe extern "C" fn(
        *const libc::c_char,
        *const libc::c_char,
        *const libc::addrinfo,
        *mut *mut libc::addrinfo,
    ) -> c_int;

    #[repr(C)]
    struct InterposeGetaddrinfo {
        replacement: GetaddrinfoFn,
        original: GetaddrinfoFn,
    }

    #[unsafe(no_mangle)]
    #[used]
    #[unsafe(link_section = "__DATA,__interpose")]
    static INTERPOSE_GETADDRINFO: InterposeGetaddrinfo = InterposeGetaddrinfo {
        replacement: silo_getaddrinfo_entry,
        original: real_getaddrinfo,
    };

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_getaddrinfo_entry(
        node: *const libc::c_char,
        service: *const libc::c_char,
        hints: *const libc::addrinfo,
        res: *mut *mut libc::addrinfo,
    ) -> c_int {
        let ret = real_getaddrinfo(node, service, hints, res);
        if ret != 0 || res.is_null() {
            return ret;
        }

        if debug_enabled() && !res.is_null() {
            let node_str = if !node.is_null() {
                CStr::from_ptr(node).to_string_lossy().into_owned()
            } else {
                "(null)".into()
            };
            eprintln!("[silo-bind] getaddrinfo: {} rewriting → SILO_IP", node_str);
        }

        rewrite_addrinfo_results(res);
        ret
    }

    // --- gethostbyname ---

    type GethostbynameFn = unsafe extern "C" fn(*const libc::c_char) -> *mut libc::hostent;

    #[repr(C)]
    struct InterposeGethostbyname {
        replacement: GethostbynameFn,
        original: GethostbynameFn,
    }

    #[unsafe(no_mangle)]
    #[used]
    #[unsafe(link_section = "__DATA,__interpose")]
    static INTERPOSE_GETHOSTBYNAME: InterposeGethostbyname = InterposeGethostbyname {
        replacement: silo_gethostbyname_entry,
        original: real_gethostbyname,
    };

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_gethostbyname_entry(name: *const libc::c_char) -> *mut libc::hostent {
        let result = real_gethostbyname(name);
        rewrite_hostent(result);
        result
    }

    // --- gethostbyname2 ---

    type Gethostbyname2Fn = unsafe extern "C" fn(*const libc::c_char, c_int) -> *mut libc::hostent;

    #[repr(C)]
    struct InterposeGethostbyname2 {
        replacement: Gethostbyname2Fn,
        original: Gethostbyname2Fn,
    }

    #[unsafe(no_mangle)]
    #[used]
    #[unsafe(link_section = "__DATA,__interpose")]
    static INTERPOSE_GETHOSTBYNAME2: InterposeGethostbyname2 = InterposeGethostbyname2 {
        replacement: silo_gethostbyname2_entry,
        original: real_gethostbyname2,
    };

    #[unsafe(no_mangle)]
    unsafe extern "C" fn silo_gethostbyname2_entry(
        name: *const libc::c_char,
        af: c_int,
    ) -> *mut libc::hostent {
        let result = real_gethostbyname2(name, af);
        rewrite_hostent(result);
        result
    }

    // --- sendto ---

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
        rewrite_addr(dest_addr, true);
        real_sendto(fd, buf, len, flags, dest_addr, addrlen)
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
        let ret = real_getifaddrs(ifap);
        if ret == 0 && !ifap.is_null() && !(*ifap).is_null() {
            if debug_enabled() {
                eprintln!("[silo-bind] getifaddrs intercepted, filtering aliases");
            }
            hide_other_silo_aliases(*ifap);
        }
        ret
    }

    // --- sendmsg ---

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
        if !msg.is_null() && !(*msg).msg_name.is_null() && (*msg).msg_namelen > 0 {
            rewrite_addr((*msg).msg_name as *const sockaddr, true);
        }
        real_sendmsg(fd, msg, flags)
    }

    unsafe fn replace_with_ipv4(fd: c_int) -> Result<c_int, c_int> {
        let mut sock_type: c_int = 0;
        let mut optlen: socklen_t = std::mem::size_of::<c_int>() as socklen_t;
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut sock_type as *mut _ as *mut libc::c_void,
            &mut optlen,
        );

        let fd_flags = libc::fcntl(fd, libc::F_GETFL);

        let new_fd = libc::socket(AF_INET, sock_type, 0);
        if new_fd < 0 {
            return Err(-1);
        }

        // Boolean socket options (copy if non-zero)
        for opt in [
            libc::SO_REUSEADDR,
            libc::SO_REUSEPORT,
            libc::SO_KEEPALIVE,
            libc::SO_NOSIGPIPE,
            libc::SO_OOBINLINE,
        ] {
            let mut optval: c_int = 0;
            optlen = std::mem::size_of::<c_int>() as socklen_t;
            if libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &mut optval as *mut _ as *mut libc::c_void,
                &mut optlen,
            ) == 0
                && optval != 0
            {
                libc::setsockopt(
                    new_fd,
                    libc::SOL_SOCKET,
                    opt,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<c_int>() as socklen_t,
                );
            }
        }

        // Integer socket options (copy unconditionally)
        for opt in [
            libc::SO_RCVBUF,
            libc::SO_SNDBUF,
            libc::SO_RCVLOWAT,
            libc::SO_SNDLOWAT,
        ] {
            let mut optval: c_int = 0;
            optlen = std::mem::size_of::<c_int>() as socklen_t;
            if libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &mut optval as *mut _ as *mut libc::c_void,
                &mut optlen,
            ) == 0
            {
                libc::setsockopt(
                    new_fd,
                    libc::SOL_SOCKET,
                    opt,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of::<c_int>() as socklen_t,
                );
            }
        }

        // SO_LINGER (struct linger)
        {
            let mut linger_val: libc::linger = std::mem::zeroed();
            optlen = std::mem::size_of::<libc::linger>() as socklen_t;
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

        // SO_RCVTIMEO / SO_SNDTIMEO (struct timeval)
        for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            let mut tv: libc::timeval = std::mem::zeroed();
            optlen = std::mem::size_of::<libc::timeval>() as socklen_t;
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

        // TCP-level options (only for stream sockets)
        if sock_type == libc::SOCK_STREAM {
            for opt in [libc::TCP_NODELAY, libc::TCP_KEEPALIVE] {
                let mut optval: c_int = 0;
                optlen = std::mem::size_of::<c_int>() as socklen_t;
                if libc::getsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    opt,
                    &mut optval as *mut _ as *mut libc::c_void,
                    &mut optlen,
                ) == 0
                    && optval != 0
                {
                    libc::setsockopt(
                        new_fd,
                        libc::IPPROTO_TCP,
                        opt,
                        &optval as *const _ as *const libc::c_void,
                        std::mem::size_of::<c_int>() as socklen_t,
                    );
                }
            }
        }

        libc::dup2(new_fd, fd);
        libc::close(new_fd);

        if fd_flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, fd_flags);
        }

        Ok(fd)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    /// Resolve a libc symbol via `dlsym(RTLD_NEXT)` once and cache the result
    /// in a `OnceLock`. Subsequent calls return the cached function pointer
    /// with only an atomic load (no dynamic-linker lock, no library-chain walk).
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
        rewrite_addr(addr, true);
        real_fn(fd, addr, len)
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
        let real_fn = real!(
            "connect",
            unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int
        );
        rewrite_addr(addr, false);
        real_fn(fd, addr, len)
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn getaddrinfo(
        node: *const libc::c_char,
        service: *const libc::c_char,
        hints: *const libc::addrinfo,
        res: *mut *mut libc::addrinfo,
    ) -> c_int {
        let real_fn = real!(
            "getaddrinfo",
            unsafe extern "C" fn(
                *const libc::c_char,
                *const libc::c_char,
                *const libc::addrinfo,
                *mut *mut libc::addrinfo,
            ) -> c_int
        );

        let ret = real_fn(node, service, hints, res);
        if ret != 0 || res.is_null() {
            return ret;
        }

        rewrite_addrinfo_results(res);
        ret
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn gethostbyname(name: *const libc::c_char) -> *mut libc::hostent {
        let real_fn = real!(
            "gethostbyname",
            unsafe extern "C" fn(*const libc::c_char) -> *mut libc::hostent
        );
        let result = real_fn(name);
        rewrite_hostent(result);
        result
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn gethostbyname2(
        name: *const libc::c_char,
        af: c_int,
    ) -> *mut libc::hostent {
        let real_fn = real!(
            "gethostbyname2",
            unsafe extern "C" fn(*const libc::c_char, c_int) -> *mut libc::hostent
        );
        let result = real_fn(name, af);
        rewrite_hostent(result);
        result
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn getifaddrs(ifap: *mut *mut libc::ifaddrs) -> c_int {
        let real_fn = real!(
            "getifaddrs",
            unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> c_int
        );
        let ret = real_fn(ifap);
        if ret == 0 && !ifap.is_null() && !(*ifap).is_null() {
            hide_other_silo_aliases(*ifap);
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

        rewrite_addr(dest_addr, true);
        real_fn(fd, buf, len, flags, dest_addr, addrlen)
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
        if !msg.is_null() && !(*msg).msg_name.is_null() && (*msg).msg_namelen > 0 {
            rewrite_addr((*msg).msg_name as *const sockaddr, true);
        }
        real_fn(fd, msg, flags)
    }
}
