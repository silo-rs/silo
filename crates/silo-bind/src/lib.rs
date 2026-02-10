#![allow(unsafe_op_in_unsafe_fn)]

use std::env;
use std::net::Ipv4Addr;
use std::os::raw::c_int;
use std::sync::OnceLock;

#[cfg(target_os = "macos")]
use std::ffi::{CStr, CString};

use libc::{AF_INET, sockaddr, sockaddr_in, socklen_t};

static SILO_IP: OnceLock<Option<u32>> = OnceLock::new();

static DEBUG: OnceLock<bool> = OnceLock::new();

unsafe extern "C" {
    #[link_name = "bind"]
    fn real_bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int;

    #[link_name = "connect"]
    fn real_connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int;
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
}

unsafe fn rewrite_bind_addr(addr: *const sockaddr) {
    if addr.is_null() {
        return;
    }

    let family = (*addr).sa_family as c_int;

    if family == AF_INET {
        let sin = addr as *mut sockaddr_in;
        let s_addr = (*sin).sin_addr.s_addr;
        if (s_addr == 0 || s_addr == u32::from(Ipv4Addr::LOCALHOST).to_be())
            && let Some(ip_bytes) = get_silo_ip()
        {
            (*sin).sin_addr.s_addr = ip_bytes;
        }
    }

    #[cfg(target_os = "linux")]
    if family == libc::AF_INET6 as c_int {
        let sin6 = addr as *mut libc::sockaddr_in6;
        let v6_addr = (*sin6).sin6_addr.s6_addr;
        let is_any = v6_addr == [0u8; 16];
        let is_loopback = v6_addr == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        if is_any || is_loopback {
            if let Some(ip_bytes) = get_silo_ip() {
                let octets = ip_bytes.to_be_bytes();
                (*sin6).sin6_addr.s6_addr = [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, octets[0], octets[1], octets[2],
                    octets[3],
                ];
            }
        }
    }
}

unsafe fn rewrite_connect_addr(addr: *const sockaddr) {
    if addr.is_null() {
        return;
    }

    let family = (*addr).sa_family as c_int;

    if family == AF_INET {
        let sin = addr as *mut sockaddr_in;
        if (*sin).sin_addr.s_addr == u32::from(Ipv4Addr::LOCALHOST).to_be()
            && let Some(ip_bytes) = get_silo_ip()
        {
            (*sin).sin_addr.s_addr = ip_bytes;
        }
    }

    #[cfg(target_os = "linux")]
    if family == libc::AF_INET6 as c_int {
        let sin6 = addr as *mut libc::sockaddr_in6;
        let loopback_v6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        if (*sin6).sin6_addr.s6_addr == loopback_v6 {
            if let Some(ip_bytes) = get_silo_ip() {
                let octets = ip_bytes.to_be_bytes();
                (*sin6).sin6_addr.s6_addr = [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, octets[0], octets[1], octets[2],
                    octets[3],
                ];
            }
        }
    }
}

unsafe fn rewrite_sendto_addr(addr: *const sockaddr) {
    if addr.is_null() {
        return;
    }

    let family = (*addr).sa_family as c_int;

    if family == AF_INET {
        let sin = addr as *mut sockaddr_in;
        let s_addr = (*sin).sin_addr.s_addr;
        if (s_addr == 0 || s_addr == u32::from(Ipv4Addr::LOCALHOST).to_be())
            && let Some(ip_bytes) = get_silo_ip()
        {
            (*sin).sin_addr.s_addr = ip_bytes;
        }
    }

    #[cfg(target_os = "linux")]
    if family == libc::AF_INET6 as c_int {
        let sin6 = addr as *mut libc::sockaddr_in6;
        let v6_addr = (*sin6).sin6_addr.s6_addr;
        let is_any = v6_addr == [0u8; 16];
        let is_loopback = v6_addr == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        if is_any || is_loopback {
            if let Some(ip_bytes) = get_silo_ip() {
                let octets = ip_bytes.to_be_bytes();
                (*sin6).sin6_addr.s6_addr = [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, octets[0], octets[1], octets[2],
                    octets[3],
                ];
            }
        }
    }
}

fn get_silo_ip() -> Option<u32> {
    *SILO_IP.get_or_init(|| {
        let val = env::var("SILO_IP").ok()?;
        let ip: Ipv4Addr = val.parse().ok()?;
        Some(u32::from(ip).to_be())
    })
}

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
                let is_any = v6_addr == [0u8; 16];
                let is_loopback = v6_addr == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
                if (is_any || is_loopback)
                    && let Some(ip) = get_silo_ip()
                {
                    let ret = rebind_as_ipv4(fd, (*sin6).sin6_port, ip);
                    if debug_enabled() {
                        let kind = if is_any { "::" } else { "::1" };
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

        rewrite_bind_addr(addr);
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
                let loopback_v6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
                if (*sin6).sin6_addr.s6_addr == loopback_v6
                    && let Some(ip) = get_silo_ip()
                {
                    return reconnect_as_ipv4(fd, (*sin6).sin6_port, ip);
                }
            }
        }

        rewrite_connect_addr(addr);
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

        if let Some(silo_ip) = get_silo_ip() {
            let localhost_be = u32::from(Ipv4Addr::LOCALHOST).to_be();
            let mut cur = *res;
            while !cur.is_null() {
                let ai = &mut *cur;
                if ai.ai_family == AF_INET && !ai.ai_addr.is_null() {
                    let sin = ai.ai_addr as *mut sockaddr_in;
                    let addr = (*sin).sin_addr.s_addr;
                    if addr == localhost_be || addr == 0 {
                        if debug_enabled() {
                            let node_str = if !node.is_null() {
                                CStr::from_ptr(node).to_string_lossy().into_owned()
                            } else {
                                "(null)".into()
                            };
                            eprintln!(
                                "[silo-bind] getaddrinfo: {} rewriting {:?} → SILO_IP",
                                node_str,
                                Ipv4Addr::from(u32::from_be(addr)),
                            );
                        }
                        (*sin).sin_addr.s_addr = silo_ip;
                    }
                }
                cur = ai.ai_next;
            }
        }
        ret
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
        rewrite_sendto_addr(dest_addr);
        real_sendto(fd, buf, len, flags, dest_addr, addrlen)
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

        let new_fd = libc::socket(AF_INET, sock_type, 0);
        if new_fd < 0 {
            return Err(-1);
        }

        for opt in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
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

        libc::dup2(new_fd, fd);
        libc::close(new_fd);

        Ok(fd)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
        let real = libc::dlsym(libc::RTLD_NEXT, b"bind\0".as_ptr() as *const _);
        let real_fn: unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int =
            std::mem::transmute(real);

        rewrite_bind_addr(addr);
        real_fn(fd, addr, len)
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
        let real = libc::dlsym(libc::RTLD_NEXT, b"connect\0".as_ptr() as *const _);
        let real_fn: unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int =
            std::mem::transmute(real);

        rewrite_connect_addr(addr);
        real_fn(fd, addr, len)
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn getaddrinfo(
        node: *const libc::c_char,
        service: *const libc::c_char,
        hints: *const libc::addrinfo,
        res: *mut *mut libc::addrinfo,
    ) -> c_int {
        let real = libc::dlsym(libc::RTLD_NEXT, b"getaddrinfo\0".as_ptr() as *const _);
        let real_fn: unsafe extern "C" fn(
            *const libc::c_char,
            *const libc::c_char,
            *const libc::addrinfo,
            *mut *mut libc::addrinfo,
        ) -> c_int = std::mem::transmute(real);

        let ret = real_fn(node, service, hints, res);
        if ret != 0 || res.is_null() {
            return ret;
        }

        if let Some(silo_ip) = get_silo_ip() {
            let localhost_be = u32::from(Ipv4Addr::LOCALHOST).to_be();
            let mut cur = *res;
            while !cur.is_null() {
                let ai = &mut *cur;
                if ai.ai_family == AF_INET && !ai.ai_addr.is_null() {
                    let sin = ai.ai_addr as *mut sockaddr_in;
                    let addr = (*sin).sin_addr.s_addr;
                    if addr == localhost_be || addr == 0 {
                        (*sin).sin_addr.s_addr = silo_ip;
                    }
                }
                cur = ai.ai_next;
            }
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
        let real = libc::dlsym(libc::RTLD_NEXT, b"sendto\0".as_ptr() as *const _);
        let real_fn: unsafe extern "C" fn(
            c_int,
            *const libc::c_void,
            libc::size_t,
            c_int,
            *const sockaddr,
            socklen_t,
        ) -> libc::ssize_t = std::mem::transmute(real);

        rewrite_sendto_addr(dest_addr);
        real_fn(fd, buf, len, flags, dest_addr, addrlen)
    }
}
