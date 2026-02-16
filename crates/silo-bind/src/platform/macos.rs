use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::net::Ipv4Addr;
use std::os::raw::c_int;

use libc::{AF_INET, sockaddr, sockaddr_in, socklen_t};

use crate::addr::{
    SockaddrStorage, bind_prepare_v6, hide_other_silo_aliases, is_v6only, maybe_rewrite_addr,
    maybe_rewrite_connect_addr, prepare_sendmsg, read_port,
};
use crate::probe;
use crate::sip::resolve_sip_exec;
use crate::{
    connect_enabled, debug_enabled, errno_ptr, get_silo_ip, real_bind, real_connect, real_execve,
    real_getifaddrs, real_posix_spawn, real_posix_spawnp, real_sendmsg, real_sendto, rewrite,
};

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
unsafe extern "C" fn silo_bind_entry(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    if !addr.is_null() && debug_enabled() {
        let family = unsafe { (*addr).sa_family } as c_int;
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

    if let Some(sin6_copy) = unsafe { bind_prepare_v6(fd, addr, len) } {
        let ret = unsafe {
            real_bind(
                fd,
                &sin6_copy as *const libc::sockaddr_in6 as *const sockaddr,
                len,
            )
        };
        if debug_enabled() {
            eprintln!(
                "[silo-bind] pid={} bind v6 → ::ffff:SILO_IP → {}",
                std::process::id(),
                ret
            );
        }
        return ret;
    }

    if !addr.is_null() {
        let family = unsafe { (*addr).sa_family } as c_int;
        if family == libc::AF_INET6 as c_int && unsafe { is_v6only(fd) } {
            return unsafe { real_bind(fd, addr, len) };
        }
    }

    let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
    let (addr, len) = unsafe { maybe_rewrite_addr(addr, len, true, &mut storage) };
    unsafe { real_bind(fd, addr, len) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn silo_connect_entry(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
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
                    if unsafe { probe::probe_has_listener(fd, ip, port) } {
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
                            probe::cache_clear_listener(port);
                        }
                        return ret;
                    }
                }
                return unsafe { real_connect(fd, addr, len) };
            }
        }
    }

    let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
    let (new_addr, new_len) = unsafe { maybe_rewrite_connect_addr(fd, addr, len, &mut storage) };
    let ret = unsafe { real_connect(fd, new_addr, new_len) };
    if new_addr != addr
        && ret == -1
        && unsafe { *errno_ptr() } == libc::ECONNREFUSED
        && let Some(port) = unsafe { read_port(addr, len) }
    {
        probe::cache_clear_listener(port);
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

#[allow(clippy::too_many_arguments)]
unsafe fn spawn_common(
    pid: *mut libc::pid_t,
    path: *const libc::c_char,
    file_actions: *const libc::c_void,
    attrp: *const libc::c_void,
    argv: *const *mut libc::c_char,
    envp: *const *mut libc::c_char,
    label: &str,
    fallback: PosixSpawnFn,
) -> c_int {
    if debug_enabled() && !path.is_null() {
        let p = unsafe { CStr::from_ptr(path) }.to_string_lossy();
        eprintln!("[silo-bind] {} called: {}", label, p);
    }
    if let Some((resolved, _owned, new_argv)) =
        unsafe { resolve_sip_exec(path, argv as *const *const libc::c_char) }
    {
        if debug_enabled() {
            let orig = unsafe { CStr::from_ptr(path) }.to_string_lossy();
            eprintln!(
                "[silo-bind] {}: {} → {}",
                label,
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
    unsafe { fallback(pid, path, file_actions, attrp, argv, envp) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn silo_posix_spawn_entry(
    pid: *mut libc::pid_t,
    path: *const libc::c_char,
    file_actions: *const libc::c_void,
    attrp: *const libc::c_void,
    argv: *const *mut libc::c_char,
    envp: *const *mut libc::c_char,
) -> c_int {
    unsafe {
        spawn_common(
            pid,
            path,
            file_actions,
            attrp,
            argv,
            envp,
            "posix_spawn",
            real_posix_spawn,
        )
    }
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
    unsafe {
        spawn_common(
            pid,
            file,
            file_actions,
            attrp,
            argv,
            envp,
            "posix_spawnp",
            real_posix_spawnp,
        )
    }
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
    let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
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
    let mut msg_buf: libc::msghdr = unsafe { std::mem::zeroed() };
    let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
    let msg = unsafe { prepare_sendmsg(msg, &mut msg_buf, &mut storage) };
    unsafe { real_sendmsg(fd, msg, flags) }
}
