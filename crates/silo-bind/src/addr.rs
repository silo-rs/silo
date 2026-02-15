use std::mem::MaybeUninit;
use std::os::raw::c_int;

use libc::{AF_INET, sockaddr, sockaddr_in, socklen_t};

use crate::{connect_enabled, get_silo_ip, rewrite};

#[repr(C)]
pub union SockaddrStorage {
    pub sa: sockaddr,
    pub v4: sockaddr_in,
    pub v6: libc::sockaddr_in6,
}

pub const unsafe fn read_sa_family(addr: *const sockaddr) -> Option<c_int> {
    if addr.is_null() {
        return None;
    }
    Some(unsafe { (*addr).sa_family } as c_int)
}

pub unsafe fn read_port(addr: *const sockaddr, len: socklen_t) -> Option<u16> {
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

pub unsafe fn is_v6only(fd: c_int) -> bool {
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

pub unsafe fn maybe_rewrite_addr(
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

pub unsafe fn maybe_rewrite_connect_addr(
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
            && unsafe { crate::probe::probe_has_listener(fd, silo_ip, sin.sin_port) }
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
            && unsafe { crate::probe::probe_has_listener(fd, silo_ip, sin6.sin6_port) }
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

pub unsafe fn hide_other_silo_aliases(ifap: *mut libc::ifaddrs) {
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

pub unsafe fn bind_prepare_v6(
    fd: c_int,
    addr: *const sockaddr,
    len: socklen_t,
) -> Option<libc::sockaddr_in6> {
    if addr.is_null() {
        return None;
    }
    let family = unsafe { (*addr).sa_family } as c_int;
    if family != libc::AF_INET6 as c_int
        || (len as usize) < std::mem::size_of::<libc::sockaddr_in6>()
    {
        return None;
    }
    let sin6 = unsafe { &*(addr as *const libc::sockaddr_in6) };
    let ip = get_silo_ip()?;
    let new_v6 = rewrite::rewrite_ipv6_addr(sin6.sin6_addr.s6_addr, ip, true)?;
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
    let mut sin6_copy = *sin6;
    sin6_copy.sin6_addr.s6_addr = new_v6;
    Some(sin6_copy)
}

pub unsafe fn prepare_sendmsg(
    msg: *const libc::msghdr,
    msg_buf: &mut libc::msghdr,
    storage: &mut MaybeUninit<SockaddrStorage>,
) -> *const libc::msghdr {
    if msg.is_null() {
        return msg;
    }
    let msg_ref = unsafe { &*msg };
    if msg_ref.msg_name.is_null() || msg_ref.msg_namelen == 0 {
        return msg;
    }
    let (new_addr, new_len) = unsafe {
        maybe_rewrite_addr(
            msg_ref.msg_name as *const sockaddr,
            msg_ref.msg_namelen,
            true,
            storage,
        )
    };
    if new_addr == msg_ref.msg_name as *const sockaddr {
        return msg;
    }
    *msg_buf = *msg_ref;
    msg_buf.msg_name = new_addr as *mut libc::c_void;
    msg_buf.msg_namelen = new_len;
    msg_buf as *const libc::msghdr
}
