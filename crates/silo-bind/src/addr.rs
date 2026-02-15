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

impl SockaddrStorage {
    unsafe fn store_v4(
        storage: &mut MaybeUninit<Self>,
        src: &sockaddr_in,
        new_s_addr: u32,
    ) -> *const sockaddr {
        let ptr = storage.as_mut_ptr();
        unsafe {
            (*ptr).v4 = *src;
            (*ptr).v4.sin_addr.s_addr = new_s_addr;
            &(*ptr).sa
        }
    }

    unsafe fn store_v6(
        storage: &mut MaybeUninit<Self>,
        src: &libc::sockaddr_in6,
        new_s6_addr: [u8; 16],
    ) -> *const sockaddr {
        let ptr = storage.as_mut_ptr();
        unsafe {
            (*ptr).v6 = *src;
            (*ptr).v6.sin6_addr.s6_addr = new_s6_addr;
            &(*ptr).sa
        }
    }
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
        if let Some(new_s_addr) =
            rewrite::rewrite_ipv4_addr(sin.sin_addr.s_addr, silo_ip, match_any)
        {
            return (
                unsafe { SockaddrStorage::store_v4(storage, sin, new_s_addr) },
                len,
            );
        }
    }

    if family == libc::AF_INET6 as c_int
        && (len as usize) >= std::mem::size_of::<libc::sockaddr_in6>()
    {
        let sin6 = unsafe { &*(addr as *const libc::sockaddr_in6) };
        if let Some(new_s6_addr) =
            rewrite::rewrite_ipv6_addr(sin6.sin6_addr.s6_addr, silo_ip, match_any)
        {
            return (
                unsafe { SockaddrStorage::store_v6(storage, sin6, new_s6_addr) },
                len,
            );
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
            return (
                unsafe { SockaddrStorage::store_v4(storage, sin, silo_ip) },
                len,
            );
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
            let mapped = rewrite::ipv4_mapped_v6(silo_ip);
            return (
                unsafe { SockaddrStorage::store_v6(storage, sin6, mapped) },
                len,
            );
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn read_sa_family_null_returns_none() {
        assert_eq!(unsafe { read_sa_family(ptr::null()) }, None);
    }

    #[test]
    fn read_sa_family_ipv4() {
        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = AF_INET as _;
        let sa = &sin as *const sockaddr_in as *const sockaddr;
        assert_eq!(unsafe { read_sa_family(sa) }, Some(AF_INET));
    }

    #[test]
    fn read_sa_family_ipv6() {
        let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sin6.sin6_family = libc::AF_INET6 as _;
        let sa = &sin6 as *const libc::sockaddr_in6 as *const sockaddr;
        assert_eq!(unsafe { read_sa_family(sa) }, Some(libc::AF_INET6));
    }

    #[test]
    fn read_port_null_returns_none() {
        assert_eq!(unsafe { read_port(ptr::null(), 0) }, None);
    }

    #[test]
    fn read_port_ipv4() {
        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = AF_INET as _;
        sin.sin_port = 8080u16.to_be();
        let sa = &sin as *const sockaddr_in as *const sockaddr;
        let len = std::mem::size_of::<sockaddr_in>() as socklen_t;
        assert_eq!(unsafe { read_port(sa, len) }, Some(8080u16.to_be()));
    }

    #[test]
    fn read_port_ipv6() {
        let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sin6.sin6_family = libc::AF_INET6 as _;
        sin6.sin6_port = 443u16.to_be();
        let sa = &sin6 as *const libc::sockaddr_in6 as *const sockaddr;
        let len = std::mem::size_of::<libc::sockaddr_in6>() as socklen_t;
        assert_eq!(unsafe { read_port(sa, len) }, Some(443u16.to_be()));
    }

    #[test]
    fn read_port_truncated_ipv4_returns_none() {
        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = AF_INET as _;
        sin.sin_port = 80u16.to_be();
        let sa = &sin as *const sockaddr_in as *const sockaddr;
        let short_len = (std::mem::size_of::<sockaddr_in>() - 1) as socklen_t;
        assert_eq!(unsafe { read_port(sa, short_len) }, None);
    }

    #[test]
    fn read_port_truncated_ipv6_returns_none() {
        let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sin6.sin6_family = libc::AF_INET6 as _;
        sin6.sin6_port = 80u16.to_be();
        let sa = &sin6 as *const libc::sockaddr_in6 as *const sockaddr;
        let short_len = (std::mem::size_of::<libc::sockaddr_in6>() - 1) as socklen_t;
        assert_eq!(unsafe { read_port(sa, short_len) }, None);
    }

    #[test]
    fn read_port_unknown_family_returns_none() {
        let mut sa: sockaddr = unsafe { std::mem::zeroed() };
        sa.sa_family = libc::AF_UNIX as _;
        let len = std::mem::size_of::<sockaddr>() as socklen_t;
        assert_eq!(unsafe { read_port(&sa as *const sockaddr, len) }, None);
    }

    #[test]
    fn prepare_sendmsg_null_msg_returns_null() {
        let mut msg_buf: libc::msghdr = unsafe { std::mem::zeroed() };
        let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
        let result = unsafe { prepare_sendmsg(ptr::null(), &mut msg_buf, &mut storage) };
        assert!(result.is_null());
    }

    #[test]
    fn prepare_sendmsg_null_name_returns_original() {
        let msg: libc::msghdr = unsafe { std::mem::zeroed() };
        let mut msg_buf: libc::msghdr = unsafe { std::mem::zeroed() };
        let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
        let result =
            unsafe { prepare_sendmsg(&msg as *const libc::msghdr, &mut msg_buf, &mut storage) };
        assert_eq!(result, &msg as *const libc::msghdr);
    }

    #[test]
    fn prepare_sendmsg_zero_namelen_returns_original() {
        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = AF_INET as _;
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &mut sin as *mut sockaddr_in as *mut libc::c_void;
        msg.msg_namelen = 0;
        let mut msg_buf: libc::msghdr = unsafe { std::mem::zeroed() };
        let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
        let result =
            unsafe { prepare_sendmsg(&msg as *const libc::msghdr, &mut msg_buf, &mut storage) };
        assert_eq!(result, &msg as *const libc::msghdr);
    }

    #[test]
    fn maybe_rewrite_addr_null_returns_original() {
        let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
        let (out_addr, out_len) = unsafe { maybe_rewrite_addr(ptr::null(), 0, true, &mut storage) };
        assert!(out_addr.is_null());
        assert_eq!(out_len, 0);
    }

    #[test]
    fn maybe_rewrite_addr_unix_passthrough() {
        let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sun.sun_family = libc::AF_UNIX as _;
        let sa = &sun as *const libc::sockaddr_un as *const sockaddr;
        let len = std::mem::size_of::<libc::sockaddr_un>() as socklen_t;
        let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
        let (out_addr, out_len) = unsafe { maybe_rewrite_addr(sa, len, true, &mut storage) };
        assert_eq!(out_addr, sa);
        assert_eq!(out_len, len);
    }

    #[test]
    fn maybe_rewrite_addr_v4_truncated_passthrough() {
        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = AF_INET as _;
        sin.sin_addr.s_addr = 0;
        let sa = &sin as *const sockaddr_in as *const sockaddr;
        let short_len = (std::mem::size_of::<sockaddr_in>() - 1) as socklen_t;
        let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
        let (out_addr, out_len) = unsafe { maybe_rewrite_addr(sa, short_len, true, &mut storage) };
        assert_eq!(out_addr, sa);
        assert_eq!(out_len, short_len);
    }

    #[test]
    fn maybe_rewrite_addr_v6_truncated_passthrough() {
        let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sin6.sin6_family = libc::AF_INET6 as _;
        let sa = &sin6 as *const libc::sockaddr_in6 as *const sockaddr;
        let short_len = (std::mem::size_of::<libc::sockaddr_in6>() - 1) as socklen_t;
        let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
        let (out_addr, out_len) = unsafe { maybe_rewrite_addr(sa, short_len, true, &mut storage) };
        assert_eq!(out_addr, sa);
        assert_eq!(out_len, short_len);
    }

    #[test]
    fn maybe_rewrite_addr_non_loopback_v4_passthrough() {
        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = AF_INET as _;
        sin.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::new(192, 168, 1, 1)).to_be();
        sin.sin_port = 8080u16.to_be();
        let sa = &sin as *const sockaddr_in as *const sockaddr;
        let len = std::mem::size_of::<sockaddr_in>() as socklen_t;
        let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
        let (out_addr, out_len) = unsafe { maybe_rewrite_addr(sa, len, true, &mut storage) };
        assert_eq!(out_addr, sa);
        assert_eq!(out_len, len);
    }

    #[test]
    fn maybe_rewrite_addr_non_loopback_v6_passthrough() {
        let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sin6.sin6_family = libc::AF_INET6 as _;
        sin6.sin6_addr.s6_addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let sa = &sin6 as *const libc::sockaddr_in6 as *const sockaddr;
        let len = std::mem::size_of::<libc::sockaddr_in6>() as socklen_t;
        let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
        let (out_addr, out_len) = unsafe { maybe_rewrite_addr(sa, len, true, &mut storage) };
        assert_eq!(out_addr, sa);
        assert_eq!(out_len, len);
    }

    #[test]
    fn maybe_rewrite_addr_preserves_port() {
        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = AF_INET as _;
        sin.sin_addr.s_addr = 0;
        sin.sin_port = 3000u16.to_be();
        let sa = &sin as *const sockaddr_in as *const sockaddr;
        let len = std::mem::size_of::<sockaddr_in>() as socklen_t;
        let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
        let (out_addr, out_len) = unsafe { maybe_rewrite_addr(sa, len, true, &mut storage) };
        let out_sin = unsafe { &*(out_addr as *const sockaddr_in) };
        assert_eq!(out_sin.sin_port, 3000u16.to_be());
        assert_eq!(out_len, len);
    }

    #[test]
    fn maybe_rewrite_addr_zero_len_passthrough() {
        let sin: sockaddr_in = unsafe { std::mem::zeroed() };
        let sa = &sin as *const sockaddr_in as *const sockaddr;
        let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
        let (out_addr, out_len) = unsafe { maybe_rewrite_addr(sa, 0, true, &mut storage) };
        assert_eq!(out_addr, sa);
        assert_eq!(out_len, 0);
    }

    #[test]
    fn maybe_rewrite_connect_addr_null_returns_original() {
        let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
        let (out_addr, out_len) =
            unsafe { maybe_rewrite_connect_addr(-1, ptr::null(), 0, &mut storage) };
        assert!(out_addr.is_null());
        assert_eq!(out_len, 0);
    }

    #[test]
    fn maybe_rewrite_connect_addr_unix_passthrough() {
        let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sun.sun_family = libc::AF_UNIX as _;
        let sa = &sun as *const libc::sockaddr_un as *const sockaddr;
        let len = std::mem::size_of::<libc::sockaddr_un>() as socklen_t;
        let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
        let (out_addr, out_len) = unsafe { maybe_rewrite_connect_addr(-1, sa, len, &mut storage) };
        assert_eq!(out_addr, sa);
        assert_eq!(out_len, len);
    }

    #[test]
    fn maybe_rewrite_connect_addr_v4_truncated_passthrough() {
        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = AF_INET as _;
        sin.sin_addr.s_addr = rewrite::LOCALHOST_NBO;
        let sa = &sin as *const sockaddr_in as *const sockaddr;
        let short_len = (std::mem::size_of::<sockaddr_in>() - 1) as socklen_t;
        let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
        let (out_addr, out_len) =
            unsafe { maybe_rewrite_connect_addr(-1, sa, short_len, &mut storage) };
        assert_eq!(out_addr, sa);
        assert_eq!(out_len, short_len);
    }

    #[test]
    fn bind_prepare_v6_null_returns_none() {
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
        let result = unsafe { bind_prepare_v6(fd, ptr::null(), 0) };
        assert!(result.is_none());
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }

    #[test]
    fn bind_prepare_v6_ipv4_returns_none() {
        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = AF_INET as _;
        let sa = &sin as *const sockaddr_in as *const sockaddr;
        let len = std::mem::size_of::<sockaddr_in>() as socklen_t;
        let fd = unsafe { libc::socket(AF_INET, libc::SOCK_STREAM, 0) };
        let result = unsafe { bind_prepare_v6(fd, sa, len) };
        assert!(result.is_none());
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }

    #[test]
    fn bind_prepare_v6_truncated_returns_none() {
        let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sin6.sin6_family = libc::AF_INET6 as _;
        let sa = &sin6 as *const libc::sockaddr_in6 as *const sockaddr;
        let short_len = (std::mem::size_of::<libc::sockaddr_in6>() - 1) as socklen_t;
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
        let result = unsafe { bind_prepare_v6(fd, sa, short_len) };
        assert!(result.is_none());
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }

    #[test]
    fn bind_prepare_v6_non_rewritable_addr_returns_none() {
        let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sin6.sin6_family = libc::AF_INET6 as _;
        sin6.sin6_addr.s6_addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let sa = &sin6 as *const libc::sockaddr_in6 as *const sockaddr;
        let len = std::mem::size_of::<libc::sockaddr_in6>() as socklen_t;
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
        let result = unsafe { bind_prepare_v6(fd, sa, len) };
        assert!(result.is_none());
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }

    #[test]
    fn prepare_sendmsg_with_unix_name_passthrough() {
        let mut sun: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sun.sun_family = libc::AF_UNIX as _;
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &mut sun as *mut libc::sockaddr_un as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_un>() as socklen_t;
        let mut msg_buf: libc::msghdr = unsafe { std::mem::zeroed() };
        let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
        let result =
            unsafe { prepare_sendmsg(&msg as *const libc::msghdr, &mut msg_buf, &mut storage) };
        assert_eq!(result, &msg as *const libc::msghdr);
    }

    #[test]
    fn prepare_sendmsg_with_inet4_name_passthrough() {
        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = AF_INET as _;
        sin.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::new(10, 0, 0, 1)).to_be();
        sin.sin_port = 8080u16.to_be();
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &mut sin as *mut sockaddr_in as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<sockaddr_in>() as socklen_t;
        let mut msg_buf: libc::msghdr = unsafe { std::mem::zeroed() };
        let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
        let result =
            unsafe { prepare_sendmsg(&msg as *const libc::msghdr, &mut msg_buf, &mut storage) };
        assert_eq!(result, &msg as *const libc::msghdr);
    }

    #[test]
    fn read_port_zero_len_returns_none() {
        let sin: sockaddr_in = unsafe { std::mem::zeroed() };
        let sa = &sin as *const sockaddr_in as *const sockaddr;
        assert_eq!(unsafe { read_port(sa, 0) }, None);
    }

    #[test]
    fn read_port_exact_v4_len() {
        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = AF_INET as _;
        sin.sin_port = 3000u16.to_be();
        let sa = &sin as *const sockaddr_in as *const sockaddr;
        let len = std::mem::size_of::<sockaddr_in>() as socklen_t;
        assert_eq!(unsafe { read_port(sa, len) }, Some(3000u16.to_be()));
    }

    #[test]
    fn read_port_exact_v6_len() {
        let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        sin6.sin6_family = libc::AF_INET6 as _;
        sin6.sin6_port = 8443u16.to_be();
        let sa = &sin6 as *const libc::sockaddr_in6 as *const sockaddr;
        let len = std::mem::size_of::<libc::sockaddr_in6>() as socklen_t;
        assert_eq!(unsafe { read_port(sa, len) }, Some(8443u16.to_be()));
    }
}
