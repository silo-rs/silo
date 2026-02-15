use std::mem::MaybeUninit;
use std::os::raw::c_int;
use std::sync::OnceLock;

use libc::{sockaddr, socklen_t};

use crate::addr::{
    SockaddrStorage, bind_prepare_v6, hide_other_silo_aliases, maybe_rewrite_addr,
    maybe_rewrite_connect_addr, prepare_sendmsg, read_port,
};
use crate::errno_ptr;
use crate::probe;

macro_rules! real {
    ($sym:literal, $ty:ty) => {{
        static REAL: OnceLock<Option<$ty>> = OnceLock::new();
        *REAL.get_or_init(|| unsafe {
            let ptr = libc::dlsym(libc::RTLD_NEXT, concat!($sym, "\0").as_ptr().cast());
            if ptr.is_null() {
                eprintln!(concat!("silo-bind: dlsym failed to resolve ", $sym));
                return None;
            }
            Some(std::mem::transmute::<*mut libc::c_void, $ty>(ptr))
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

    if let Some(sin6_copy) = unsafe { bind_prepare_v6(fd, addr, len) } {
        return unsafe {
            real_fn(
                fd,
                &sin6_copy as *const libc::sockaddr_in6 as *const sockaddr,
                len,
            )
        };
    }

    let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
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
    let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
    let (new_addr, new_len) = unsafe { maybe_rewrite_connect_addr(fd, addr, len, &mut storage) };
    let ret = unsafe { real_fn(fd, new_addr, new_len) };
    if new_addr != addr
        && ret == -1
        && unsafe { *errno_ptr() } == libc::ECONNREFUSED
        && let Some(port) = unsafe { read_port(addr, len) }
    {
        probe::cache_clear_listener(port);
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

    let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
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
    let mut msg_buf: libc::msghdr = unsafe { std::mem::zeroed() };
    let mut storage = MaybeUninit::<SockaddrStorage>::uninit();
    let msg = unsafe { prepare_sendmsg(msg, &mut msg_buf, &mut storage) };
    unsafe { real_fn(fd, msg, flags) }
}
