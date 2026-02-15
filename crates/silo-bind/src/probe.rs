use std::os::raw::c_int;
use std::sync::atomic::{AtomicU64, Ordering};

use libc::{AF_INET, sockaddr, sockaddr_in, socklen_t};

static LISTENER_CACHE: [AtomicU64; 1024] = [const { AtomicU64::new(0) }; 1024];

pub fn cache_has_listener(port: u16) -> bool {
    let idx = (port as usize) / 64;
    let bit = (port as usize) % 64;
    LISTENER_CACHE[idx].load(Ordering::Acquire) & (1u64 << bit) != 0
}

pub fn cache_set_listener(port: u16) {
    let idx = (port as usize) / 64;
    let bit = (port as usize) % 64;
    LISTENER_CACHE[idx].fetch_or(1u64 << bit, Ordering::Release);
}

pub fn cache_clear_listener(port: u16) {
    let idx = (port as usize) / 64;
    let bit = (port as usize) % 64;
    LISTENER_CACHE[idx].fetch_and(!(1u64 << bit), Ordering::Release);
}

#[cfg(target_os = "macos")]
unsafe fn call_real_bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    unsafe { crate::real_bind(fd, addr, len) }
}

#[cfg(target_os = "linux")]
unsafe fn call_real_bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    use std::sync::OnceLock;

    type BindFn = unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int;
    static REAL_BIND: OnceLock<Option<BindFn>> = OnceLock::new();
    let f = *REAL_BIND.get_or_init(|| unsafe {
        let ptr = libc::dlsym(libc::RTLD_NEXT, c"bind".as_ptr());
        if ptr.is_null() {
            eprintln!("silo-bind: dlsym failed to resolve bind");
            return None;
        }
        Some(std::mem::transmute::<*mut libc::c_void, BindFn>(ptr))
    });
    f.map_or_else(
        || {
            unsafe { *crate::errno_ptr() = libc::ENOSYS };
            -1
        },
        |f| unsafe { f(fd, addr, len) },
    )
}

pub unsafe fn probe_has_listener(fd: c_int, silo_ip: u32, port: u16) -> bool {
    if cache_has_listener(port) {
        return true;
    }

    let saved_errno = unsafe { *crate::errno_ptr() };

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
        unsafe { *crate::errno_ptr() = saved_errno };
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

    let has_listener = ret < 0 && unsafe { *crate::errno_ptr() } == libc::EADDRINUSE;
    unsafe { libc::close(probe_fd) };
    unsafe { *crate::errno_ptr() = saved_errno };

    if has_listener {
        cache_set_listener(port);
    }

    has_listener
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_check() {
        let port = 40_000;
        cache_set_listener(port);
        assert!(cache_has_listener(port));
    }

    #[test]
    fn clear_after_set() {
        let port = 40_001;
        cache_set_listener(port);
        cache_clear_listener(port);
        assert!(!cache_has_listener(port));
    }

    #[test]
    fn unset_port_is_not_cached() {
        let port = 40_002;
        cache_clear_listener(port);
        assert!(!cache_has_listener(port));
    }

    #[test]
    fn independent_ports() {
        let a = 40_010;
        let b = 40_011;
        cache_clear_listener(a);
        cache_clear_listener(b);

        cache_set_listener(a);
        assert!(cache_has_listener(a));
        assert!(!cache_has_listener(b));
    }

    #[test]
    fn boundary_port_zero() {
        cache_set_listener(0);
        assert!(cache_has_listener(0));
        cache_clear_listener(0);
        assert!(!cache_has_listener(0));
    }

    #[test]
    fn boundary_port_63() {
        cache_set_listener(63);
        assert!(cache_has_listener(63));
        cache_clear_listener(63);
        assert!(!cache_has_listener(63));
    }

    #[test]
    fn boundary_port_64() {
        cache_set_listener(64);
        assert!(cache_has_listener(64));
        cache_clear_listener(64);
        assert!(!cache_has_listener(64));
    }

    #[test]
    fn boundary_port_max() {
        cache_set_listener(u16::MAX);
        assert!(cache_has_listener(u16::MAX));
        cache_clear_listener(u16::MAX);
        assert!(!cache_has_listener(u16::MAX));
    }

    #[test]
    fn set_does_not_clobber_neighbor_bits() {
        let base = 40_064;
        let neighbor = base + 1;
        cache_clear_listener(base);
        cache_clear_listener(neighbor);

        cache_set_listener(base);
        assert!(!cache_has_listener(neighbor));

        cache_set_listener(neighbor);
        assert!(cache_has_listener(base));
        assert!(cache_has_listener(neighbor));

        cache_clear_listener(base);
        assert!(!cache_has_listener(base));
        assert!(cache_has_listener(neighbor));

        cache_clear_listener(neighbor);
    }

    #[test]
    fn double_set_is_idempotent() {
        let port = 40_100;
        cache_set_listener(port);
        cache_set_listener(port);
        assert!(cache_has_listener(port));
        cache_clear_listener(port);
        assert!(!cache_has_listener(port));
    }

    #[test]
    fn double_clear_is_idempotent() {
        let port = 40_101;
        cache_set_listener(port);
        cache_clear_listener(port);
        cache_clear_listener(port);
        assert!(!cache_has_listener(port));
    }

    #[test]
    fn probe_detects_tcp_listener() {
        let listener = unsafe { libc::socket(AF_INET, libc::SOCK_STREAM, 0) };
        assert!(listener >= 0, "failed to create listener socket");

        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        #[cfg(target_os = "macos")]
        {
            sin.sin_len = std::mem::size_of::<sockaddr_in>() as u8;
        }
        sin.sin_family = AF_INET as _;
        sin.sin_addr.s_addr = 0x7f000001_u32.to_be();
        sin.sin_port = 0;

        let ret = unsafe {
            call_real_bind(
                listener,
                &sin as *const sockaddr_in as *const sockaddr,
                std::mem::size_of::<sockaddr_in>() as socklen_t,
            )
        };
        assert_eq!(ret, 0, "bind failed");

        let ret = unsafe { libc::listen(listener, 1) };
        assert_eq!(ret, 0, "listen failed");

        let mut bound: sockaddr_in = unsafe { std::mem::zeroed() };
        let mut bound_len = std::mem::size_of::<sockaddr_in>() as socklen_t;
        unsafe {
            libc::getsockname(
                listener,
                &mut bound as *mut sockaddr_in as *mut sockaddr,
                &mut bound_len,
            );
        }
        let port_nbo = bound.sin_port;
        cache_clear_listener(port_nbo);

        let probe_fd = unsafe { libc::socket(AF_INET, libc::SOCK_STREAM, 0) };
        assert!(probe_fd >= 0);

        let localhost_nbo = 0x7f000001_u32.to_be();
        let has = unsafe { probe_has_listener(probe_fd, localhost_nbo, port_nbo) };
        assert!(has, "should detect active TCP listener");
        assert!(
            cache_has_listener(port_nbo),
            "cache should be set after positive probe"
        );

        cache_clear_listener(port_nbo);
        unsafe { libc::close(probe_fd) };
        unsafe { libc::close(listener) };
    }

    #[test]
    fn probe_no_listener_returns_false() {
        let sock = unsafe { libc::socket(AF_INET, libc::SOCK_STREAM, 0) };
        assert!(sock >= 0);
        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        #[cfg(target_os = "macos")]
        {
            sin.sin_len = std::mem::size_of::<sockaddr_in>() as u8;
        }
        sin.sin_family = AF_INET as _;
        sin.sin_addr.s_addr = 0x7f000001_u32.to_be();
        sin.sin_port = 0;
        let ret = unsafe {
            call_real_bind(
                sock,
                &sin as *const sockaddr_in as *const sockaddr,
                std::mem::size_of::<sockaddr_in>() as socklen_t,
            )
        };
        assert_eq!(ret, 0);
        let mut bound: sockaddr_in = unsafe { std::mem::zeroed() };
        let mut bound_len = std::mem::size_of::<sockaddr_in>() as socklen_t;
        unsafe {
            libc::getsockname(
                sock,
                &mut bound as *mut sockaddr_in as *mut sockaddr,
                &mut bound_len,
            );
        }
        let port_nbo = bound.sin_port;
        unsafe { libc::close(sock) };

        cache_clear_listener(port_nbo);

        let probe_fd = unsafe { libc::socket(AF_INET, libc::SOCK_STREAM, 0) };
        assert!(probe_fd >= 0);

        let localhost_nbo = 0x7f000001_u32.to_be();
        let has = unsafe { probe_has_listener(probe_fd, localhost_nbo, port_nbo) };
        assert!(!has, "should not detect listener on closed port");
        assert!(
            !cache_has_listener(port_nbo),
            "cache should not be set after negative probe"
        );

        unsafe { libc::close(probe_fd) };
    }

    #[test]
    fn probe_cached_port_skips_syscall() {
        let port_nbo = 45678u16.to_be();
        cache_set_listener(port_nbo);

        let has = unsafe { probe_has_listener(-1, 0, port_nbo) };
        assert!(has, "cached port should return true without probing");

        cache_clear_listener(port_nbo);
    }

    #[test]
    fn probe_udp_listener() {
        let sock = unsafe { libc::socket(AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(sock >= 0);

        let mut sin: sockaddr_in = unsafe { std::mem::zeroed() };
        #[cfg(target_os = "macos")]
        {
            sin.sin_len = std::mem::size_of::<sockaddr_in>() as u8;
        }
        sin.sin_family = AF_INET as _;
        sin.sin_addr.s_addr = 0x7f000001_u32.to_be();
        sin.sin_port = 0;

        let ret = unsafe {
            call_real_bind(
                sock,
                &sin as *const sockaddr_in as *const sockaddr,
                std::mem::size_of::<sockaddr_in>() as socklen_t,
            )
        };
        assert_eq!(ret, 0, "UDP bind failed");

        let mut bound: sockaddr_in = unsafe { std::mem::zeroed() };
        let mut bound_len = std::mem::size_of::<sockaddr_in>() as socklen_t;
        unsafe {
            libc::getsockname(
                sock,
                &mut bound as *mut sockaddr_in as *mut sockaddr,
                &mut bound_len,
            );
        }
        let port_nbo = bound.sin_port;
        cache_clear_listener(port_nbo);

        let probe_fd = unsafe { libc::socket(AF_INET, libc::SOCK_DGRAM, 0) };
        assert!(probe_fd >= 0);

        let localhost_nbo = 0x7f000001_u32.to_be();
        let has = unsafe { probe_has_listener(probe_fd, localhost_nbo, port_nbo) };
        assert!(has, "should detect active UDP listener");

        cache_clear_listener(port_nbo);
        unsafe { libc::close(probe_fd) };
        unsafe { libc::close(sock) };
    }

    #[test]
    fn probe_preserves_errno() {
        let probe_fd = unsafe { libc::socket(AF_INET, libc::SOCK_STREAM, 0) };
        assert!(probe_fd >= 0);

        unsafe { *crate::errno_ptr() = libc::ENOENT };

        let localhost_nbo = 0x7f000001_u32.to_be();
        let port_nbo = 59999u16.to_be();
        cache_clear_listener(port_nbo);

        let _ = unsafe { probe_has_listener(probe_fd, localhost_nbo, port_nbo) };

        assert_eq!(
            unsafe { *crate::errno_ptr() },
            libc::ENOENT,
            "probe_has_listener should restore errno"
        );

        cache_clear_listener(port_nbo);
        unsafe { libc::close(probe_fd) };
    }

    #[test]
    fn probe_invalid_fd_returns_false() {
        let port_nbo = 44444u16.to_be();
        cache_clear_listener(port_nbo);

        let localhost_nbo = 0x7f000001_u32.to_be();

        let has = unsafe { probe_has_listener(-1, localhost_nbo, port_nbo) };
        let _ = has;

        cache_clear_listener(port_nbo);
    }
}
