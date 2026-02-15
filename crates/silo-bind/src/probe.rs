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
}
