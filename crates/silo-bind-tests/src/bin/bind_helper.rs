use std::env;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, TcpListener, UdpSocket};
use std::os::unix::net::UnixListener;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: bind-helper <command> [args...]");
        eprintln!(
            "commands: bind_any, bind_localhost, connect_localhost, getaddrinfo, sendto_any, passthrough"
        );
        std::process::exit(1);
    }

    let result = match args[1].as_str() {
        "bind_any" => cmd_bind(Ipv4Addr::UNSPECIFIED),
        "bind_localhost" => cmd_bind(Ipv4Addr::LOCALHOST),
        "connect_localhost" => cmd_connect_localhost(),
        "connect_no_listener" => cmd_connect_no_listener(),
        "getaddrinfo" => cmd_getaddrinfo(),
        "getaddrinfo_v6" => cmd_getaddrinfo_v6(),
        "sendto_any" => cmd_sendto(Ipv4Addr::UNSPECIFIED),
        "gethostbyname" => cmd_gethostbyname(),
        "gethostbyname2" => cmd_gethostbyname2(),
        "sendmsg_localhost" => cmd_sendmsg_localhost(),
        #[cfg(target_os = "macos")]
        "bind_v6_opts" => cmd_bind_v6_opts(),
        #[cfg(target_os = "macos")]
        "bind_v6_dualstack" => cmd_bind_v6_dualstack(),
        #[cfg(target_os = "macos")]
        "bind_v6_v6only" => cmd_bind_v6_v6only(),
        #[cfg(target_os = "macos")]
        "bind_v6_kqueue" => cmd_bind_v6_kqueue(),
        "passthrough" => cmd_bind(Ipv4Addr::UNSPECIFIED),
        "bind_unix" => cmd_bind_unix(),
        "errno_after_connect" => cmd_errno_after_connect(),
        "bind_v6_any_linux" => cmd_bind_v6(Ipv6Addr::UNSPECIFIED),
        "bind_v6_localhost_linux" => cmd_bind_v6(Ipv6Addr::LOCALHOST),
        "connect_v6_localhost" => cmd_connect_v6_localhost(),
        "concurrent_bind" => cmd_concurrent_bind(),
        "connect_cache_hit" => cmd_connect_cache_hit(),
        "connect_cache_invalidation" => cmd_connect_cache_invalidation(),
        "connect_cache_full_cycle" => cmd_connect_cache_full_cycle(),
        "connect_cache_port_isolation" => cmd_connect_cache_port_isolation(),
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(1);
        }
    };

    match result {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_bind(addr: Ipv4Addr) -> io::Result<()> {
    let listener = TcpListener::bind(SocketAddrV4::new(addr, 0))?;
    let local = listener.local_addr()?;
    println!("bound={local}");
    Ok(())
}

fn cmd_connect_localhost() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let listener_addr = listener.local_addr()?;
    let stream = std::net::TcpStream::connect(format!("127.0.0.1:{}", listener_addr.port()))?;
    let peer = stream.peer_addr()?;
    println!("connected={peer}");
    Ok(())
}

fn cmd_connect_no_listener() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    match std::net::TcpStream::connect(format!("127.0.0.1:{port}")) {
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            println!("connect_result=refused");
        }
        Ok(stream) => {
            let peer = stream.peer_addr()?;
            println!("connect_result=connected:{peer}");
        }
        Err(e) => {
            println!("connect_result=error:{e}");
        }
    }
    Ok(())
}

fn cmd_getaddrinfo() -> io::Result<()> {
    use std::ffi::CString;
    use std::ptr;
    let node = CString::new("localhost").unwrap();
    let mut res: *mut libc::addrinfo = ptr::null_mut();
    let hints = libc::addrinfo {
        ai_flags: 0,
        ai_family: libc::AF_INET,
        ai_socktype: libc::SOCK_STREAM,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: ptr::null_mut(),
        ai_canonname: ptr::null_mut(),
        ai_next: ptr::null_mut(),
    };
    let ret = unsafe { libc::getaddrinfo(node.as_ptr(), ptr::null(), &hints, &mut res) };
    if ret != 0 {
        eprintln!("getaddrinfo failed: {ret}");
        std::process::exit(1);
    }
    let mut cur = res;
    let mut printed = false;
    while !cur.is_null() {
        unsafe {
            let ai = &*cur;
            if ai.ai_family == libc::AF_INET && !ai.ai_addr.is_null() {
                let sin = &*(ai.ai_addr as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                println!("resolved={ip}");
                printed = true;
            }
            cur = ai.ai_next;
        }
    }
    unsafe {
        libc::freeaddrinfo(res);
    }
    if !printed {
        eprintln!("no AF_INET results from getaddrinfo");
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_getaddrinfo_v6() -> io::Result<()> {
    use std::ffi::CString;
    use std::ptr;
    let node = CString::new("localhost").unwrap();
    let mut res: *mut libc::addrinfo = ptr::null_mut();
    let hints = libc::addrinfo {
        ai_flags: 0,
        ai_family: libc::AF_UNSPEC,
        ai_socktype: libc::SOCK_STREAM,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: ptr::null_mut(),
        ai_canonname: ptr::null_mut(),
        ai_next: ptr::null_mut(),
    };
    let ret = unsafe { libc::getaddrinfo(node.as_ptr(), ptr::null(), &hints, &mut res) };
    if ret != 0 {
        eprintln!("getaddrinfo failed: {ret}");
        std::process::exit(1);
    }
    let mut cur = res;
    let mut printed = false;
    while !cur.is_null() {
        unsafe {
            let ai = &*cur;
            if ai.ai_family == libc::AF_INET && !ai.ai_addr.is_null() {
                let sin = &*(ai.ai_addr as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                println!("v4={ip}");
                printed = true;
            } else if ai.ai_family == libc::AF_INET6 && !ai.ai_addr.is_null() {
                let sin6 = &*(ai.ai_addr as *const libc::sockaddr_in6);
                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                println!("v6={ip}");
                printed = true;
            }
            cur = ai.ai_next;
        }
    }
    unsafe {
        libc::freeaddrinfo(res);
    }
    if !printed {
        eprintln!("no results from getaddrinfo");
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn cmd_bind_v6_opts() -> io::Result<()> {
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let optval: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
        addr6.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
        addr6.sin6_family = libc::AF_INET6 as u8;
        addr6.sin6_port = 0;
        let ret = libc::bind(
            fd,
            &addr6 as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        );
        if ret != 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }
        let mut bound_addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut bound_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        libc::getsockname(
            fd,
            &mut bound_addr as *mut _ as *mut libc::sockaddr,
            &mut bound_len,
        );
        let family = bound_addr.ss_family;
        if family == libc::AF_INET as u8 {
            let sin = &*(&bound_addr as *const _ as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            println!("family=v4");
            println!("bound={ip}");
        } else {
            println!("family=v6");
        }
        let mut reuseaddr: libc::c_int = 0;
        let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &mut reuseaddr as *mut _ as *mut libc::c_void,
            &mut optlen,
        );
        println!("reuseaddr={reuseaddr}");
        let final_flags = libc::fcntl(fd, libc::F_GETFL);
        let nonblock = (final_flags & libc::O_NONBLOCK) != 0;
        println!("nonblock={nonblock}");
        libc::close(fd);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn cmd_bind_v6_dualstack() -> io::Result<()> {
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut v6only: libc::c_int = -1;
        let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        libc::getsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &mut v6only as *mut _ as *mut libc::c_void,
            &mut optlen,
        );
        println!("v6only_before={v6only}");
        let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
        addr6.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
        addr6.sin6_family = libc::AF_INET6 as u8;
        addr6.sin6_port = 0;
        let ret = libc::bind(
            fd,
            &addr6 as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        );
        if ret != 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }
        let mut bound: libc::sockaddr_storage = std::mem::zeroed();
        let mut bound_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        libc::getsockname(
            fd,
            &mut bound as *mut _ as *mut libc::sockaddr,
            &mut bound_len,
        );
        let family = bound.ss_family;
        if family == libc::AF_INET6 as u8 {
            let sin6 = &*(&bound as *const _ as *const libc::sockaddr_in6);
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            println!("family=v6");
            println!("bound={ip}");
            libc::listen(fd, 1);
            let silo_ip = env::var("SILO_IP").unwrap_or_default();
            let connect_target = format!("{silo_ip}:{port}");
            let handle = std::thread::spawn(move || std::net::TcpStream::connect(&connect_target));
            let client_fd = libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut());
            println!("accept={}", if client_fd >= 0 { "ok" } else { "fail" });
            if client_fd >= 0 {
                libc::close(client_fd);
            }
            let _ = handle.join();
        } else if family == libc::AF_INET as u8 {
            let sin = &*(&bound as *const _ as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            println!("family=v4");
            println!("bound={ip}");
        }
        libc::close(fd);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn cmd_bind_v6_v6only() -> io::Result<()> {
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let optval: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
        addr6.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
        addr6.sin6_family = libc::AF_INET6 as u8;
        addr6.sin6_port = 0;
        let ret = libc::bind(
            fd,
            &addr6 as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        );
        if ret != 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }
        let mut bound: libc::sockaddr_storage = std::mem::zeroed();
        let mut bound_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        libc::getsockname(
            fd,
            &mut bound as *mut _ as *mut libc::sockaddr,
            &mut bound_len,
        );
        let family = bound.ss_family;
        if family == libc::AF_INET as u8 {
            let sin = &*(&bound as *const _ as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            println!("family=v4");
            println!("bound={ip}");
        } else if family == libc::AF_INET6 as u8 {
            let sin6 = &*(&bound as *const _ as *const libc::sockaddr_in6);
            let v6_bytes = sin6.sin6_addr.s6_addr;
            let mut v6only: libc::c_int = 0;
            let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            libc::getsockopt(
                fd,
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &mut v6only as *mut _ as *mut libc::c_void,
                &mut optlen,
            );
            println!("family=v6");
            println!("v6only_after={v6only}");
            if v6_bytes[..10] == [0; 10] && v6_bytes[10] == 0xff && v6_bytes[11] == 0xff {
                let ip = Ipv4Addr::new(v6_bytes[12], v6_bytes[13], v6_bytes[14], v6_bytes[15]);
                println!("bound={ip}");
            } else {
                let addr = std::net::Ipv6Addr::from(v6_bytes);
                println!("bound={addr}");
            }
        } else {
            println!("family=unknown");
        }
        libc::close(fd);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn cmd_bind_v6_kqueue() -> io::Result<()> {
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let kq = libc::kqueue();
        if kq < 0 {
            libc::close(fd);
            return Err(io::Error::last_os_error());
        }
        let change = libc::kevent {
            ident: fd as usize,
            filter: libc::EVFILT_READ,
            flags: libc::EV_ADD,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null());
        let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
        addr6.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
        addr6.sin6_family = libc::AF_INET6 as u8;
        addr6.sin6_port = 0;
        let ret = libc::bind(
            fd,
            &addr6 as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        );
        if ret != 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            libc::close(kq);
            return Err(err);
        }
        libc::listen(fd, 1);
        let mut bound: libc::sockaddr_storage = std::mem::zeroed();
        let mut bound_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        libc::getsockname(
            fd,
            &mut bound as *mut _ as *mut libc::sockaddr,
            &mut bound_len,
        );
        let port = if bound.ss_family == libc::AF_INET6 as u8 {
            let sin6 = &*(&bound as *const _ as *const libc::sockaddr_in6);
            u16::from_be(sin6.sin6_port)
        } else {
            let sin = &*(&bound as *const _ as *const libc::sockaddr_in);
            u16::from_be(sin.sin_port)
        };
        let silo_ip = env::var("SILO_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
        let target = format!("{silo_ip}:{port}");
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            std::net::TcpStream::connect(&target)
        });
        let mut event: libc::kevent = std::mem::zeroed();
        let timeout = libc::timespec {
            tv_sec: 2,
            tv_nsec: 0,
        };
        let n = libc::kevent(kq, std::ptr::null(), 0, &mut event, 1, &timeout);
        println!("kqueue_events={n}");
        if n > 0 {
            let client_fd = libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut());
            if client_fd >= 0 {
                libc::close(client_fd);
            }
        }
        let _ = handle.join();
        libc::close(fd);
        libc::close(kq);
    }
    Ok(())
}

fn cmd_gethostbyname() -> io::Result<()> {
    use std::ffi::CString;
    unsafe extern "C" {
        fn gethostbyname(name: *const libc::c_char) -> *mut libc::hostent;
    }
    let name = CString::new("localhost").unwrap();
    let hp = unsafe { gethostbyname(name.as_ptr()) };
    if hp.is_null() {
        eprintln!("gethostbyname failed");
        std::process::exit(1);
    }
    unsafe {
        print_hostent_v4(hp, "gethostbyname");
    }
    Ok(())
}

fn cmd_gethostbyname2() -> io::Result<()> {
    use std::ffi::CString;
    unsafe extern "C" {
        fn gethostbyname2(name: *const libc::c_char, af: libc::c_int) -> *mut libc::hostent;
    }
    let name = CString::new("localhost").unwrap();
    let hp = unsafe { gethostbyname2(name.as_ptr(), libc::AF_INET) };
    if hp.is_null() {
        eprintln!("gethostbyname2 failed");
        std::process::exit(1);
    }
    unsafe {
        print_hostent_v4(hp, "gethostbyname2");
    }
    Ok(())
}

unsafe fn print_hostent_v4(hp: *mut libc::hostent, fn_name: &str) {
    unsafe {
        let h_addrtype = std::ptr::addr_of!((*hp).h_addrtype).read_unaligned();
        let h_length = std::ptr::addr_of!((*hp).h_length).read_unaligned();
        let h_addr_list = std::ptr::addr_of!((*hp).h_addr_list).read_unaligned();
        if h_addrtype != libc::AF_INET || h_length != 4 {
            eprintln!("unexpected address type: {h_addrtype} len: {h_length}");
            std::process::exit(1);
        }
        let mut i = 0usize;
        let mut printed = false;
        loop {
            let entry = h_addr_list.add(i).read_unaligned();
            if entry.is_null() {
                break;
            }
            let mut bytes = [0u8; 4];
            std::ptr::copy_nonoverlapping(entry as *const u8, bytes.as_mut_ptr(), 4);
            let ip = Ipv4Addr::from(bytes);
            println!("resolved={ip}");
            printed = true;
            i += 1;
        }
        if !printed {
            eprintln!("no addresses from {fn_name}");
            std::process::exit(1);
        }
    }
}

fn cmd_sendmsg_localhost() -> io::Result<()> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut bind_addr: libc::sockaddr_in = std::mem::zeroed();
        #[cfg(target_os = "macos")]
        {
            bind_addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        bind_addr.sin_family = libc::AF_INET as _;
        bind_addr.sin_port = 0;
        bind_addr.sin_addr.s_addr = 0;
        let ret = libc::bind(
            fd,
            &bind_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        if ret != 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }
        let mut local_addr: libc::sockaddr_in = std::mem::zeroed();
        let mut local_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        libc::getsockname(
            fd,
            &mut local_addr as *mut _ as *mut libc::sockaddr,
            &mut local_len,
        );
        let bound_ip = Ipv4Addr::from(u32::from_be(local_addr.sin_addr.s_addr));
        let bound_port = u16::from_be(local_addr.sin_port);
        println!("bound={bound_ip}:{bound_port}");
        let mut dest_addr: libc::sockaddr_in = std::mem::zeroed();
        #[cfg(target_os = "macos")]
        {
            dest_addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        dest_addr.sin_family = libc::AF_INET as _;
        dest_addr.sin_port = u16::to_be(bound_port);
        dest_addr.sin_addr.s_addr = u32::from(Ipv4Addr::LOCALHOST).to_be();
        let mut data = *b"silo-test";
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: data.len(),
        };
        let msg = libc::msghdr {
            msg_name: &mut dest_addr as *mut _ as *mut libc::c_void,
            msg_namelen: std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let sent = libc::sendmsg(fd, &msg, 0);
        if sent < 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }
        let mut buf = [0u8; 64];
        let mut recv_iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut src_addr: libc::sockaddr_in = std::mem::zeroed();
        let mut recv_msg = libc::msghdr {
            msg_name: &mut src_addr as *mut _ as *mut libc::c_void,
            msg_namelen: std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            msg_iov: &mut recv_iov,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        let recvd = libc::recvmsg(fd, &mut recv_msg, 0);
        if recvd > 0 {
            println!("sendmsg=ok");
        } else {
            println!("sendmsg=failed");
        }
        libc::close(fd);
    }
    Ok(())
}

fn cmd_sendto(addr: Ipv4Addr) -> io::Result<()> {
    let socket = UdpSocket::bind(SocketAddrV4::new(addr, 0))?;
    let local = socket.local_addr()?;
    println!("bound={local}");
    let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, local.port());
    let _ = socket.send_to(b"test", target);
    println!("sendto=ok");
    Ok(())
}

fn cmd_bind_unix() -> io::Result<()> {
    let dir = tempfile::tempdir()?;
    let sock_path = dir.path().join("test.sock");
    let listener = UnixListener::bind(&sock_path)?;
    let addr = listener.local_addr()?;
    println!(
        "unix_bound={}",
        addr.as_pathname()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
    );
    println!("unix=ok");
    Ok(())
}

fn cmd_errno_after_connect() -> io::Result<()> {
    unsafe {
        #[cfg(target_os = "linux")]
        let errno_ptr = libc::__errno_location();
        #[cfg(target_os = "macos")]
        let errno_ptr = libc::__error();

        *errno_ptr = libc::EAGAIN;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let _ = std::net::TcpStream::connect(format!("127.0.0.1:{port}"));

        let errno_after = *errno_ptr;
        println!("errno_before=EAGAIN");
        println!("errno_after={errno_after}");
        println!("errno_preserved={}", errno_after == libc::EAGAIN);
    }
    Ok(())
}

fn cmd_bind_v6(addr: Ipv6Addr) -> io::Result<()> {
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
        #[cfg(target_os = "macos")]
        {
            addr6.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
        }
        addr6.sin6_family = libc::AF_INET6 as _;
        addr6.sin6_port = 0;
        addr6.sin6_addr.s6_addr = addr.octets();

        let ret = libc::bind(
            fd,
            &addr6 as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        );
        if ret != 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(err);
        }

        let mut bound: libc::sockaddr_storage = std::mem::zeroed();
        let mut bound_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        libc::getsockname(
            fd,
            &mut bound as *mut _ as *mut libc::sockaddr,
            &mut bound_len,
        );

        if bound.ss_family == libc::AF_INET6 as _ {
            let sin6 = &*(&bound as *const _ as *const libc::sockaddr_in6);
            let v6_bytes = sin6.sin6_addr.s6_addr;
            if v6_bytes[..10] == [0; 10] && v6_bytes[10] == 0xff && v6_bytes[11] == 0xff {
                let ip = Ipv4Addr::new(v6_bytes[12], v6_bytes[13], v6_bytes[14], v6_bytes[15]);
                println!("family=v6");
                println!("bound={ip}");
                println!("mapped=true");
            } else {
                let ip = Ipv6Addr::from(v6_bytes);
                println!("family=v6");
                println!("bound={ip}");
                println!("mapped=false");
            }
        } else if bound.ss_family == libc::AF_INET as _ {
            let sin = &*(&bound as *const _ as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            println!("family=v4");
            println!("bound={ip}");
        }

        libc::close(fd);
    }
    Ok(())
}

fn cmd_connect_v6_localhost() -> io::Result<()> {
    unsafe {
        let listen_fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if listen_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut bind_addr: libc::sockaddr_in = std::mem::zeroed();
        #[cfg(target_os = "macos")]
        {
            bind_addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        bind_addr.sin_family = libc::AF_INET as _;
        bind_addr.sin_port = 0;
        let silo_ip_str = env::var("SILO_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
        let silo_ip: Ipv4Addr = silo_ip_str.parse().unwrap_or(Ipv4Addr::LOCALHOST);
        bind_addr.sin_addr.s_addr = u32::from(silo_ip).to_be();

        libc::bind(
            listen_fd,
            &bind_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        libc::listen(listen_fd, 1);

        let mut bound: libc::sockaddr_in = std::mem::zeroed();
        let mut bound_len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        libc::getsockname(
            listen_fd,
            &mut bound as *mut _ as *mut libc::sockaddr,
            &mut bound_len,
        );
        let port = u16::from_be(bound.sin_port);

        let connect_fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
        let mut dest: libc::sockaddr_in6 = std::mem::zeroed();
        #[cfg(target_os = "macos")]
        {
            dest.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
        }
        dest.sin6_family = libc::AF_INET6 as _;
        dest.sin6_port = u16::to_be(port);
        dest.sin6_addr.s6_addr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        let ret = libc::connect(
            connect_fd,
            &dest as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        );

        if ret == 0 {
            let mut peer: libc::sockaddr_storage = std::mem::zeroed();
            let mut peer_len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            libc::getpeername(
                connect_fd,
                &mut peer as *mut _ as *mut libc::sockaddr,
                &mut peer_len,
            );

            if peer.ss_family == libc::AF_INET6 as _ {
                let sin6 = &*(&peer as *const _ as *const libc::sockaddr_in6);
                let v6_bytes = sin6.sin6_addr.s6_addr;
                if v6_bytes[..10] == [0; 10] && v6_bytes[10] == 0xff && v6_bytes[11] == 0xff {
                    let ip = Ipv4Addr::new(v6_bytes[12], v6_bytes[13], v6_bytes[14], v6_bytes[15]);
                    println!("connected={ip}");
                } else {
                    let ip = Ipv6Addr::from(v6_bytes);
                    println!("connected={ip}");
                }
            } else if peer.ss_family == libc::AF_INET as _ {
                let sin = &*(&peer as *const _ as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                println!("connected={ip}");
            }
            println!("connect_v6=ok");
        } else {
            println!("connect_v6=failed");
        }

        libc::close(connect_fd);
        libc::close(listen_fd);
    }
    Ok(())
}

fn cmd_connect_cache_hit() -> io::Result<()> {
    let silo_ip_str = env::var("SILO_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
    let silo_ip: Ipv4Addr = silo_ip_str.parse().unwrap();

    let listener = TcpListener::bind(SocketAddrV4::new(silo_ip, 0))?;
    let port = listener.local_addr()?.port();

    for i in 0..5 {
        let stream = std::net::TcpStream::connect(format!("127.0.0.1:{port}"))?;
        let peer = stream.peer_addr()?;
        println!("connect_{i}={}", peer.ip());
    }

    Ok(())
}

fn cmd_connect_cache_invalidation() -> io::Result<()> {
    let silo_ip_str = env::var("SILO_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
    let silo_ip: Ipv4Addr = silo_ip_str.parse().unwrap();

    let listener = TcpListener::bind(SocketAddrV4::new(silo_ip, 0))?;
    let port = listener.local_addr()?.port();

    let stream = std::net::TcpStream::connect(format!("127.0.0.1:{port}"))?;
    let peer = stream.peer_addr()?;
    println!("phase1={}", peer.ip());
    drop(stream);
    drop(listener);

    std::thread::sleep(std::time::Duration::from_millis(50));

    match std::net::TcpStream::connect(format!("127.0.0.1:{port}")) {
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            println!("phase2=refused");
        }
        Ok(s) => {
            println!("phase2=connected:{}", s.peer_addr()?.ip());
        }
        Err(e) => {
            println!("phase2=error:{e}");
        }
    }

    Ok(())
}

fn cmd_connect_cache_full_cycle() -> io::Result<()> {
    let silo_ip_str = env::var("SILO_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
    let silo_ip: Ipv4Addr = silo_ip_str.parse().unwrap();

    let listener = TcpListener::bind(SocketAddrV4::new(silo_ip, 0))?;
    let port = listener.local_addr()?.port();

    let s1 = std::net::TcpStream::connect(format!("127.0.0.1:{port}"))?;
    println!("phase1={}", s1.peer_addr()?.ip());
    drop(s1);
    drop(listener);

    std::thread::sleep(std::time::Duration::from_millis(50));

    match std::net::TcpStream::connect(format!("127.0.0.1:{port}")) {
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            println!("phase2=refused");
        }
        Ok(s) => {
            println!("phase2=connected:{}", s.peer_addr()?.ip());
            return Ok(());
        }
        Err(e) => {
            println!("phase2=error:{e}");
            return Ok(());
        }
    }

    let listener2 = TcpListener::bind(SocketAddrV4::new(silo_ip, port))?;
    let _ = listener2.local_addr()?;

    let s3 = std::net::TcpStream::connect(format!("127.0.0.1:{port}"))?;
    println!("phase3={}", s3.peer_addr()?.ip());

    Ok(())
}

fn cmd_connect_cache_port_isolation() -> io::Result<()> {
    let silo_ip_str = env::var("SILO_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
    let silo_ip: Ipv4Addr = silo_ip_str.parse().unwrap();

    let listener_a = TcpListener::bind(SocketAddrV4::new(silo_ip, 0))?;
    let port_a = listener_a.local_addr()?.port();

    let sa = std::net::TcpStream::connect(format!("127.0.0.1:{port_a}"))?;
    println!("port_a={}", sa.peer_addr()?.ip());

    let tmp = TcpListener::bind(SocketAddrV4::new(silo_ip, 0))?;
    let port_b = tmp.local_addr()?.port();
    drop(tmp);

    match std::net::TcpStream::connect(format!("127.0.0.1:{port_b}")) {
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            println!("port_b=refused");
        }
        Ok(s) => {
            println!("port_b={}", s.peer_addr()?.ip());
        }
        Err(e) => {
            println!("port_b=error:{e}");
        }
    }

    Ok(())
}

fn cmd_concurrent_bind() -> io::Result<()> {
    let threads: Vec<_> = (0..10)
        .map(|_| {
            std::thread::spawn(|| -> io::Result<String> {
                let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
                let local = listener.local_addr()?;
                Ok(local.ip().to_string())
            })
        })
        .collect();

    let mut all_ok = true;
    for (i, handle) in threads.into_iter().enumerate() {
        match handle.join().unwrap() {
            Ok(ip) => println!("thread_{i}={ip}"),
            Err(e) => {
                println!("thread_{i}=error:{e}");
                all_ok = false;
            }
        }
    }
    println!("concurrent={}", if all_ok { "ok" } else { "failed" });
    Ok(())
}
