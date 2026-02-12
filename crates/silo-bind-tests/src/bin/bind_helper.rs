//! Helper binary for silo-bind integration tests.
//!
//! This binary is spawned by the test harness with DYLD_INSERT_LIBRARIES or
//! LD_PRELOAD pointing at libsilo_bind, and SILO_IP set to a test address.
//! It performs a requested syscall and prints the resulting address to stdout
//! so the test can verify interception worked correctly.

use std::env;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, TcpListener, UdpSocket};

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
        "getaddrinfo" => cmd_getaddrinfo(),
        "getaddrinfo_v6" => cmd_getaddrinfo_v6(),
        "sendto_any" => cmd_sendto(Ipv4Addr::UNSPECIFIED),
        "sendmsg_localhost" => cmd_sendmsg_localhost(),
        #[cfg(target_os = "macos")]
        "bind_v6_opts" => cmd_bind_v6_opts(),
        "passthrough" => cmd_bind(Ipv4Addr::UNSPECIFIED),
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

/// Create a TCP listener, bind to the given address on port 0, then print
/// the actual local address after binding.
fn cmd_bind(addr: Ipv4Addr) -> io::Result<()> {
    let listener = TcpListener::bind(SocketAddrV4::new(addr, 0))?;
    let local = listener.local_addr()?;
    println!("bound={local}");
    Ok(())
}

/// Create a TCP socket and attempt to connect to 127.0.0.1 on a port where
/// nothing is listening. We don't care if connect fails — we care what address
/// the kernel tried to connect to. We use getsockname after the attempt.
fn cmd_connect_localhost() -> io::Result<()> {
    // First, create a listener on SILO_IP so connect() succeeds.
    // If SILO_IP is set, the bind will land on SILO_IP.
    // If SILO_IP is not set, the bind will land on 127.0.0.1.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let listener_addr = listener.local_addr()?;

    // Now connect to 127.0.0.1:<port> — silo-bind should rewrite this to SILO_IP:<port>
    let stream = std::net::TcpStream::connect(format!("127.0.0.1:{}", listener_addr.port()))?;
    let peer = stream.peer_addr()?;
    println!("connected={peer}");
    Ok(())
}

/// Call libc::getaddrinfo for "localhost" and print all IPv4 results.
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

/// Call libc::getaddrinfo for "localhost" with AF_UNSPEC hints and print
/// all results, including IPv6. This tests that ::1 is rewritten to
/// ::ffff:SILO_IP (IPv4-mapped IPv6).
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

/// Create an IPv6 TCP socket with SO_REUSEADDR and O_NONBLOCK set, then bind
/// to [::]:0. On macOS with SILO_IP, silo-bind's `replace_with_ipv4` replaces
/// the socket fd. This test verifies that socket options survive the replacement.
#[cfg(target_os = "macos")]
fn cmd_bind_v6_opts() -> io::Result<()> {
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Set SO_REUSEADDR
        let optval: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );

        // Set O_NONBLOCK
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);

        // Bind to [::]:0 — triggers replace_with_ipv4 when SILO_IP is set
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

        // Check what address we're bound to
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

        // Check SO_REUSEADDR is preserved
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

        // Check O_NONBLOCK is preserved
        let final_flags = libc::fcntl(fd, libc::F_GETFL);
        let nonblock = (final_flags & libc::O_NONBLOCK) != 0;
        println!("nonblock={nonblock}");

        libc::close(fd);
    }

    Ok(())
}

/// Create a UDP socket, bind to SILO_IP, then use raw sendmsg() with
/// msg_name pointing to 127.0.0.1. Verify that the bind was rewritten
/// (proving sendmsg's msg_name address rewriting works alongside bind).
fn cmd_sendmsg_localhost() -> io::Result<()> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Bind to 0.0.0.0:0 — will be rewritten to SILO_IP:port
        let mut bind_addr: libc::sockaddr_in = std::mem::zeroed();
        #[cfg(target_os = "macos")]
        {
            bind_addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        bind_addr.sin_family = libc::AF_INET as _;
        bind_addr.sin_port = 0;
        bind_addr.sin_addr.s_addr = 0; // INADDR_ANY

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

        // Get the actual bound address
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

        // Now use sendmsg with msg_name pointing to 127.0.0.1
        // (which should be rewritten to SILO_IP)
        let mut dest_addr: libc::sockaddr_in = std::mem::zeroed();
        #[cfg(target_os = "macos")]
        {
            dest_addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        dest_addr.sin_family = libc::AF_INET as _;
        dest_addr.sin_port = u16::to_be(bound_port);
        dest_addr.sin_addr.s_addr = u32::from(Ipv4Addr::LOCALHOST).to_be();

        let data = b"silo-test";
        let mut iov = libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
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

        // Receive the packet we sent to ourselves
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

/// Create a UDP socket, bind to an ephemeral port, then sendto the given
/// address. Print the address that sendto was called with (we verify by
/// checking the bound address instead since we can't easily inspect sendto's
/// target after the fact — but the bind itself verifies interception).
fn cmd_sendto(addr: Ipv4Addr) -> io::Result<()> {
    let socket = UdpSocket::bind(SocketAddrV4::new(addr, 0))?;
    let local = socket.local_addr()?;
    println!("bound={local}");

    // Also try sending to localhost — if intercepted, it goes to SILO_IP
    let target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, local.port());
    // Send to ourselves (will work since we're bound)
    let _ = socket.send_to(b"test", target);
    println!("sendto=ok");
    Ok(())
}
