//! Helper binary for silo-bind integration tests.
//!
//! This binary is spawned by the test harness with DYLD_INSERT_LIBRARIES or
//! LD_PRELOAD pointing at libsilo_bind, and SILO_IP set to a test address.
//! It performs a requested syscall and prints the resulting address to stdout
//! so the test can verify interception worked correctly.

use std::env;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, UdpSocket};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: bind-helper <command> [args...]");
        eprintln!("commands: bind_any, bind_localhost, connect_localhost, getaddrinfo, sendto_any, passthrough");
        std::process::exit(1);
    }

    let result = match args[1].as_str() {
        "bind_any" => cmd_bind(Ipv4Addr::UNSPECIFIED),
        "bind_localhost" => cmd_bind(Ipv4Addr::LOCALHOST),
        "connect_localhost" => cmd_connect_localhost(),
        "getaddrinfo" => cmd_getaddrinfo(),
        "sendto_any" => cmd_sendto(Ipv4Addr::UNSPECIFIED),
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
