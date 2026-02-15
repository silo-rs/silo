#![allow(unsafe_code)]

use std::env;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, TcpListener};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: ebpf-helper <command>");
        std::process::exit(1);
    }

    let result = match args[1].as_str() {
        "bind_any" => cmd_bind(Ipv4Addr::UNSPECIFIED),
        "bind_localhost" => cmd_bind(Ipv4Addr::LOCALHOST),
        "bind_v6_any" => cmd_bind_v6(Ipv6Addr::UNSPECIFIED),
        "bind_v6_loopback" => cmd_bind_v6(Ipv6Addr::LOCALHOST),
        "connect_localhost" => cmd_connect_localhost(),
        "sendmsg_recvmsg" => cmd_sendmsg_recvmsg(),
        "connect_getpeername" => cmd_connect_getpeername(),
        "connect_no_listener" => cmd_connect_no_listener(),
        "connect_host_service" => cmd_connect_host_service(),
        "connect_external" => cmd_connect_external(),
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn cmd_bind(addr: Ipv4Addr) -> io::Result<()> {
    let listener = TcpListener::bind(SocketAddrV4::new(addr, 0))?;
    let local = listener.local_addr()?;
    println!("bound={local}");
    Ok(())
}

fn cmd_bind_v6(addr: Ipv6Addr) -> io::Result<()> {
    let listener = TcpListener::bind(SocketAddrV6::new(addr, 0, 0, 0))?;
    let local = listener.local_addr()?;
    println!("bound={local}");
    Ok(())
}

fn cmd_connect_localhost() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    let stream = std::net::TcpStream::connect(format!("127.0.0.1:{port}"))?;
    let peer = stream.peer_addr()?;
    println!("connected={peer}");
    Ok(())
}

fn cmd_sendmsg_recvmsg() -> io::Result<()> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut bind_addr: libc::sockaddr_in = std::mem::zeroed();
        bind_addr.sin_family = libc::AF_INET as _;
        bind_addr.sin_port = 0;
        bind_addr.sin_addr.s_addr = 0;

        let ret = libc::bind(
            fd,
            &bind_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        if ret != 0 {
            libc::close(fd);
            return Err(io::Error::last_os_error());
        }

        let mut local: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        libc::getsockname(fd, &mut local as *mut _ as *mut libc::sockaddr, &mut len);
        let bound_ip = Ipv4Addr::from(u32::from_be(local.sin_addr.s_addr));
        let bound_port = u16::from_be(local.sin_port);
        println!("bound={bound_ip}:{bound_port}");

        let mut dest: libc::sockaddr_in = std::mem::zeroed();
        dest.sin_family = libc::AF_INET as _;
        dest.sin_port = local.sin_port;
        dest.sin_addr.s_addr = u32::from(Ipv4Addr::LOCALHOST).to_be();

        let mut data = *b"silo-test";
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: data.len(),
        };
        let msg = libc::msghdr {
            msg_name: &mut dest as *mut _ as *mut libc::c_void,
            msg_namelen: std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let sent = libc::sendmsg(fd, &msg, 0);
        if sent < 0 {
            libc::close(fd);
            return Err(io::Error::last_os_error());
        }

        let mut buf = [0u8; 64];
        let mut recv_iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut src: libc::sockaddr_in = std::mem::zeroed();
        let mut recv_msg = libc::msghdr {
            msg_name: &mut src as *mut _ as *mut libc::c_void,
            msg_namelen: std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            msg_iov: &mut recv_iov,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        let recvd = libc::recvmsg(fd, &mut recv_msg, 0);
        if recvd > 0 {
            let src_ip = Ipv4Addr::from(u32::from_be(src.sin_addr.s_addr));
            println!("recvmsg_src={src_ip}");
        } else {
            println!("recvmsg=failed");
        }

        libc::close(fd);
    }
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

fn cmd_connect_host_service() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    match std::net::TcpStream::connect(format!("127.0.0.1:{port}")) {
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

fn cmd_connect_external() -> io::Result<()> {
    let port: u16 = env::var("SILO_TEST_PORT")
        .expect("SILO_TEST_PORT not set")
        .parse()
        .expect("invalid SILO_TEST_PORT");

    match std::net::TcpStream::connect(format!("127.0.0.1:{port}")) {
        Ok(stream) => {
            let peer = stream.peer_addr()?;
            println!("connect_result=connected:{peer}");
        }
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            println!("connect_result=refused");
        }
        Err(e) => {
            println!("connect_result=error:{e}");
        }
    }
    Ok(())
}

fn cmd_connect_getpeername() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();

    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        addr.sin_family = libc::AF_INET as _;
        addr.sin_port = port.to_be();
        addr.sin_addr.s_addr = u32::from(Ipv4Addr::LOCALHOST).to_be();

        let ret = libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        if ret != 0 {
            libc::close(fd);
            return Err(io::Error::last_os_error());
        }

        let mut peer: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        libc::getpeername(fd, &mut peer as *mut _ as *mut libc::sockaddr, &mut len);
        let peer_ip = Ipv4Addr::from(u32::from_be(peer.sin_addr.s_addr));
        let peer_port = u16::from_be(peer.sin_port);
        println!("getpeername={peer_ip}:{peer_port}");

        libc::close(fd);
    }
    Ok(())
}
