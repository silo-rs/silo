#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_sock_addr, map},
    maps::HashMap,
    programs::SockAddrContext,
};

/// BPF map holding per-cgroup silo IPs.
/// Key: cgroup v2 ID (u64), Value: silo IP in network byte order (u32).
/// Using a HashMap allows multiple concurrent silo sessions, each with its
/// own cgroup and IP, to share the same pinned BPF programs.
#[map]
static SILO_CONFIG: HashMap<u64, u32> = HashMap::with_max_entries(256, 0);

// --- Constants ---

/// 127.0.0.1 in network byte order (big-endian).
const LOCALHOST_NBO: u32 = 0x7f000001_u32.to_be();

// --- Helpers ---

/// BPF helper: get the cgroup v2 ID of the current task.
/// Helper function ID 80 (bpf_get_current_cgroup_id).
#[inline(always)]
fn current_cgroup_id() -> u64 {
    unsafe {
        let f: unsafe extern "C" fn() -> u64 = core::mem::transmute(80usize);
        f()
    }
}

/// Read silo IP for the current cgroup from the config map.
#[inline(always)]
fn silo_ip() -> Option<u32> {
    let cgroup_id = current_cgroup_id();
    unsafe { SILO_CONFIG.get(&cgroup_id).copied() }
}

/// Rewrite IPv4 address to silo IP.
/// `match_any`: if true, also rewrite 0.0.0.0 (INADDR_ANY).
#[inline(always)]
fn rewrite_ip4(ctx: &SockAddrContext, match_any: bool) -> i32 {
    let ip = match silo_ip() {
        Some(ip) if ip != 0 => ip,
        _ => return 1,
    };
    let addr = unsafe { (*ctx.sock_addr).user_ip4 };
    if addr == LOCALHOST_NBO || (match_any && addr == 0) {
        unsafe { (*ctx.sock_addr).user_ip4 = ip };
    }
    1
}

/// Rewrite IPv6 address to ::ffff:SILO_IP (IPv4-mapped IPv6).
/// `match_any`: if true, also rewrite :: (in6addr_any).
#[inline(always)]
fn rewrite_ip6(ctx: &SockAddrContext, match_any: bool) -> i32 {
    let ip = match silo_ip() {
        Some(ip) if ip != 0 => ip,
        _ => return 1,
    };
    let addr = unsafe { (*ctx.sock_addr).user_ip6 };
    let is_loopback = addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 1_u32.to_be();
    let is_any = addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 0;
    if is_loopback || (match_any && is_any) {
        // ::ffff:SILO_IP
        unsafe {
            (*ctx.sock_addr).user_ip6 = [0, 0, 0x0000ffff_u32.to_be(), ip];
        }
    }
    1
}

/// Reverse-rewrite IPv4: SILO_IP -> 127.0.0.1.
#[inline(always)]
fn reverse_ip4(ctx: &SockAddrContext) -> i32 {
    let ip = match silo_ip() {
        Some(ip) if ip != 0 => ip,
        _ => return 1,
    };
    if unsafe { (*ctx.sock_addr).user_ip4 } == ip {
        unsafe { (*ctx.sock_addr).user_ip4 = LOCALHOST_NBO };
    }
    1
}

/// Reverse-rewrite IPv6: ::ffff:SILO_IP -> ::1.
#[inline(always)]
fn reverse_ip6(ctx: &SockAddrContext) -> i32 {
    let ip = match silo_ip() {
        Some(ip) if ip != 0 => ip,
        _ => return 1,
    };
    let addr = unsafe { (*ctx.sock_addr).user_ip6 };
    if addr[0] == 0 && addr[1] == 0 && addr[2] == 0x0000ffff_u32.to_be() && addr[3] == ip {
        unsafe {
            (*ctx.sock_addr).user_ip6 = [0, 0, 0, 1_u32.to_be()];
        }
    }
    1
}

// --- BPF program entry points ---

// bind: rewrite 0.0.0.0 and 127.0.0.1 -> SILO_IP
#[cgroup_sock_addr(bind4)]
pub fn silo_bind4(ctx: SockAddrContext) -> i32 {
    rewrite_ip4(&ctx, true)
}

#[cgroup_sock_addr(bind6)]
pub fn silo_bind6(ctx: SockAddrContext) -> i32 {
    rewrite_ip6(&ctx, true)
}

// connect: rewrite 127.0.0.1 -> SILO_IP (NOT 0.0.0.0)
#[cgroup_sock_addr(connect4)]
pub fn silo_connect4(ctx: SockAddrContext) -> i32 {
    rewrite_ip4(&ctx, false)
}

#[cgroup_sock_addr(connect6)]
pub fn silo_connect6(ctx: SockAddrContext) -> i32 {
    rewrite_ip6(&ctx, false)
}

// sendmsg: rewrite 0.0.0.0 and 127.0.0.1 -> SILO_IP
#[cgroup_sock_addr(sendmsg4)]
pub fn silo_sendmsg4(ctx: SockAddrContext) -> i32 {
    rewrite_ip4(&ctx, true)
}

#[cgroup_sock_addr(sendmsg6)]
pub fn silo_sendmsg6(ctx: SockAddrContext) -> i32 {
    rewrite_ip6(&ctx, true)
}

// recvmsg: reverse SILO_IP -> 127.0.0.1
#[cgroup_sock_addr(recvmsg4)]
pub fn silo_recvmsg4(ctx: SockAddrContext) -> i32 {
    reverse_ip4(&ctx)
}

#[cgroup_sock_addr(recvmsg6)]
pub fn silo_recvmsg6(ctx: SockAddrContext) -> i32 {
    reverse_ip6(&ctx)
}

// getpeername: reverse SILO_IP -> 127.0.0.1
#[cgroup_sock_addr(getpeername4)]
pub fn silo_getpeername4(ctx: SockAddrContext) -> i32 {
    reverse_ip4(&ctx)
}

#[cgroup_sock_addr(getpeername6)]
pub fn silo_getpeername6(ctx: SockAddrContext) -> i32 {
    reverse_ip6(&ctx)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
