#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_sock_addr, map},
    maps::HashMap,
    programs::SockAddrContext,
};

#[map]
static SILO_CONFIG: HashMap<u64, u32> = HashMap::with_max_entries(1024, 0);

const LOCALHOST_NBO: u32 = 0x7f000001_u32.to_be();

const BPF_FUNC_GET_CURRENT_CGROUP_ID: usize = 80;
const BPF_FUNC_SK_LOOKUP_TCP: usize = 84;
const BPF_FUNC_SK_LOOKUP_UDP: usize = 85;
const BPF_FUNC_SK_RELEASE: usize = 86;

#[inline(always)]
fn current_cgroup_id() -> u64 {
    unsafe {
        let f: unsafe extern "C" fn() -> u64 = core::mem::transmute(BPF_FUNC_GET_CURRENT_CGROUP_ID);
        f()
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SockTupleV4 {
    saddr: u32,
    daddr: u32,
    sport: u16,
    dport: u16,
}

#[inline(always)]
fn has_listener(ctx: &SockAddrContext, ip: u32, port: u32) -> bool {
    let tuple = SockTupleV4 {
        saddr: 0,
        daddr: ip,
        sport: 0,
        dport: port as u16,
    };
    let tuple_size = core::mem::size_of::<SockTupleV4>() as u32;

    unsafe {
        type LookupFn = unsafe extern "C" fn(
            *const core::ffi::c_void,
            *const SockTupleV4,
            u32,
            u64,
            u64,
        ) -> *mut core::ffi::c_void;

        type ReleaseFn = unsafe extern "C" fn(*mut core::ffi::c_void) -> i64;

        let release: ReleaseFn = core::mem::transmute(BPF_FUNC_SK_RELEASE);

        let tcp_lookup: LookupFn = core::mem::transmute(BPF_FUNC_SK_LOOKUP_TCP);
        let sk = tcp_lookup(
            ctx.sock_addr as *const core::ffi::c_void,
            &tuple,
            tuple_size,
            0,
            0,
        );
        if !sk.is_null() {
            release(sk);
            return true;
        }

        let udp_lookup: LookupFn = core::mem::transmute(BPF_FUNC_SK_LOOKUP_UDP);
        let sk = udp_lookup(
            ctx.sock_addr as *const core::ffi::c_void,
            &tuple,
            tuple_size,
            0,
            0,
        );
        if !sk.is_null() {
            release(sk);
            return true;
        }
    }

    false
}

#[inline(always)]
fn silo_ip() -> Option<u32> {
    let cgroup_id = current_cgroup_id();
    unsafe { SILO_CONFIG.get(&cgroup_id).copied() }
}

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
        unsafe {
            (*ctx.sock_addr).user_ip6 = [0, 0, 0x0000ffff_u32.to_be(), ip];
        }
    }
    1
}

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

#[cgroup_sock_addr(bind4)]
pub fn silo_bind4(ctx: SockAddrContext) -> i32 {
    rewrite_ip4(&ctx, true)
}

#[cgroup_sock_addr(bind6)]
pub fn silo_bind6(ctx: SockAddrContext) -> i32 {
    rewrite_ip6(&ctx, true)
}

#[cgroup_sock_addr(connect4)]
pub fn silo_connect4(ctx: SockAddrContext) -> i32 {
    let ip = match silo_ip() {
        Some(ip) if ip != 0 => ip,
        _ => return 1,
    };
    let addr = unsafe { (*ctx.sock_addr).user_ip4 };
    if addr == LOCALHOST_NBO {
        let port = unsafe { (*ctx.sock_addr).user_port };
        if has_listener(&ctx, ip, port) {
            unsafe { (*ctx.sock_addr).user_ip4 = ip };
        }
    }
    1
}

#[cgroup_sock_addr(connect6)]
pub fn silo_connect6(ctx: SockAddrContext) -> i32 {
    let ip = match silo_ip() {
        Some(ip) if ip != 0 => ip,
        _ => return 1,
    };
    let addr = unsafe { (*ctx.sock_addr).user_ip6 };
    let is_loopback = addr[0] == 0 && addr[1] == 0 && addr[2] == 0 && addr[3] == 1_u32.to_be();
    if is_loopback {
        let port = unsafe { (*ctx.sock_addr).user_port };
        if has_listener(&ctx, ip, port) {
            unsafe {
                (*ctx.sock_addr).user_ip6 = [0, 0, 0x0000ffff_u32.to_be(), ip];
            }
        }
    }
    1
}

#[cgroup_sock_addr(sendmsg4)]
pub fn silo_sendmsg4(ctx: SockAddrContext) -> i32 {
    rewrite_ip4(&ctx, true)
}

#[cgroup_sock_addr(sendmsg6)]
pub fn silo_sendmsg6(ctx: SockAddrContext) -> i32 {
    rewrite_ip6(&ctx, true)
}

#[cgroup_sock_addr(recvmsg4)]
pub fn silo_recvmsg4(ctx: SockAddrContext) -> i32 {
    reverse_ip4(&ctx)
}

#[cgroup_sock_addr(recvmsg6)]
pub fn silo_recvmsg6(ctx: SockAddrContext) -> i32 {
    reverse_ip6(&ctx)
}

#[cgroup_sock_addr(getpeername4)]
pub fn silo_getpeername4(ctx: SockAddrContext) -> i32 {
    reverse_ip4(&ctx)
}

#[cgroup_sock_addr(getpeername6)]
pub fn silo_getpeername6(ctx: SockAddrContext) -> i32 {
    reverse_ip6(&ctx)
}

#[cgroup_sock_addr(getsockname4)]
pub fn silo_getsockname4(ctx: SockAddrContext) -> i32 {
    reverse_ip4(&ctx)
}

#[cgroup_sock_addr(getsockname6)]
pub fn silo_getsockname6(ctx: SockAddrContext) -> i32 {
    reverse_ip6(&ctx)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
