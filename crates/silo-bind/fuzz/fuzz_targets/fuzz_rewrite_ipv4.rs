#![no_main]

use libfuzzer_sys::fuzz_target;
use silo_bind::rewrite;
use std::net::Ipv4Addr;

fuzz_target!(|data: (u32, u32, bool)| {
    let (s_addr, silo_ip, match_any) = data;

    let result = rewrite::rewrite_ipv4_addr(s_addr, silo_ip, match_any);

    // Invariant 1: Non-target addresses are never rewritten.
    let localhost_be = u32::from(Ipv4Addr::LOCALHOST).to_be();
    let is_target = s_addr == localhost_be || (match_any && s_addr == 0);
    if !is_target {
        assert!(result.is_none(), "non-target address was rewritten");
    }

    // Invariant 2: Rewriting is idempotent.
    let after = result.unwrap_or(s_addr);
    let second = rewrite::rewrite_ipv4_addr(after, silo_ip, match_any).unwrap_or(after);
    assert_eq!(after, second, "rewrite is not idempotent");

    // Invariant 3: If rewritten, result equals silo_ip.
    if let Some(rewritten) = result {
        assert_eq!(rewritten, silo_ip, "rewritten address doesn't match silo_ip");
    }
});
