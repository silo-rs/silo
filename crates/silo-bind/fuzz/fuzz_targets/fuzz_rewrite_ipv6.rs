#![no_main]

use libfuzzer_sys::fuzz_target;
use silo_bind::rewrite;

fuzz_target!(|data: ([u8; 16], u32, bool)| {
    let (s6_addr, silo_ip, match_any) = data;

    let result = rewrite::rewrite_ipv6_addr(s6_addr, silo_ip, match_any);

    // Invariant 1: Non-target addresses are never rewritten.
    let is_target =
        s6_addr == rewrite::V6_LOOPBACK || (match_any && s6_addr == rewrite::V6_ANY);
    if !is_target {
        assert!(result.is_none(), "non-target IPv6 address was rewritten");
    }

    // Invariant 2: Rewriting is idempotent.
    let after = result.unwrap_or(s6_addr);
    let second = rewrite::rewrite_ipv6_addr(after, silo_ip, match_any).unwrap_or(after);
    assert_eq!(after, second, "IPv6 rewrite is not idempotent");

    // Invariant 3: Rewritten addresses have ::ffff: prefix (IPv4-mapped).
    if let Some(rewritten) = result {
        assert_eq!(&rewritten[..10], &[0u8; 10], "missing IPv4-mapped prefix zeros");
        assert_eq!(rewritten[10], 0xff, "missing 0xff in mapped prefix");
        assert_eq!(rewritten[11], 0xff, "missing 0xff in mapped prefix");
    }
});
