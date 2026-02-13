#![no_main]

use libfuzzer_sys::fuzz_target;
use silo_bind::rewrite;
use std::net::Ipv4Addr;

fuzz_target!(|data: (u32, [u8; 16], u32)| {
    let (ipv4_addr, ipv6_addr, silo_ip) = data;

    // -- IPv4 resolved --
    let v4_result = rewrite::rewrite_resolved_ipv4(ipv4_addr, silo_ip);

    // Only 127.0.0.1 and 0.0.0.0 should be rewritten.
    let localhost_be = u32::from(Ipv4Addr::LOCALHOST).to_be();
    let is_v4_target = ipv4_addr == localhost_be || ipv4_addr == 0;
    if !is_v4_target {
        assert!(
            v4_result.is_none(),
            "non-target resolved IPv4 was rewritten"
        );
    }

    // Idempotent.
    let v4_after = v4_result.unwrap_or(ipv4_addr);
    let v4_second = rewrite::rewrite_resolved_ipv4(v4_after, silo_ip).unwrap_or(v4_after);
    assert_eq!(v4_after, v4_second, "resolved IPv4 rewrite not idempotent");

    // -- IPv6 resolved --
    let v6_result = rewrite::rewrite_resolved_ipv6(ipv6_addr, silo_ip);

    // Only ::1 should be rewritten (not ::).
    if ipv6_addr != rewrite::V6_LOOPBACK {
        assert!(
            v6_result.is_none(),
            "non-loopback resolved IPv6 was rewritten"
        );
    }

    // Idempotent.
    let v6_after = v6_result.unwrap_or(ipv6_addr);
    let v6_second = rewrite::rewrite_resolved_ipv6(v6_after, silo_ip).unwrap_or(v6_after);
    assert_eq!(v6_after, v6_second, "resolved IPv6 rewrite not idempotent");
});
