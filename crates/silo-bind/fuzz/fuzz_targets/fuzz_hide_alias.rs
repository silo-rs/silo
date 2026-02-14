#![no_main]

use libfuzzer_sys::fuzz_target;
use silo_bind::rewrite;
use std::net::Ipv4Addr;

fuzz_target!(|data: (u32, u32)| {
    let (s_addr, silo_ip) = data;

    let result = rewrite::hide_alias(s_addr, silo_ip);
    let octets = s_addr.to_ne_bytes();
    let localhost_be = u32::from(Ipv4Addr::LOCALHOST).to_be();

    if octets[0] != 127 {
        assert!(result.is_none(), "non-loopback address was hidden");
    }

    if s_addr == localhost_be {
        assert!(result.is_none(), "localhost was hidden");
    }

    if s_addr == silo_ip {
        assert!(result.is_none(), "silo_ip was hidden");
    }

    if let Some(hidden) = result {
        assert_eq!(hidden, localhost_be, "hidden address is not 127.0.0.1");
    }

    let after = result.unwrap_or(s_addr);
    let second = rewrite::hide_alias(after, silo_ip).unwrap_or(after);
    assert_eq!(after, second, "hide_alias is not idempotent");
});
