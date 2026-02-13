#![no_main]

use libfuzzer_sys::fuzz_target;
use silo_bind::rewrite;
use std::net::Ipv4Addr;

fuzz_target!(|data: &str| {
    let result = rewrite::parse_silo_ip(data);

    // Invariant 1: If parsing succeeds, the result must be the network-byte-order
    // representation of the input parsed as an IPv4 address.
    if let Some(ip_be) = result {
        let expected: Ipv4Addr = data.parse().unwrap();
        assert_eq!(ip_be, u32::from(expected).to_be());
    }

    // Invariant 2: If std can parse it as Ipv4Addr, we must also succeed.
    if let Ok(std_ip) = data.parse::<Ipv4Addr>() {
        assert!(
            result.is_some(),
            "std parsed '{}' as {} but parse_silo_ip returned None",
            data,
            std_ip
        );
    }

    // Invariant 3: Must never panic regardless of input.
    // (If we got here, no panic occurred.)
});
