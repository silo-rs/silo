#![no_main]

use libfuzzer_sys::fuzz_target;
use silo_bind::rewrite;
use std::net::Ipv4Addr;

fuzz_target!(|data: &str| {
    let result = rewrite::parse_silo_ip(data);

    if let Some(ip_be) = result {
        let expected: Ipv4Addr = data.parse().unwrap();
        assert_eq!(ip_be, u32::from(expected).to_be());
    }

    if let Ok(std_ip) = data.parse::<Ipv4Addr>() {
        if std_ip.octets()[0] == 127 {
            assert!(
                result.is_some(),
                "std parsed '{}' as loopback {} but parse_silo_ip returned None",
                data,
                std_ip
            );
        } else {
            assert!(
                result.is_none(),
                "non-loopback '{}' ({}) should be rejected but parse_silo_ip returned Some",
                data,
                std_ip
            );
        }
    }
});
