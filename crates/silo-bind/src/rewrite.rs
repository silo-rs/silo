#![forbid(unsafe_code)]

use std::net::Ipv4Addr;

pub const V6_LOOPBACK: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
pub const V6_ANY: [u8; 16] = [0u8; 16];

pub fn parse_silo_ip(val: &str) -> Option<u32> {
    let ip: Ipv4Addr = val.parse().ok()?;
    if ip.octets()[0] != 127 || ip == Ipv4Addr::LOCALHOST {
        return None;
    }
    Some(u32::from(ip).to_be())
}

pub fn ipv4_mapped_v6(silo_ip: u32) -> [u8; 16] {
    let octets = silo_ip.to_ne_bytes();
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, octets[0], octets[1], octets[2], octets[3],
    ]
}

pub fn rewrite_ipv4_addr(s_addr: u32, silo_ip: u32, match_any: bool) -> Option<u32> {
    let localhost_be = u32::from(Ipv4Addr::LOCALHOST).to_be();
    if (match_any && s_addr == 0) || s_addr == localhost_be {
        Some(silo_ip)
    } else {
        None
    }
}

pub fn rewrite_ipv6_addr(s6_addr: [u8; 16], silo_ip: u32, match_any: bool) -> Option<[u8; 16]> {
    if (match_any && s6_addr == V6_ANY) || s6_addr == V6_LOOPBACK {
        Some(ipv4_mapped_v6(silo_ip))
    } else {
        None
    }
}

pub fn hide_alias(s_addr: u32, silo_ip: u32) -> Option<u32> {
    let localhost_be = u32::from(Ipv4Addr::LOCALHOST).to_be();
    let octets = s_addr.to_ne_bytes();
    if octets[0] == 127 && s_addr != localhost_be && s_addr != silo_ip {
        Some(localhost_be)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn silo_ip() -> u32 {
        u32::from(Ipv4Addr::new(127, 0, 99, 1)).to_be()
    }

    fn localhost_be() -> u32 {
        u32::from(Ipv4Addr::LOCALHOST).to_be()
    }

    #[test]
    fn parse_valid_ipv4() {
        assert_eq!(parse_silo_ip("127.0.99.1"), Some(silo_ip()));
    }

    #[test]
    fn parse_localhost_rejected() {
        assert_eq!(parse_silo_ip("127.0.0.1"), None);
    }

    #[test]
    fn parse_zeros_rejected() {
        assert_eq!(parse_silo_ip("0.0.0.0"), None);
    }

    #[test]
    fn parse_non_loopback_rejected() {
        assert_eq!(parse_silo_ip("10.0.0.1"), None);
        assert_eq!(parse_silo_ip("192.168.1.1"), None);
        assert_eq!(parse_silo_ip("8.8.8.8"), None);
    }

    #[test]
    fn parse_invalid_string() {
        assert_eq!(parse_silo_ip("not-an-ip"), None);
    }

    #[test]
    fn parse_empty_string() {
        assert_eq!(parse_silo_ip(""), None);
    }

    #[test]
    fn parse_ipv6_rejected() {
        assert_eq!(parse_silo_ip("::1"), None);
    }

    #[test]
    fn parse_overflow_rejected() {
        assert_eq!(parse_silo_ip("256.0.0.1"), None);
    }

    #[test]
    fn mapped_localhost() {
        let result = ipv4_mapped_v6(localhost_be());
        assert_eq!(
            result,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1]
        );
    }

    #[test]
    fn mapped_custom_ip() {
        let result = ipv4_mapped_v6(silo_ip());
        assert_eq!(
            result,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 99, 1]
        );
    }

    #[test]
    fn mapped_zeros() {
        let result = ipv4_mapped_v6(0);
        assert_eq!(
            result,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0]
        );
    }

    #[test]
    fn ipv4_localhost_match_any_true() {
        assert_eq!(
            rewrite_ipv4_addr(localhost_be(), silo_ip(), true),
            Some(silo_ip())
        );
    }

    #[test]
    fn ipv4_localhost_match_any_false() {
        assert_eq!(
            rewrite_ipv4_addr(localhost_be(), silo_ip(), false),
            Some(silo_ip())
        );
    }

    #[test]
    fn ipv4_any_match_any_true() {
        assert_eq!(rewrite_ipv4_addr(0, silo_ip(), true), Some(silo_ip()));
    }

    #[test]
    fn ipv4_any_match_any_false() {
        assert_eq!(rewrite_ipv4_addr(0, silo_ip(), false), None);
    }

    #[test]
    fn ipv4_other_addr_no_match() {
        let other = u32::from(Ipv4Addr::new(192, 168, 1, 1)).to_be();
        assert_eq!(rewrite_ipv4_addr(other, silo_ip(), true), None);
    }

    #[test]
    fn ipv4_silo_ip_itself_no_match() {
        assert_eq!(rewrite_ipv4_addr(silo_ip(), silo_ip(), true), None);
    }

    #[test]
    fn ipv4_broadcast_no_match() {
        assert_eq!(rewrite_ipv4_addr(0xFFFFFFFF, silo_ip(), true), None);
    }

    #[test]
    fn ipv6_loopback_match_any_true() {
        let expected = ipv4_mapped_v6(silo_ip());
        assert_eq!(
            rewrite_ipv6_addr(V6_LOOPBACK, silo_ip(), true),
            Some(expected)
        );
    }

    #[test]
    fn ipv6_loopback_match_any_false() {
        let expected = ipv4_mapped_v6(silo_ip());
        assert_eq!(
            rewrite_ipv6_addr(V6_LOOPBACK, silo_ip(), false),
            Some(expected)
        );
    }

    #[test]
    fn ipv6_any_match_any_true() {
        let expected = ipv4_mapped_v6(silo_ip());
        assert_eq!(rewrite_ipv6_addr(V6_ANY, silo_ip(), true), Some(expected));
    }

    #[test]
    fn ipv6_any_match_any_false() {
        assert_eq!(rewrite_ipv6_addr(V6_ANY, silo_ip(), false), None);
    }

    #[test]
    fn ipv6_other_no_match() {
        let link_local = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(rewrite_ipv6_addr(link_local, silo_ip(), true), None);
    }

    #[test]
    fn ipv6_already_mapped_no_match() {
        let mapped = ipv4_mapped_v6(silo_ip());
        assert_eq!(rewrite_ipv6_addr(mapped, silo_ip(), true), None);
    }

    #[test]
    fn hide_other_loopback() {
        let other = u32::from(Ipv4Addr::new(127, 0, 0, 2)).to_be();
        assert_eq!(hide_alias(other, silo_ip()), Some(localhost_be()));
    }

    #[test]
    fn hide_preserves_silo_ip() {
        assert_eq!(hide_alias(silo_ip(), silo_ip()), None);
    }

    #[test]
    fn hide_preserves_localhost() {
        assert_eq!(hide_alias(localhost_be(), silo_ip()), None);
    }

    #[test]
    fn hide_ignores_non_loopback() {
        let other = u32::from(Ipv4Addr::new(192, 168, 1, 1)).to_be();
        assert_eq!(hide_alias(other, silo_ip()), None);
    }

    #[test]
    fn hide_loopback_255() {
        let addr = u32::from(Ipv4Addr::new(127, 255, 255, 255)).to_be();
        assert_eq!(hide_alias(addr, silo_ip()), Some(localhost_be()));
    }

    #[test]
    fn connect_semantic_does_not_match_any() {
        assert_eq!(rewrite_ipv4_addr(0, silo_ip(), false), None);
        assert_eq!(
            rewrite_ipv4_addr(localhost_be(), silo_ip(), false),
            Some(silo_ip())
        );
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        fn arb_v6() -> impl Strategy<Value = [u8; 16]> {
            proptest::array::uniform16(any::<u8>())
        }

        proptest! {
            #[test]
            fn ipv4_rewrite_idempotent(s_addr: u32, silo_ip: u32, match_any: bool) {
                let first = rewrite_ipv4_addr(s_addr, silo_ip, match_any).unwrap_or(s_addr);
                let second = rewrite_ipv4_addr(first, silo_ip, match_any).unwrap_or(first);
                prop_assert_eq!(first, second);
            }

            #[test]
            fn ipv6_rewrite_idempotent(s6_addr in arb_v6(), silo_ip: u32, match_any: bool) {
                let first = rewrite_ipv6_addr(s6_addr, silo_ip, match_any).unwrap_or(s6_addr);
                let second = rewrite_ipv6_addr(first, silo_ip, match_any).unwrap_or(first);
                prop_assert_eq!(first, second);
            }

            #[test]
            fn hide_alias_idempotent(s_addr: u32, silo_ip: u32) {
                let first = hide_alias(s_addr, silo_ip).unwrap_or(s_addr);
                let second = hide_alias(first, silo_ip).unwrap_or(first);
                prop_assert_eq!(first, second);
            }
        }

        proptest! {
            #[test]
            fn ipv4_non_target_untouched(s_addr: u32, silo_ip: u32, match_any: bool) {
                let localhost_be = u32::from(Ipv4Addr::LOCALHOST).to_be();
                let is_target = s_addr == localhost_be || (match_any && s_addr == 0);
                if !is_target {
                    prop_assert_eq!(rewrite_ipv4_addr(s_addr, silo_ip, match_any), None);
                }
            }

            #[test]
            fn ipv6_non_target_untouched(s6_addr in arb_v6(), silo_ip: u32, match_any: bool) {
                let is_target = s6_addr == V6_LOOPBACK || (match_any && s6_addr == V6_ANY);
                if !is_target {
                    prop_assert_eq!(rewrite_ipv6_addr(s6_addr, silo_ip, match_any), None);
                }
            }

            #[test]
            fn hide_preserves_non_127(s_addr: u32, silo_ip: u32) {
                let octets = s_addr.to_ne_bytes();
                if octets[0] != 127 {
                    prop_assert_eq!(hide_alias(s_addr, silo_ip), None);
                }
            }
        }

        proptest! {
            #[test]
            fn mapped_v6_has_correct_prefix(ip: u32) {
                let result = ipv4_mapped_v6(ip);
                prop_assert_eq!(&result[..10], &[0u8; 10]);
                prop_assert_eq!(result[10], 0xff);
                prop_assert_eq!(result[11], 0xff);
                prop_assert_eq!(&result[12..16], &ip.to_ne_bytes());
            }

            #[test]
            fn parse_roundtrip(a in 0u8..=255, b in 0u8..=255, c in 0u8..=255, d in 0u8..=255) {
                let s = format!("{a}.{b}.{c}.{d}");
                let result = parse_silo_ip(&s);
                if a == 127 && !(b == 0 && c == 0 && d == 1) {
                    let expected = u32::from(Ipv4Addr::new(a, b, c, d)).to_be();
                    prop_assert_eq!(result, Some(expected));
                } else {
                    prop_assert_eq!(result, None);
                }
            }
        }
    }

    #[test]
    fn parse_silo_ip_trailing_whitespace() {
        assert_eq!(parse_silo_ip("127.0.99.1 "), None);
    }

    #[test]
    fn parse_silo_ip_leading_zeros() {
        assert_eq!(parse_silo_ip("127.000.099.001"), None);
    }

    #[test]
    fn parse_silo_ip_with_port() {
        assert_eq!(parse_silo_ip("127.0.99.1:8080"), None);
    }

    #[test]
    fn parse_silo_ip_boundary_smallest() {
        assert!(parse_silo_ip("127.0.0.2").is_some());
    }

    #[test]
    fn parse_silo_ip_boundary_largest() {
        assert!(parse_silo_ip("127.255.255.255").is_some());
    }

    #[test]
    fn ipv4_silo_ip_itself_no_match_any_false() {
        assert_eq!(rewrite_ipv4_addr(silo_ip(), silo_ip(), false), None);
    }

    #[test]
    fn ipv6_mapped_localhost_no_match() {
        let mapped_localhost = ipv4_mapped_v6(u32::from(Ipv4Addr::LOCALHOST).to_be());
        assert_eq!(rewrite_ipv6_addr(mapped_localhost, silo_ip(), true), None);
    }

    #[test]
    fn hide_alias_zero_addr() {
        assert_eq!(hide_alias(0, silo_ip()), None);
    }
}
