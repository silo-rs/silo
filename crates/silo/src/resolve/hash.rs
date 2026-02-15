use std::net::Ipv4Addr;
use std::path::Path;

pub(super) const IP_VERSION: u8 = 1;
pub(super) const FNV_OFFSET: u64 = 0xcbf29ce484222325;
pub(super) const FNV_PRIME: u64 = 0x100000001b3;

pub fn compute_ip(canonical_path: &Path, name: &str) -> Ipv4Addr {
    let mut hash = FNV_OFFSET;
    hash ^= IP_VERSION as u64;
    hash = hash.wrapping_mul(FNV_PRIME);
    for &byte in canonical_path.as_os_str().as_encoded_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash ^= 0xff_u64;
    hash = hash.wrapping_mul(FNV_PRIME);
    for &byte in name.as_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    const OCTET1_RANGE: u64 = 254;
    const OCTET2_RANGE: u64 = 256;
    const OCTET3_RANGE: u64 = 254;
    const SPACE: u64 = OCTET1_RANGE * OCTET2_RANGE * OCTET3_RANGE;

    let raw = hash % SPACE;
    let o1 = (raw / (OCTET2_RANGE * OCTET3_RANGE)) as u8 + 1;
    let o2 = ((raw / OCTET3_RANGE) % OCTET2_RANGE) as u8;
    let o3 = (raw % OCTET3_RANGE) as u8 + 1;

    Ipv4Addr::new(127, o1, o2, o3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_ip_deterministic() {
        let path = Path::new("/home/user/project");
        let ip1 = compute_ip(path, "main");
        let ip2 = compute_ip(path, "main");
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn compute_ip_different_paths() {
        let ip1 = compute_ip(Path::new("/home/user/project-a"), "main");
        let ip2 = compute_ip(Path::new("/home/user/project-b"), "main");
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn compute_ip_different_names() {
        let path = Path::new("/home/user/project");
        let ip1 = compute_ip(path, "main");
        let ip2 = compute_ip(path, "feature");
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn compute_ip_in_range() {
        for i in 0..1000 {
            let path = format!("/test/path/{}", i);
            let ip = compute_ip(Path::new(&path), "main");
            let [o0, o1, _o2, o3] = ip.octets();
            assert_eq!(o0, 127);
            assert!((1..=254).contains(&o1), "second octet {o1} out of range");
            assert!((1..=254).contains(&o3), "fourth octet {o3} out of range");
        }
    }

    #[test]
    fn compute_ip_golden() {
        assert_eq!(
            compute_ip(Path::new("/home/user/project"), "main"),
            Ipv4Addr::new(127, 120, 134, 3),
        );
        assert_eq!(
            compute_ip(Path::new("/home/user/project"), "feature-auth"),
            Ipv4Addr::new(127, 185, 176, 25),
        );
        assert_eq!(
            compute_ip(Path::new("/tmp/myapp"), "develop"),
            Ipv4Addr::new(127, 139, 94, 75),
        );
    }

    #[test]
    fn compute_ip_never_localhost() {
        for i in 0..10_000 {
            let path = format!("/test/project/{i}");
            let ip = compute_ip(Path::new(&path), &format!("branch-{i}"));
            assert_ne!(
                ip,
                Ipv4Addr::new(127, 0, 0, 1),
                "generated localhost for {path}"
            );
        }
    }

    #[test]
    fn compute_ip_never_zero_octets() {
        for i in 0..10_000 {
            let path = format!("/proj/{i}");
            let ip = compute_ip(Path::new(&path), &format!("b{i}"));
            let [_, o1, _, o3] = ip.octets();
            assert_ne!(o1, 0, "second octet is 0 for {path}");
            assert_ne!(o3, 0, "fourth octet is 0 for {path}");
        }
    }

    #[test]
    fn compute_ip_collision_rate() {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        let n = 10_000;
        for i in 0..n {
            let path = format!("/users/dev/project-{}", i / 100);
            let ip = compute_ip(Path::new(&path), &format!("branch-{i}"));
            seen.insert(ip);
        }
        let collisions = n - seen.len();
        let expected_max = n * n / (2 * 16_516_096) + 50;
        assert!(
            collisions <= expected_max,
            "too many collisions: {collisions} (expected at most ~{expected_max})"
        );
    }
}
