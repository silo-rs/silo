use std::net::Ipv4Addr;

use crate::error::ValidationError;

pub fn validate_ip(ip: Ipv4Addr) -> Result<(), ValidationError> {
    if ip.octets()[0] != 127 {
        return Err(ValidationError::IpNotLoopback(ip));
    }
    if ip == Ipv4Addr::new(127, 0, 0, 1) {
        return Err(ValidationError::IpReservedLocalhost);
    }
    Ok(())
}

pub fn validate_hostname(hostname: &str) -> Result<(), ValidationError> {
    if !hostname.ends_with(".silo") {
        return Err(ValidationError::HostnameMissingSuffix(hostname.to_string()));
    }
    let prefix = &hostname[..hostname.len() - 5];
    if prefix.is_empty() || prefix == "." {
        return Err(ValidationError::HostnameEmptyPrefix);
    }
    if hostname.len() > 253 {
        return Err(ValidationError::HostnameTooLong);
    }
    if !hostname
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(ValidationError::HostnameInvalidChars(hostname.to_string()));
    }
    Ok(())
}

pub fn validate_dir(dir: &str) -> Result<(), ValidationError> {
    if dir.is_empty() {
        return Err(ValidationError::DirEmpty);
    }
    if dir.contains('\n') || dir.contains('\r') || dir.contains('\t') || dir.contains('\0') {
        return Err(ValidationError::DirInvalidChars);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_ip_accepts_loopback() {
        assert!(validate_ip(Ipv4Addr::new(127, 0, 1, 1)).is_ok());
        assert!(validate_ip(Ipv4Addr::new(127, 255, 255, 254)).is_ok());
    }

    #[test]
    fn validate_ip_rejects_localhost() {
        assert!(validate_ip(Ipv4Addr::new(127, 0, 0, 1)).is_err());
    }

    #[test]
    fn validate_ip_rejects_non_loopback() {
        assert!(validate_ip(Ipv4Addr::new(10, 0, 0, 1)).is_err());
        assert!(validate_ip(Ipv4Addr::new(192, 168, 1, 1)).is_err());
        assert!(validate_ip(Ipv4Addr::new(0, 0, 0, 0)).is_err());
    }

    #[test]
    fn validate_hostname_accepts_valid() {
        assert!(validate_hostname("feat.project.silo").is_ok());
        assert!(validate_hostname("main.my-app.silo").is_ok());
        assert!(validate_hostname("a.silo").is_ok());
        assert!(validate_hostname("feature-auth.my_project.silo").is_ok());
    }

    #[test]
    fn validate_hostname_rejects_no_silo_suffix() {
        assert!(validate_hostname("foo.com").is_err());
        assert!(validate_hostname("foo.sil").is_err());
    }

    #[test]
    fn validate_hostname_rejects_empty_prefix() {
        assert!(validate_hostname(".silo").is_err());
    }

    #[test]
    fn validate_hostname_rejects_newline() {
        assert!(validate_hostname("foo.silo\n127.0.0.1 evil").is_err());
    }

    #[test]
    fn validate_hostname_rejects_tab() {
        assert!(validate_hostname("foo.silo\tevil").is_err());
    }

    #[test]
    fn validate_hostname_rejects_space() {
        assert!(validate_hostname("foo .silo").is_err());
    }

    #[test]
    fn validate_hostname_rejects_too_long() {
        let long = format!("{}.silo", "a".repeat(250));
        assert!(validate_hostname(&long).is_err());
    }

    #[test]
    fn validate_hostname_boundary_253() {
        let prefix_len = 253 - 5;
        let prefix = "a".repeat(prefix_len);
        let hostname = format!("{prefix}.silo");
        assert_eq!(hostname.len(), 253);
        assert!(validate_hostname(&hostname).is_ok());
    }

    #[test]
    fn validate_hostname_boundary_254() {
        let prefix_len = 254 - 5;
        let prefix = "a".repeat(prefix_len);
        let hostname = format!("{prefix}.silo");
        assert_eq!(hostname.len(), 254);
        assert!(validate_hostname(&hostname).is_err());
    }

    #[test]
    fn validate_dir_accepts_valid() {
        assert!(validate_dir("/home/user/project").is_ok());
        assert!(validate_dir("/tmp/my app").is_ok());
    }

    #[test]
    fn validate_dir_rejects_newline() {
        assert!(validate_dir("/home/user\n# evil").is_err());
    }

    #[test]
    fn validate_dir_rejects_tab() {
        assert!(validate_dir("/home/user\tevil").is_err());
    }

    #[test]
    fn validate_dir_rejects_empty() {
        assert!(validate_dir("").is_err());
    }

    #[test]
    fn validate_dir_rejects_null() {
        assert!(validate_dir("/home/user\0evil").is_err());
    }
}
