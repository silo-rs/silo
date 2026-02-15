use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;

use tracing::debug;

pub fn active_loopback_aliases() -> eyre::Result<Vec<Ipv4Addr>> {
    Ok(silo::ip::active_aliases()?)
}

pub fn listening_ports() -> HashMap<Ipv4Addr, Vec<u16>> {
    let output = match listening_ports_output() {
        Ok(o) => o,
        Err(e) => {
            debug!("failed to get listening ports: {e}");
            return HashMap::new();
        }
    };
    parse_listening_ports(&output)
}

fn listening_ports_output() -> eyre::Result<String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("lsof")
            .args(["-nP", "-iTCP", "-sTCP:LISTEN"])
            .output()?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ss").args(["-tlnH"]).output()?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

fn parse_listening_ports(output: &str) -> HashMap<Ipv4Addr, Vec<u16>> {
    let mut map: HashMap<Ipv4Addr, Vec<u16>> = HashMap::new();

    for line in output.lines() {
        let addr_port = extract_listen_address(line);
        let Some((ip_str, port_str)) = addr_port else {
            continue;
        };
        let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
            continue;
        };
        if ip.octets()[0] != 127 || ip == Ipv4Addr::new(127, 0, 0, 1) {
            continue;
        }
        let Ok(port) = port_str.parse::<u16>() else {
            continue;
        };
        let ports = map.entry(ip).or_default();
        if !ports.contains(&port) {
            ports.push(port);
        }
    }

    for ports in map.values_mut() {
        ports.sort();
    }

    map
}

fn extract_listen_address(line: &str) -> Option<(&str, &str)> {
    #[cfg(target_os = "macos")]
    {
        let addr_part = line.split_whitespace().find(|tok| {
            tok.contains(':')
                && tok
                    .split(':')
                    .next()
                    .is_some_and(|ip| ip.starts_with("127."))
        })?;
        let (ip, port) = addr_part.rsplit_once(':')?;
        Some((ip, port))
    }

    #[cfg(target_os = "linux")]
    {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let local = fields.get(3)?;
        let (ip, port) = local.rsplit_once(':')?;
        Some((ip, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_output() {
        let map = parse_listening_ports("");
        assert!(map.is_empty());
    }

    #[test]
    fn parse_filters_localhost() {
        let map = parse_listening_ports("dummy 127.0.0.1:8080 stuff");
        assert!(!map.contains_key(&Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn parse_filters_non_loopback() {
        let map = parse_listening_ports("dummy 192.168.1.1:8080 stuff");
        assert!(map.is_empty());
    }

    #[cfg(target_os = "macos")]
    mod macos {
        use super::*;

        const LSOF_OUTPUT: &str = "\
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
node    12345 user   23u  IPv4 0x1234      0t0  TCP 127.1.2.3:3000 (LISTEN)
node    12345 user   24u  IPv4 0x1235      0t0  TCP 127.1.2.3:3001 (LISTEN)
node    12346 user   10u  IPv4 0x1236      0t0  TCP 127.0.0.1:5432 (LISTEN)
node    12347 user   11u  IPv4 0x1237      0t0  TCP 127.1.4.5:8080 (LISTEN)";

        #[test]
        fn parse_lsof_output() {
            let map = parse_listening_ports(LSOF_OUTPUT);
            let ip1 = Ipv4Addr::new(127, 1, 2, 3);
            let ip2 = Ipv4Addr::new(127, 1, 4, 5);
            assert_eq!(map.get(&ip1).unwrap(), &vec![3000, 3001]);
            assert_eq!(map.get(&ip2).unwrap(), &vec![8080]);
            assert!(!map.contains_key(&Ipv4Addr::new(127, 0, 0, 1)));
        }

        #[test]
        fn extract_lsof_line() {
            let line = "node 123 user 23u IPv4 0x1234 0t0 TCP 127.1.2.3:3000 (LISTEN)";
            let (ip, port) = extract_listen_address(line).unwrap();
            assert_eq!(ip, "127.1.2.3");
            assert_eq!(port, "3000");
        }

        #[test]
        fn extract_no_loopback_returns_none() {
            let line = "node 123 user 23u IPv4 0x1234 0t0 TCP 192.168.1.1:80 (LISTEN)";
            assert!(extract_listen_address(line).is_none());
        }

        #[test]
        fn ports_are_sorted() {
            let input = "\
COMMAND PID USER FD TYPE DEVICE SIZE NODE NAME
x 1 u 1u IPv4 0 0t0 TCP 127.1.0.1:9000 (LISTEN)
x 1 u 2u IPv4 0 0t0 TCP 127.1.0.1:80 (LISTEN)
x 1 u 3u IPv4 0 0t0 TCP 127.1.0.1:443 (LISTEN)";
            let map = parse_listening_ports(input);
            let ports = map.get(&Ipv4Addr::new(127, 1, 0, 1)).unwrap();
            assert_eq!(ports, &vec![80, 443, 9000]);
        }

        #[test]
        fn no_duplicate_ports() {
            let input = "\
COMMAND PID USER FD TYPE DEVICE SIZE NODE NAME
x 1 u 1u IPv4 0 0t0 TCP 127.1.0.1:3000 (LISTEN)
x 2 u 1u IPv4 0 0t0 TCP 127.1.0.1:3000 (LISTEN)";
            let map = parse_listening_ports(input);
            let ports = map.get(&Ipv4Addr::new(127, 1, 0, 1)).unwrap();
            assert_eq!(ports, &vec![3000]);
        }
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;

        const SS_OUTPUT: &str = "\
LISTEN 0 128 127.1.2.3:3000 0.0.0.0:*
LISTEN 0 128 127.1.2.3:3001 0.0.0.0:*
LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*
LISTEN 0 128 127.1.4.5:8080 0.0.0.0:*";

        #[test]
        fn parse_ss_output() {
            let map = parse_listening_ports(SS_OUTPUT);
            let ip1 = Ipv4Addr::new(127, 1, 2, 3);
            let ip2 = Ipv4Addr::new(127, 1, 4, 5);
            assert_eq!(map.get(&ip1).unwrap(), &vec![3000, 3001]);
            assert_eq!(map.get(&ip2).unwrap(), &vec![8080]);
            assert!(!map.contains_key(&Ipv4Addr::new(127, 0, 0, 1)));
        }

        #[test]
        fn extract_ss_line() {
            let line = "LISTEN 0 128 127.1.2.3:3000 0.0.0.0:*";
            let (ip, port) = extract_listen_address(line).unwrap();
            assert_eq!(ip, "127.1.2.3");
            assert_eq!(port, "3000");
        }

        #[test]
        fn ports_are_sorted() {
            let input = "\
LISTEN 0 128 127.1.0.1:9000 0.0.0.0:*
LISTEN 0 128 127.1.0.1:80 0.0.0.0:*
LISTEN 0 128 127.1.0.1:443 0.0.0.0:*";
            let map = parse_listening_ports(input);
            let ports = map.get(&Ipv4Addr::new(127, 1, 0, 1)).unwrap();
            assert_eq!(ports, &vec![80, 443, 9000]);
        }

        #[test]
        fn no_duplicate_ports() {
            let input = "\
LISTEN 0 128 127.1.0.1:3000 0.0.0.0:*
LISTEN 0 128 127.1.0.1:3000 0.0.0.0:*";
            let map = parse_listening_ports(input);
            let ports = map.get(&Ipv4Addr::new(127, 1, 0, 1)).unwrap();
            assert_eq!(ports, &vec![3000]);
        }
    }
}
