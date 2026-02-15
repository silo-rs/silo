use std::net::Ipv4Addr;

const BEGIN_MARKER: &str = "# BEGIN silo managed block - do not edit";
const END_MARKER: &str = "# END silo managed block";

pub(super) fn find_ip_conflict(entries: &[String], ip: Ipv4Addr, hostname: &str) -> Option<String> {
    let ip_str = ip.to_string();
    for entry in entries {
        let mut parts = entry.split('\t');
        let Some(entry_ip) = parts.next() else {
            continue;
        };
        let Some(entry_host) = parts.next() else {
            continue;
        };
        if entry_ip == ip_str && entry_host != hostname {
            return Some(entry_host.to_string());
        }
    }
    None
}

pub(super) fn parse_block(content: &str) -> (String, Vec<String>, String) {
    enum State {
        Before,
        Inside,
        After,
    }

    let mut before = String::new();
    let mut entries = Vec::new();
    let mut after = String::new();
    let mut state = State::Before;

    for line in content.lines() {
        match state {
            State::Before => {
                if line == BEGIN_MARKER {
                    state = State::Inside;
                } else {
                    before.push_str(line);
                    before.push('\n');
                }
            }
            State::Inside => {
                if line == END_MARKER {
                    state = State::After;
                } else {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        entries.push(trimmed.to_string());
                    }
                }
            }
            State::After => {
                after.push_str(line);
                after.push('\n');
            }
        }
    }

    (before, entries, after)
}

pub(super) fn rebuild(before: String, entries: &[String], after: String) -> String {
    let mut out = before;

    if !out.ends_with('\n') && !out.is_empty() {
        out.push('\n');
    }

    if !entries.is_empty() {
        out.push_str(BEGIN_MARKER);
        out.push('\n');
        for entry in entries {
            out.push_str(entry);
            out.push('\n');
        }
        out.push_str(END_MARKER);
        out.push('\n');
    }

    out.push_str(&after);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_no_block() {
        let content = "127.0.0.1\tlocalhost\n::1\tlocalhost\n";
        let (before, entries, after) = parse_block(content);
        assert_eq!(before, content);
        assert!(entries.is_empty());
        assert_eq!(after, "");
    }

    #[test]
    fn parse_with_block() {
        let content = format!(
            "127.0.0.1\tlocalhost\n{}\n127.0.1.1\tapi.myapp.silo\n{}\n::1\tlocalhost\n",
            BEGIN_MARKER, END_MARKER
        );
        let (before, entries, after) = parse_block(&content);
        assert_eq!(before, "127.0.0.1\tlocalhost\n");
        assert_eq!(entries, vec!["127.0.1.1\tapi.myapp.silo"]);
        assert_eq!(after, "::1\tlocalhost\n");
    }

    #[test]
    fn rebuild_with_entries() {
        let before = "127.0.0.1\tlocalhost\n".to_string();
        let entries = vec!["127.0.1.1\tapi.myapp.silo".to_string()];
        let after = "::1\tlocalhost\n".to_string();

        let result = rebuild(before, &entries, after);
        let expected = format!(
            "127.0.0.1\tlocalhost\n{}\n127.0.1.1\tapi.myapp.silo\n{}\n::1\tlocalhost\n",
            BEGIN_MARKER, END_MARKER
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn rebuild_empty_entries_removes_block() {
        let before = "127.0.0.1\tlocalhost\n".to_string();
        let entries: Vec<String> = vec![];
        let after = "::1\tlocalhost\n".to_string();

        let result = rebuild(before, &entries, after);
        assert_eq!(result, "127.0.0.1\tlocalhost\n::1\tlocalhost\n");
    }

    #[test]
    fn roundtrip() {
        let original = format!(
            "127.0.0.1\tlocalhost\n{}\n127.0.1.1\tapi.myapp.silo\n127.0.1.2\tweb.myapp.silo\n{}\n::1\tlocalhost\n",
            BEGIN_MARKER, END_MARKER
        );
        let (before, entries, after) = parse_block(&original);
        let rebuilt = rebuild(before, &entries, after);
        assert_eq!(rebuilt, original);
    }

    #[test]
    fn roundtrip_with_dir_comment() {
        let original = format!(
            "127.0.0.1\tlocalhost\n{}\n127.0.1.1\tapi.myapp.silo\t# /home/user/myapp\n{}\n::1\tlocalhost\n",
            BEGIN_MARKER, END_MARKER
        );
        let (before, entries, after) = parse_block(&original);
        assert_eq!(
            entries,
            vec!["127.0.1.1\tapi.myapp.silo\t# /home/user/myapp"]
        );
        let rebuilt = rebuild(before, &entries, after);
        assert_eq!(rebuilt, original);
    }

    #[test]
    fn parse_block_missing_end_marker() {
        let content = format!(
            "127.0.0.1\tlocalhost\n{}\n127.0.1.1\tapi.myapp.silo\n::1\tlocalhost\n",
            BEGIN_MARKER
        );
        let (before, entries, after) = parse_block(&content);
        assert_eq!(before, "127.0.0.1\tlocalhost\n");
        assert_eq!(entries, vec!["127.0.1.1\tapi.myapp.silo", "::1\tlocalhost"]);
        assert_eq!(after, "");
    }

    #[test]
    fn parse_block_end_without_begin() {
        let content = format!("127.0.0.1\tlocalhost\n{}\n::1\tlocalhost\n", END_MARKER);
        let (before, entries, after) = parse_block(&content);
        assert_eq!(
            before,
            format!("127.0.0.1\tlocalhost\n{}\n::1\tlocalhost\n", END_MARKER)
        );
        assert!(entries.is_empty());
        assert_eq!(after, "");
    }

    #[test]
    fn parse_block_duplicate_begin_marker() {
        let content = format!(
            "127.0.0.1\tlocalhost\n{b}\n127.0.1.1\tapi.myapp.silo\n{b}\n127.0.1.2\tweb.myapp.silo\n{e}\n::1\tlocalhost\n",
            b = BEGIN_MARKER,
            e = END_MARKER
        );
        let (before, entries, after) = parse_block(&content);
        assert_eq!(before, "127.0.0.1\tlocalhost\n");
        assert!(entries.contains(&"127.0.1.1\tapi.myapp.silo".to_string()));
        assert_eq!(after, "::1\tlocalhost\n");
    }

    #[test]
    fn parse_block_crlf() {
        let content = format!(
            "127.0.0.1\tlocalhost\r\n{}\r\n127.0.1.1\tapi.myapp.silo\r\n{}\r\n::1\tlocalhost\r\n",
            BEGIN_MARKER, END_MARKER
        );
        let (before, entries, _after) = parse_block(&content);
        assert!(before.contains("localhost"));
        assert_eq!(entries.len(), 1);
        assert!(entries[0].contains("api.myapp.silo"));
    }

    #[test]
    fn parse_block_empty_file() {
        let (before, entries, after) = parse_block("");
        assert_eq!(before, "");
        assert!(entries.is_empty());
        assert_eq!(after, "");
    }

    #[test]
    fn parse_block_only_silo_block() {
        let content = format!(
            "{}\n127.0.1.1\tapi.myapp.silo\n{}\n",
            BEGIN_MARKER, END_MARKER
        );
        let (before, entries, after) = parse_block(&content);
        assert_eq!(before, "");
        assert_eq!(entries, vec!["127.0.1.1\tapi.myapp.silo"]);
        assert_eq!(after, "");
    }

    #[test]
    fn rebuild_no_trailing_newline_in_before() {
        let before = "127.0.0.1\tlocalhost".to_string();
        let entries = vec!["127.0.1.1\tapi.myapp.silo".to_string()];
        let after = String::new();

        let result = rebuild(before, &entries, after);
        assert!(result.contains(BEGIN_MARKER));
        assert!(result.contains("127.0.1.1\tapi.myapp.silo"));
        assert!(result.contains(END_MARKER));
    }

    #[test]
    fn find_ip_conflict_detects_collision() {
        let entries = vec!["127.1.2.3\tmain.project-a.silo\t# /home/user/a".to_string()];
        assert!(
            find_ip_conflict(&entries, Ipv4Addr::new(127, 1, 2, 3), "feat.project-b.silo")
                .is_some()
        );
        assert!(
            find_ip_conflict(&entries, Ipv4Addr::new(127, 1, 2, 3), "main.project-a.silo")
                .is_none()
        );
        assert!(
            find_ip_conflict(&entries, Ipv4Addr::new(127, 4, 5, 6), "feat.project-b.silo")
                .is_none()
        );
    }

    #[test]
    fn find_ip_conflict_empty_entries() {
        let entries: Vec<String> = vec![];
        assert!(find_ip_conflict(&entries, Ipv4Addr::new(127, 1, 2, 3), "test.silo").is_none());
    }

    #[test]
    fn find_ip_conflict_malformed_entry() {
        let entries = vec!["not-a-valid-entry".to_string()];
        assert!(find_ip_conflict(&entries, Ipv4Addr::new(127, 1, 2, 3), "test.silo").is_none());
    }
}
