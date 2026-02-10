use std::io::Write;
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::{Command, Stdio};

use eyre::Context;
use fs2::FileExt;
use tracing::{debug, instrument};

use crate::ip;

const HOSTS_PATH: &str = "/etc/hosts";
const LOCK_PATH: &str = "/tmp/silo-hosts.lock";
const BEGIN_MARKER: &str = "# BEGIN silo managed block - do not edit";
const END_MARKER: &str = "# END silo managed block";

/// RAII file lock using flock(2) via fs2. Automatically released on drop.
struct FileLock {
    file: std::fs::File,
}

impl FileLock {
    /// Acquire an exclusive lock on the given path, blocking until available.
    fn exclusive(path: &str) -> eyre::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("failed to open lock file: {path}"))?;

        file.lock_exclusive()
            .with_context(|| format!("failed to acquire file lock on {path}"))?;

        debug!(path, "acquired hosts file lock");
        Ok(Self { file })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

pub fn hostname(name: &str, repo: &Path) -> String {
    let repo_dir = repo
        .file_name()
        .map(|s| s.to_string_lossy())
        .unwrap_or_default();
    format!("{}.{}.silo", name, repo_dir)
}

#[instrument]
pub fn add_entry(ip: Ipv4Addr, hostname: &str) -> eyre::Result<()> {
    ip::ensure_sudoers()?;
    let _lock = FileLock::exclusive(LOCK_PATH)?;

    let content = read_hosts()?;
    let (before, mut entries, after) = parse_block(&content);

    let new_line = format!("{}\t{}", ip, hostname);

    if let Some(pos) = entries
        .iter()
        .position(|e| e.split('\t').nth(1).map(|h| h == hostname).unwrap_or(false))
    {
        entries[pos] = new_line;
    } else {
        entries.push(new_line);
    }

    let output = rebuild(before, &entries, after);
    write_hosts(&output)?;

    eprintln!("  adding hosts entry {} -> {}", hostname, ip);
    Ok(())
}

#[instrument]
pub fn remove_entry(hostname: &str) -> eyre::Result<()> {
    ip::ensure_sudoers()?;
    let _lock = FileLock::exclusive(LOCK_PATH)?;

    let content = read_hosts()?;
    let (before, mut entries, after) = parse_block(&content);

    let len_before = entries.len();
    entries.retain(|e| e.split('\t').nth(1).map(|h| h != hostname).unwrap_or(true));

    if entries.len() == len_before {
        debug!(%hostname, "no hosts entry found, skipping");
        return Ok(());
    }

    let output = rebuild(before, &entries, after);
    write_hosts(&output)?;

    eprintln!("  removing hosts entry {}", hostname);
    Ok(())
}

#[instrument(skip(entries))]
pub fn sync_entries(entries: &[(Ipv4Addr, String)]) -> eyre::Result<()> {
    ip::ensure_sudoers()?;
    let _lock = FileLock::exclusive(LOCK_PATH)?;

    let content = read_hosts()?;
    let (before, _, after) = parse_block(&content);

    let lines: Vec<String> = entries
        .iter()
        .map(|(ip, host)| format!("{}\t{}", ip, host))
        .collect();

    let output = rebuild(before, &lines, after);
    write_hosts(&output)?;

    Ok(())
}

pub fn has_managed_block() -> eyre::Result<bool> {
    let content = read_hosts()?;
    Ok(content.contains(BEGIN_MARKER))
}

pub fn current_entries() -> eyre::Result<Vec<String>> {
    let content = read_hosts()?;
    let (_, entries, _) = parse_block(&content);
    Ok(entries
        .iter()
        .filter_map(|line| line.split_whitespace().nth(1).map(String::from))
        .collect())
}

fn read_hosts() -> eyre::Result<String> {
    std::fs::read_to_string(HOSTS_PATH).context("failed to read /etc/hosts")
}

fn write_hosts(content: &str) -> eyre::Result<()> {
    debug!("writing /etc/hosts via sudo tee");
    let mut child = Command::new("sudo")
        .args(["tee", HOSTS_PATH])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to run sudo tee /etc/hosts")?;

    if let Some(ref mut stdin) = child.stdin {
        stdin
            .write_all(content.as_bytes())
            .context("failed to write to sudo tee stdin")?;
    }

    let status = child.wait().context("failed to wait for sudo tee")?;
    if !status.success() {
        eyre::bail!("sudo tee /etc/hosts failed");
    }

    Ok(())
}

fn parse_block(content: &str) -> (String, Vec<String>, String) {
    let mut before = String::new();
    let mut entries = Vec::new();
    let mut after = String::new();

    let mut state = ParseState::Before;

    for line in content.lines() {
        match state {
            ParseState::Before => {
                if line == BEGIN_MARKER {
                    state = ParseState::Inside;
                } else {
                    before.push_str(line);
                    before.push('\n');
                }
            }
            ParseState::Inside => {
                if line == END_MARKER {
                    state = ParseState::After;
                } else {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        entries.push(trimmed.to_string());
                    }
                }
            }
            ParseState::After => {
                after.push_str(line);
                after.push('\n');
            }
        }
    }

    (before, entries, after)
}

enum ParseState {
    Before,
    Inside,
    After,
}

fn rebuild(before: String, entries: &[String], after: String) -> String {
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
    fn hostname_format() {
        assert_eq!(
            hostname("feature-a", Path::new("/home/user/myproject")),
            "feature-a.myproject.silo"
        );
    }

    #[test]
    fn hostname_nested_repo() {
        assert_eq!(
            hostname("api", Path::new("/work/repos/backend")),
            "api.backend.silo"
        );
    }

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
    fn no_false_positive_on_suffix_hostname() {
        // "old-api.myapp.silo" should NOT match when looking for "api.myapp.silo"
        let entries = [
            "127.0.1.1\told-api.myapp.silo".to_string(),
            "127.0.1.2\tweb.myapp.silo".to_string(),
        ];
        let hostname = "api.myapp.silo";

        // add_entry logic: should not find a match
        let pos = entries
            .iter()
            .position(|e| e.split('\t').nth(1).map(|h| h == hostname).unwrap_or(false));
        assert!(pos.is_none());

        // remove_entry logic: should not remove old-api
        let filtered: Vec<_> = entries
            .iter()
            .filter(|e| e.split('\t').nth(1).map(|h| h != hostname).unwrap_or(true))
            .collect();
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn parse_and_rebuild_roundtrip() {
        let original = format!(
            "127.0.0.1\tlocalhost\n{}\n127.0.1.1\tapi.myapp.silo\n127.0.1.2\tweb.myapp.silo\n{}\n::1\tlocalhost\n",
            BEGIN_MARKER, END_MARKER
        );
        let (before, entries, after) = parse_block(&original);
        let rebuilt = rebuild(before, &entries, after);
        assert_eq!(rebuilt, original);
    }

    #[test]
    fn flock_acquire_and_release() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("test.lock");
        let lock_str = lock_path.to_str().unwrap();

        // Should acquire successfully
        let lock = FileLock::exclusive(lock_str).unwrap();
        assert!(lock_path.exists());

        // A second open file description should fail with try_lock
        let file2 = std::fs::File::options()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap();
        assert!(
            file2.try_lock_exclusive().is_err(),
            "expected lock to be held"
        );

        // Drop the first lock
        drop(lock);

        // Now the second should succeed
        file2.lock_exclusive().unwrap();
        file2.unlock().unwrap();
    }

    #[test]
    fn flock_sequential_reacquire() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("test.lock");
        let lock_str = lock_path.to_str().unwrap();

        let lock1 = FileLock::exclusive(lock_str).unwrap();
        drop(lock1);

        // Re-acquiring after release should work
        let lock2 = FileLock::exclusive(lock_str).unwrap();
        drop(lock2);
    }
}
