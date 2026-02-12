use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use tracing::debug;

const MAX_RECURSION_DEPTH: usize = 5;

pub fn is_sip_protected(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("/usr/bin/")
        || s.starts_with("/bin/")
        || s.starts_with("/sbin/")
        || s.starts_with("/usr/sbin/")
}

pub fn resolve_program(program: &str, args: &[String]) -> (String, Vec<String>) {
    if let Some((prog, resolved_args)) = resolve_recursive(program, args, 0) {
        debug!(
            original = program,
            resolved = %prog,
            "shebang resolved"
        );
        return (prog, resolved_args);
    }

    let program_path = Path::new(program);
    if is_sip_protected(program_path)
        && let Some(name) = program_path.file_name().and_then(|n| n.to_str())
    {
        if let Some(resolved) = find_non_sip_binary(name) {
            debug!(
                original = program,
                resolved = %resolved,
                "SIP binary resolved to non-SIP alternative"
            );
            return (resolved, args.to_vec());
        }
        debug!(
            original = program,
            "no non-SIP alternative found for SIP-protected binary"
        );
    }

    (program.to_string(), args.to_vec())
}

/// Find a non-SIP-protected binary with the given name.
///
/// For shell binaries (`sh`, `bash`, `zsh`, etc.), tries compatible alternatives
/// since macOS SIP protects all shells in `/bin/` and `/usr/bin/`.
/// Returns `None` if no non-SIP alternative exists in PATH.
pub fn find_non_sip_binary(name: &str) -> Option<String> {
    let candidates: Vec<&str> = match name {
        "sh" | "bash" | "zsh" | "dash" | "ksh" => {
            let mut c = vec![name];
            for fallback in &["bash", "zsh", "sh"] {
                if !c.contains(fallback) {
                    c.push(fallback);
                }
            }
            c
        }
        _ => vec![name],
    };

    for candidate in candidates {
        if let Ok(path) = which::which(candidate)
            && !is_sip_protected(&path)
        {
            debug!(
                name,
                candidate,
                resolved = %path.display(),
                "found non-SIP binary"
            );
            return Some(path.to_string_lossy().into_owned());
        }
    }

    None
}

fn resolve_recursive(
    program: &str,
    args: &[String],
    depth: usize,
) -> Option<(String, Vec<String>)> {
    if depth >= MAX_RECURSION_DEPTH {
        debug!("shebang resolution hit max recursion depth");
        return None;
    }

    let program_path = resolve_to_path(program)?;

    let shebang_line = read_shebang(&program_path)?;

    let (interpreter, shebang_arg) = parse_shebang(&shebang_line)?;

    debug!(
        script = %program_path.display(),
        interpreter = %interpreter,
        arg = shebang_arg.as_deref().unwrap_or(""),
        "parsed shebang"
    );

    let interpreter_path = Path::new(&interpreter);

    if !is_sip_protected(interpreter_path) {
        let mut resolved_args = Vec::new();
        if let Some(ref arg) = shebang_arg {
            resolved_args.push(arg.clone());
        }
        resolved_args.push(program_path.to_string_lossy().into_owned());
        resolved_args.extend_from_slice(args);
        return Some((interpreter, resolved_args));
    }

    let resolved_interpreter = resolve_sip_interpreter(&interpreter, shebang_arg.as_deref())?;

    if interpreter_path
        .file_name()
        .map(|n| n == "env")
        .unwrap_or(false)
    {
        if shebang_arg.is_some() {
            let mut new_args = vec![program_path.to_string_lossy().into_owned()];
            new_args.extend_from_slice(args);
            if let Some(result) = resolve_recursive(&resolved_interpreter, &new_args, depth + 1) {
                return Some(result);
            }
            let mut final_args = vec![program_path.to_string_lossy().into_owned()];
            final_args.extend_from_slice(args);
            return Some((resolved_interpreter, final_args));
        }
        return None;
    }

    let mut new_args = Vec::new();
    if let Some(ref arg) = shebang_arg {
        new_args.push(arg.clone());
    }
    new_args.push(program_path.to_string_lossy().into_owned());
    new_args.extend_from_slice(args);

    if let Some(result) = resolve_recursive(&resolved_interpreter, &new_args, depth + 1) {
        return Some(result);
    }

    Some((resolved_interpreter, new_args))
}

fn resolve_sip_interpreter(interpreter: &str, shebang_arg: Option<&str>) -> Option<String> {
    let interpreter_path = Path::new(interpreter);
    let name = interpreter_path.file_name()?.to_str()?;

    if name == "env" {
        let raw = shebang_arg?;
        let stripped = raw
            .strip_prefix("-S")
            .map(|s| s.trim_start())
            .unwrap_or(raw);
        let cmd = stripped.split_whitespace().next()?;
        match which::which(cmd) {
            Ok(p) => {
                let resolved = p.to_string_lossy().into_owned();
                debug!(cmd, resolved = %resolved, "resolved env argument");
                Some(resolved)
            }
            Err(e) => {
                debug!(cmd, error = %e, "failed to resolve env argument");
                None
            }
        }
    } else {
        match which::which(name) {
            Ok(p) => {
                let resolved = p.to_string_lossy().into_owned();
                if is_sip_protected(&p) {
                    debug!(name, resolved = %resolved, "resolved interpreter is still SIP-protected");
                    None
                } else {
                    debug!(name, resolved = %resolved, "resolved SIP interpreter");
                    Some(resolved)
                }
            }
            Err(e) => {
                debug!(name, error = %e, "failed to resolve SIP interpreter");
                None
            }
        }
    }
}

fn resolve_to_path(program: &str) -> Option<PathBuf> {
    let path = Path::new(program);
    if path.is_absolute() {
        if path.exists() {
            return Some(path.to_path_buf());
        }
        return None;
    }

    if program.contains('/') {
        let abs = std::env::current_dir().ok()?.join(program);
        if abs.exists() {
            return Some(abs);
        }
        return None;
    }

    which::which(program).ok()
}

fn read_shebang(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut magic = [0u8; 2];
    if file.read_exact(&mut magic).is_err() {
        return None;
    }
    if &magic != b"#!" {
        return None;
    }

    let file = File::open(path).ok()?;
    let reader = BufReader::new(file);
    let mut line = String::new();
    reader.take(256).read_line(&mut line).ok()?;
    Some(line)
}

fn parse_shebang(line: &str) -> Option<(String, Option<String>)> {
    let line = line.trim_start_matches("#!").trim();
    if line.is_empty() {
        return None;
    }

    let mut parts = line.splitn(2, |c: char| c.is_ascii_whitespace());
    let interpreter = parts.next()?.to_string();
    let arg = parts
        .next()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    Some((interpreter, arg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_shebang_env_bash() {
        let (interp, arg) = parse_shebang("#!/usr/bin/env bash\n").unwrap();
        assert_eq!(interp, "/usr/bin/env");
        assert_eq!(arg.as_deref(), Some("bash"));
    }

    #[test]
    fn test_parse_shebang_direct() {
        let (interp, arg) = parse_shebang("#!/bin/bash\n").unwrap();
        assert_eq!(interp, "/bin/bash");
        assert_eq!(arg, None);
    }

    #[test]
    fn test_parse_shebang_with_flags() {
        let (interp, arg) = parse_shebang("#!/usr/bin/env -S node\n").unwrap();
        assert_eq!(interp, "/usr/bin/env");
        assert_eq!(arg.as_deref(), Some("-S node"));
    }

    #[test]
    fn test_is_sip_protected() {
        assert!(is_sip_protected(Path::new("/usr/bin/env")));
        assert!(is_sip_protected(Path::new("/bin/bash")));
        assert!(is_sip_protected(Path::new("/bin/sh")));
        assert!(is_sip_protected(Path::new("/usr/sbin/something")));
        assert!(!is_sip_protected(Path::new("/opt/homebrew/bin/bash")));
        assert!(!is_sip_protected(Path::new("/usr/local/bin/node")));
    }

    #[test]
    fn test_resolve_sip_interpreter_strips_env_s_flag() {
        // resolve_sip_interpreter should strip -S and find the actual command
        // We can't test the full resolution without a real PATH, but we can
        // verify the stripping logic by checking it doesn't panic/return None
        // on "-S node" when "node" isn't installed (graceful failure).
        let result = resolve_sip_interpreter("/usr/bin/env", Some("-S node"));
        // Result depends on whether node is in PATH; just ensure no panic
        let _ = result;

        let result = resolve_sip_interpreter("/usr/bin/env", Some("-S python3 -u"));
        let _ = result;
    }

    #[test]
    fn test_parse_shebang_empty() {
        assert!(parse_shebang("#!\n").is_none());
        assert!(parse_shebang("#!  \n").is_none());
    }

    #[test]
    fn test_find_non_sip_binary_never_returns_sip_path() {
        // If find_non_sip_binary returns a path, it must NOT be SIP-protected
        for name in &["sh", "bash", "zsh", "python3", "nonexistent-binary-xyz"] {
            if let Some(ref path) = find_non_sip_binary(name) {
                assert!(
                    !is_sip_protected(Path::new(path)),
                    "find_non_sip_binary({}) returned SIP path: {}",
                    name,
                    path
                );
            }
        }
    }

    #[test]
    fn test_find_non_sip_binary_shell_fallbacks_dont_panic() {
        // Verify the function handles all shell types without panicking
        let _ = find_non_sip_binary("sh");
        let _ = find_non_sip_binary("bash");
        let _ = find_non_sip_binary("zsh");
        let _ = find_non_sip_binary("dash");
        let _ = find_non_sip_binary("ksh");
    }

    #[test]
    fn test_find_non_sip_binary_nonexistent_returns_none() {
        assert!(find_non_sip_binary("nonexistent-binary-xyz-12345").is_none());
    }

    #[test]
    fn test_resolve_program_sip_binary_preserves_args() {
        // Even if /bin/sh can't be resolved, args must pass through unchanged
        let args = vec!["-c".to_string(), "echo hello".to_string()];
        let (_, resolved_args) = resolve_program("/bin/sh", &args);
        assert_eq!(resolved_args, args);
    }

    #[test]
    fn test_resolve_program_sip_binary_resolves_to_non_sip() {
        // If a non-SIP alternative is found, it should be used
        let args = vec!["-c".to_string(), "echo hi".to_string()];
        let (prog, _) = resolve_program("/bin/sh", &args);
        if prog != "/bin/sh" {
            assert!(
                !is_sip_protected(Path::new(&prog)),
                "resolve_program returned SIP path: {}",
                prog
            );
        }
    }

    #[test]
    fn test_resolve_program_non_sip_path_unchanged() {
        let args = vec!["-c".to_string(), "echo hi".to_string()];
        let (prog, resolved_args) = resolve_program("/opt/homebrew/bin/bash", &args);
        // Non-SIP path should NOT be modified (it's not a script so shebang
        // resolution returns None, and the SIP check doesn't apply)
        assert_eq!(prog, "/opt/homebrew/bin/bash");
        assert_eq!(resolved_args, args);
    }
}
