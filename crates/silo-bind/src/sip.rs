use std::env;
use std::ffi::{CStr, CString};

pub fn is_sip_path(path: &str) -> bool {
    path.starts_with("/usr/bin/")
        || path.starts_with("/bin/")
        || path.starts_with("/sbin/")
        || path.starts_with("/usr/sbin/")
}

pub fn find_non_sip_in_path(name: &str) -> Option<CString> {
    let fallbacks: &[&str] = match name {
        "sh" | "bash" | "zsh" | "dash" | "ksh" => &["bash", "zsh", "sh"],
        "make" => &["make", "gmake"],
        _ => &[],
    };
    let names = if fallbacks.is_empty() {
        std::slice::from_ref(&name)
    } else {
        fallbacks
    };

    let path_var = env::var("PATH").ok()?;
    for try_name in names {
        for dir in path_var.split(':') {
            if dir.is_empty() {
                continue;
            }
            if dir.starts_with("/usr/bin/")
                || dir == "/usr/bin"
                || dir.starts_with("/bin/")
                || dir == "/bin"
                || dir.starts_with("/sbin/")
                || dir == "/sbin"
                || dir.starts_with("/usr/sbin/")
                || dir == "/usr/sbin"
            {
                continue;
            }
            let candidate = format!("{}/{}", dir, try_name);
            if let Ok(c) = CString::new(candidate)
                && unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0
            {
                return Some(c);
            }
        }
    }
    None
}

pub unsafe fn read_shebang_of(path: *const libc::c_char) -> Option<(String, Option<String>)> {
    let fd = unsafe { libc::open(path, libc::O_RDONLY) };
    if fd < 0 {
        return None;
    }

    let mut buf = [0u8; 256];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    unsafe { libc::close(fd) };

    if n < 4 {
        return None;
    }
    let n = n as usize;
    if buf[0] != b'#' || buf[1] != b'!' {
        return None;
    }

    let end = buf[2..n]
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| p + 2)
        .unwrap_or(n);
    let line = std::str::from_utf8(&buf[2..end]).ok()?.trim();
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

pub unsafe fn resolve_sip_exec(
    path: *const libc::c_char,
    argv: *const *const libc::c_char,
) -> Option<(CString, Vec<CString>, Vec<*const libc::c_char>)> {
    if path.is_null() {
        return None;
    }

    let path_str = unsafe { CStr::from_ptr(path) }.to_str().ok()?;

    if is_sip_path(path_str) {
        let basename = path_str.rsplit('/').next()?;
        let resolved = find_non_sip_in_path(basename)?;
        return Some((resolved, Vec::new(), Vec::new()));
    }

    let (interpreter, arg) = (unsafe { read_shebang_of(path) })?;
    if !is_sip_path(&interpreter) {
        return None;
    }

    let is_env = interpreter.ends_with("/env");
    let resolved = if is_env {
        let cmd = arg.as_deref()?;
        let stripped = cmd
            .strip_prefix("-S")
            .map(|s| s.trim_start())
            .unwrap_or(cmd);
        let actual = stripped.split_whitespace().next()?;
        find_non_sip_in_path(actual)?
    } else {
        find_non_sip_in_path(interpreter.rsplit('/').next()?)?
    };

    let mut owned: Vec<CString> = Vec::new();
    let mut ptrs: Vec<*const libc::c_char> = Vec::new();

    ptrs.push(resolved.as_ptr());

    if !is_env
        && let Some(ref a) = arg
        && let Ok(c) = CString::new(a.as_bytes())
    {
        ptrs.push(c.as_ptr());
        owned.push(c);
    }

    ptrs.push(path);

    if !argv.is_null() {
        unsafe {
            let mut p = argv.offset(1);
            while !(*p).is_null() {
                ptrs.push(*p);
                p = p.offset(1);
            }
        }
    }
    ptrs.push(std::ptr::null());

    Some((resolved, owned, ptrs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_shebang_of_normal() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("test.sh");
        std::fs::write(&script, "#!/bin/bash\necho hello\n").unwrap();
        let cpath = CString::new(script.to_str().unwrap()).unwrap();
        let result = unsafe { read_shebang_of(cpath.as_ptr()) };
        let (interp, arg) = result.unwrap();
        assert_eq!(interp, "/bin/bash");
        assert!(arg.is_none());
    }

    #[test]
    fn read_shebang_of_with_arg() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("test.sh");
        std::fs::write(&script, "#!/usr/bin/env bash\necho hello\n").unwrap();
        let cpath = CString::new(script.to_str().unwrap()).unwrap();
        let result = unsafe { read_shebang_of(cpath.as_ptr()) };
        let (interp, arg) = result.unwrap();
        assert_eq!(interp, "/usr/bin/env");
        assert_eq!(arg.as_deref(), Some("bash"));
    }

    #[test]
    fn read_shebang_of_with_env_s_flag() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("test.py");
        std::fs::write(&script, "#!/usr/bin/env -S python3 -u\nimport sys\n").unwrap();
        let cpath = CString::new(script.to_str().unwrap()).unwrap();
        let result = unsafe { read_shebang_of(cpath.as_ptr()) };
        let (interp, arg) = result.unwrap();
        assert_eq!(interp, "/usr/bin/env");
        assert_eq!(arg.as_deref(), Some("-S python3 -u"));
    }

    #[test]
    fn read_shebang_of_binary_file() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("binary");
        std::fs::write(&bin, [0x7f, 0x45, 0x4c, 0x46, 0x00, 0x00]).unwrap();
        let cpath = CString::new(bin.to_str().unwrap()).unwrap();
        let result = unsafe { read_shebang_of(cpath.as_ptr()) };
        assert!(result.is_none());
    }

    #[test]
    fn read_shebang_of_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        std::fs::write(&empty, "").unwrap();
        let cpath = CString::new(empty.to_str().unwrap()).unwrap();
        let result = unsafe { read_shebang_of(cpath.as_ptr()) };
        assert!(result.is_none());
    }

    #[test]
    fn read_shebang_of_empty_shebang() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("test.sh");
        std::fs::write(&script, "#!\n").unwrap();
        let cpath = CString::new(script.to_str().unwrap()).unwrap();
        let result = unsafe { read_shebang_of(cpath.as_ptr()) };
        assert!(result.is_none());
    }

    #[test]
    fn read_shebang_of_nonexistent() {
        let cpath = CString::new("/tmp/nonexistent-silo-test-file-12345").unwrap();
        let result = unsafe { read_shebang_of(cpath.as_ptr()) };
        assert!(result.is_none());
    }

    #[test]
    fn is_sip_path_known_dirs() {
        assert!(is_sip_path("/usr/bin/env"));
        assert!(is_sip_path("/usr/bin/bash"));
        assert!(is_sip_path("/bin/sh"));
        assert!(is_sip_path("/bin/bash"));
        assert!(is_sip_path("/sbin/mount"));
        assert!(is_sip_path("/usr/sbin/something"));
    }

    #[test]
    fn is_sip_path_non_sip() {
        assert!(!is_sip_path("/opt/homebrew/bin/bash"));
        assert!(!is_sip_path("/usr/local/bin/node"));
        assert!(!is_sip_path("/nix/store/xyz/bin/bash"));
        assert!(!is_sip_path("/home/user/bin/script"));
    }

    #[test]
    fn find_non_sip_in_path_shell_coverage() {
        for name in &["sh", "bash", "zsh", "dash", "ksh"] {
            let result = find_non_sip_in_path(name);
            if let Some(ref path) = result {
                let path_str = path.to_str().unwrap();
                assert!(
                    !is_sip_path(path_str),
                    "find_non_sip_in_path({name}) returned SIP path: {path_str}"
                );
            }
        }
    }

    #[test]
    fn find_non_sip_in_path_make() {
        let result = find_non_sip_in_path("make");
        if let Some(ref path) = result {
            let path_str = path.to_str().unwrap();
            assert!(
                !is_sip_path(path_str),
                "find_non_sip_in_path(\"make\") returned SIP path: {path_str}"
            );
        }
    }

    #[test]
    fn find_non_sip_in_path_nonexistent() {
        assert!(find_non_sip_in_path("nonexistent-binary-xyz-12345").is_none());
    }

    #[test]
    fn find_non_sip_in_path_never_returns_sip() {
        for name in &["sh", "bash", "zsh", "make", "python3"] {
            if let Some(ref path) = find_non_sip_in_path(name) {
                let path_str = path.to_str().unwrap();
                assert!(
                    !is_sip_path(path_str),
                    "find_non_sip_in_path({name}) returned SIP path: {path_str}"
                );
            }
        }
    }
}
