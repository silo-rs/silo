use serde::Serialize;

use super::Checker;

#[derive(Serialize)]
pub struct EnvironmentInfo {
    silo_ip: Option<String>,
    silo_backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ld_preload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dyld_insert_libraries: Option<String>,
    nested_session: bool,
}

pub fn check_environment(ck: &mut Checker) -> EnvironmentInfo {
    let silo_ip = std::env::var("SILO_IP").ok();
    let silo_backend = std::env::var("SILO_BACKEND").ok();
    let nested = silo_ip.is_some();

    if nested {
        ck.warn(
            "session",
            format!(
                "nested silo session detected (SILO_IP={})",
                silo_ip.as_deref().unwrap_or("?")
            ),
        );
    } else {
        ck.ok("session", "not inside a silo session");
    }

    #[cfg(target_os = "macos")]
    let dyld = std::env::var("DYLD_INSERT_LIBRARIES").ok();
    #[cfg(not(target_os = "macos"))]
    let dyld: Option<String> = None;

    #[cfg(target_os = "linux")]
    let ld_preload = std::env::var("LD_PRELOAD").ok();
    #[cfg(not(target_os = "linux"))]
    let ld_preload: Option<String> = None;

    #[cfg(target_os = "macos")]
    if let Some(ref val) = dyld {
        if !val.contains("libsilo_bind") {
            ck.warn(
                "DYLD_INSERT_LIBRARIES",
                format!("already set to: {val} (may conflict with silo)"),
            );
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(ref val) = ld_preload {
        if !val.contains("libsilo_bind") {
            ck.warn(
                "LD_PRELOAD",
                format!("already set to: {val} (may conflict with silo)"),
            );
        }
    }

    EnvironmentInfo {
        silo_ip,
        silo_backend,
        ld_preload,
        dyld_insert_libraries: dyld,
        nested_session: nested,
    }
}
