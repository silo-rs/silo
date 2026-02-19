use std::net::Ipv4Addr;
use std::path::Path;

#[test]
fn context_new_with_compute_ip() {
    let ip = silo::compute_ip(Path::new("/work/agent"), "task-1");
    let ctx = silo::Context::new("task-1", ip, "/work/agent", "task-1.silo").unwrap();

    assert_eq!(ctx.ip(), ip);
    assert_eq!(ctx.name(), "task-1");

    let vars = ctx.env_vars();
    let silo_ip = vars.iter().find(|(k, _)| *k == "SILO_IP").unwrap();
    assert_eq!(silo_ip.1.as_ref(), ip.to_string());
}

#[test]
fn sanitize_then_compute_then_context() {
    let sanitized = silo::sanitize_name("feature/agent-codegen");
    let ip = silo::compute_ip(Path::new("/tmp/agents"), &sanitized);
    let hostname = format!("{sanitized}.silo");

    let ctx = silo::Context::new(&sanitized, ip, "/tmp/agents", &hostname).unwrap();
    assert_eq!(ctx.name(), "feature-agent-codegen");
    assert_eq!(ctx.hostname(), "feature-agent-codegen.silo");
}

#[test]
fn preload_backend_with_default_path() {
    let backend = silo::PreloadBackend::new(silo::DEFAULT_BIND_LIB_PATH.into());
    assert_eq!(
        backend.lib_path().to_str().unwrap(),
        silo::DEFAULT_BIND_LIB_PATH
    );
}

#[test]
fn noop_backend_prepare_sets_env_vars() {
    let ip = Ipv4Addr::new(127, 10, 20, 30);
    let ctx = silo::Context::new("test", ip, "/tmp/test", "test.silo").unwrap();

    let mut cmd = std::process::Command::new("true");
    for (key, val) in ctx.env_vars() {
        cmd.env(key, val.as_ref());
    }

    let envs: Vec<_> = cmd.get_envs().collect();
    let silo_ip = envs.iter().find(|(k, _)| k == &"SILO_IP").unwrap();
    assert_eq!(silo_ip.1.unwrap().to_str().unwrap(), "127.10.20.30");
}

#[test]
fn multiple_agents_get_unique_ips() {
    let agents = ["codegen", "test-runner", "reviewer", "planner"];
    let ips: Vec<_> = agents
        .iter()
        .map(|id| silo::compute_ip(Path::new("/work"), id))
        .collect();

    for (i, a) in ips.iter().enumerate() {
        for (j, b) in ips.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "agents {} and {} collided", agents[i], agents[j]);
            }
        }
    }
}
