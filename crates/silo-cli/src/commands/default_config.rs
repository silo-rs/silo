pub fn run() -> eyre::Result<()> {
    print!(
        r#"[instance]
# IP range in CIDR notation (must be in 127.0.0.0/8 loopback range)
ip_range = "127.0.1.0/24"

[hooks]
# Commands to run after creating an instance
# setup = ["npm install"]
# Commands to run before each `silo exec` / `silo run`
# enter = []
# Commands to run before destroying an instance
# teardown = []

[worktree]
# Base directory for git worktrees (relative to repo root)
# base_dir = "../"
# Files to symlink from the main repo into worktrees (glob patterns)
# link = [".env", ".env.local"]
"#
    );

    Ok(())
}
