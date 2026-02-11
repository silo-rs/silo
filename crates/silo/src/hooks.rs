use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Stdio};

use colored::Colorize;
use eyre::Context;
use tracing::{debug, instrument, warn};

use crate::error::SiloError;

#[instrument(skip(hooks, env_vars), fields(hook_count = hooks.len()))]
pub fn run_hooks(
    hooks: &[String],
    working_dir: &Path,
    env_vars: &HashMap<String, String>,
    label: &str,
) -> eyre::Result<()> {
    if hooks.is_empty() {
        debug!("no hooks configured");
        return Ok(());
    }

    eprintln!("  {} running {} hooks...", "→".dimmed(), label.bold());

    for (i, cmd) in hooks.iter().enumerate() {
        eprintln!("  hook [{}/{}] {}", i + 1, hooks.len(), cmd);
        debug!(hook = cmd, index = i + 1, "executing hook");

        let status = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .current_dir(working_dir)
            .envs(env_vars)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| format!("executing hook: {}", cmd))?;

        if !status.success() {
            let code = status.code().unwrap_or(-1);
            warn!(hook = cmd, exit_code = code, "hook failed");
            return Err(SiloError::HookFailed(cmd.clone(), code).into());
        }
    }

    Ok(())
}
