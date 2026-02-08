use std::path::PathBuf;

use eyre::Context;
use colored::Colorize;

use silo_core::config;
use silo_core::error::SiloError;
use silo_core::hooks;
use silo_core::hosts;
use silo_core::ip;
use silo_core::render;
use silo_core::state::Instance;
use silo_core::store::Store;
use crate::ui;
use silo_core::worktree;

pub async fn run(
    store: &Store,
    name: &str,
    path: Option<&str>,
    branch: Option<&str>,
    no_hooks: bool,
    json: bool,
) -> eyre::Result<()> {
    validate_name(name)?;

    let (config, repo_root) = config::load_config()?;

    let use_worktree = path.is_none();

    if store.get(&repo_root, name).await?.is_some() {
        return Err(SiloError::InstanceAlreadyExists(name.to_string()).into());
    }

    let instance_path = if use_worktree {
        let p = worktree::create_worktree(&repo_root, name, &config.worktree.base_dir, branch)?;
        if !json {
            ui::success("Worktree created");
        }
        p
    } else {
        let p = PathBuf::from(path.unwrap());
        let p = if p.is_absolute() {
            p
        } else {
            std::env::current_dir()?.join(p)
        };
        let p = p.canonicalize().unwrap_or(p);

        if let Some(existing) = store.find_by_path(&p).await? {
            if existing.path == p {
                eyre::bail!("another instance already uses path {}", p.display());
            }
        }
        p
    };

    let used = store.used_ips().await?;
    let assigned_ip = ip::allocate_ip(&config.instance.ip_range, &used)?;

    let instance = Instance::builder()
        .name(name.to_string())
        .ip(assigned_ip)
        .path(instance_path)
        .repo(repo_root.clone())
        .is_worktree(use_worktree)
        .build();

    store.insert(&instance).await?;

    if let Err(e) = ip::add_alias(instance.ip) {
        let mut rollback_failed = false;

        if let Err(rb_err) = store.remove(&repo_root, name).await {
            ui::warn(format!("rollback failed (state): {rb_err}"));
            rollback_failed = true;
        }

        if instance.is_worktree {
            if let Err(rb_err) = worktree::remove_worktree(&repo_root, &instance.path) {
                ui::warn(format!("rollback failed (worktree): {rb_err}"));
                rollback_failed = true;
            }
        }

        if rollback_failed {
            ui::hint(format!("run {} to clean up", ui::accent("silo prune").bold()));
        }

        return Err(e).context("failed to create IP alias");
    }
    if !json {
        ui::success(format!("IP {} assigned", instance.ip));
    }

    let host = hosts::hostname(&instance.name, &instance.repo);
    if let Err(e) = hosts::add_entry(instance.ip, &host) {
        ui::warn(format!("failed to add hosts entry: {e}"));
    } else if !json {
        ui::success(format!("Host mapped → {host}"));
    }

    if instance.is_worktree {
        let copied = render::copy_files(&repo_root, &instance.path, &config.worktree.copy)?;
        if !json && copied > 0 {
            ui::success("Files copied");
        }

        let applied = render::apply_silo_env(&instance.path, &instance.env_vars())?;
        if !json && applied > 0 {
            ui::success("Overrides applied");
        }
    }

    if !no_hooks && !config.hooks.setup.is_empty() {
        hooks::run_hooks(
            &config.hooks.setup,
            &instance.path,
            &instance.env_vars(),
            "setup",
        )?;
        if !json {
            ui::success("Hooks completed");
        }
    }

    if json {
        println!("{}", serde_json::to_string(&instance)?);
    } else {
        eprintln!();
        eprintln!("  {}", ui::accent(name).bold());
        eprintln!("  ip     {}", instance.ip.to_string().dimmed());
        eprintln!("  host   {}", host.dimmed());
        eprintln!("  path   {}", instance.path.display().to_string().dimmed());
        eprintln!();
        ui::hint(format!(
            "run {} to jump there",
            ui::accent(&format!("silo cd {name}")).bold()
        ));
    }

    Ok(())
}

pub(crate) fn validate_name(name: &str) -> Result<(), SiloError> {
    if name.is_empty() {
        return Err(SiloError::InvalidInstanceName(name.to_string(), "must not be empty"));
    }

    if name.len() > 64 {
        return Err(SiloError::InvalidInstanceName(name.to_string(), "must be 64 characters or fewer"));
    }

    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Err(SiloError::InvalidInstanceName(
            name.to_string(),
            "must start with a letter or digit",
        ));
    }

    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(SiloError::InvalidInstanceName(
            name.to_string(),
            "may only contain letters, digits, hyphens, and underscores",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        assert!(validate_name("api").is_ok());
        assert!(validate_name("my-app").is_ok());
        assert!(validate_name("web_server").is_ok());
        assert!(validate_name("v2").is_ok());
        assert!(validate_name("a").is_ok());
        assert!(validate_name("ABC").is_ok());
        assert!(validate_name("test-123_foo").is_ok());
    }

    #[test]
    fn empty_name() {
        assert!(validate_name("").is_err());
    }

    #[test]
    fn too_long() {
        let long = "a".repeat(65);
        assert!(validate_name(&long).is_err());
        let exactly_64 = "a".repeat(64);
        assert!(validate_name(&exactly_64).is_ok());
    }

    #[test]
    fn starts_with_hyphen() {
        assert!(validate_name("-api").is_err());
    }

    #[test]
    fn starts_with_underscore() {
        assert!(validate_name("_api").is_err());
    }

    #[test]
    fn contains_colon() {
        assert!(validate_name("my:app").is_err());
    }

    #[test]
    fn contains_slash() {
        assert!(validate_name("my/app").is_err());
    }

    #[test]
    fn contains_space() {
        assert!(validate_name("my app").is_err());
    }

    #[test]
    fn contains_dot() {
        assert!(validate_name("my.app").is_err());
    }
}
