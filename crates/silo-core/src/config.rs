use std::path::{Path, PathBuf};

use std::env;

use eyre::Context;
use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use crate::error::SiloError;

#[derive(Debug, Serialize, Deserialize)]
pub struct SiloConfig {
    pub instance: InstanceConfig,
    #[serde(default)]
    pub hooks: HooksConfig,
    #[serde(default)]
    pub worktree: WorktreeConfig,
    #[serde(default)]
    pub run: RunConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstanceConfig {
    pub ip_range: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HooksConfig {
    #[serde(default)]
    pub setup: Vec<String>,
    #[serde(default)]
    pub enter: Vec<String>,
    #[serde(default)]
    pub teardown: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorktreeConfig {
    #[serde(default = "default_base_dir")]
    pub base_dir: String,
    #[serde(default = "default_copy")]
    pub copy: Vec<String>,
}

use std::collections::HashMap;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RunConfig {
    #[serde(flatten)]
    pub commands: HashMap<String, String>,
}

fn default_base_dir() -> String {
    "../".to_string()
}

fn default_copy() -> Vec<String> {
    vec!["**/.env*".to_string()]
}

impl Default for WorktreeConfig {
    fn default() -> Self {
        Self {
            base_dir: default_base_dir(),
            copy: default_copy(),
        }
    }
}

pub fn load_config() -> eyre::Result<(SiloConfig, PathBuf)> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let config_path = find_config(&cwd)?;
    let repo_root = config_path
        .parent()
        .expect("config path must have parent")
        .to_path_buf();
    debug!(path = %config_path.display(), "loading config");
    let content =
        std::fs::read_to_string(&config_path).context("failed to read silo.toml")?;
    let mut config: SiloConfig =
        toml::from_str(&content).context("failed to parse silo.toml")?;
    apply_env_overrides(&mut config);
    debug!(ip_range = %config.instance.ip_range, "config loaded");
    Ok((config, repo_root))
}

#[instrument(fields(start = %start.display()))]
fn find_config(start: &Path) -> eyre::Result<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join("silo.toml");
        debug!(candidate = %candidate.display(), "searching for config");
        if candidate.exists() {
            return Ok(candidate);
        }
        if !dir.pop() {
            return Err(SiloError::ConfigNotFound(start.to_path_buf()).into());
        }
    }
}

pub fn load_config_from(repo_root: &Path) -> eyre::Result<Option<SiloConfig>> {
    let config_path = repo_root.join("silo.toml");
    if !config_path.exists() {
        return Ok(None);
    }
    let content =
        std::fs::read_to_string(&config_path).context("failed to read silo.toml")?;
    let mut config: SiloConfig =
        toml::from_str(&content).context("failed to parse silo.toml")?;
    apply_env_overrides(&mut config);
    Ok(Some(config))
}

fn apply_env_overrides(config: &mut SiloConfig) {
    if let Ok(val) = env::var("SILO_IP_RANGE") {
        debug!(ip_range = %val, "overriding ip_range from SILO_IP_RANGE");
        config.instance.ip_range = val;
    }
    if let Ok(val) = env::var("SILO_WORKTREE_BASE_DIR") {
        debug!(base_dir = %val, "overriding base_dir from SILO_WORKTREE_BASE_DIR");
        config.worktree.base_dir = val;
    }
}

/// Detected project type for generating tailored silo.toml defaults.
pub enum ProjectType {
    Node,
    Python,
    Ruby,
    Go,
    Rust,
    Unknown,
}

/// Detect the project type from files in the given directory.
pub fn detect_project_type(dir: &Path) -> ProjectType {
    if dir.join("package.json").exists() {
        ProjectType::Node
    } else if dir.join("requirements.txt").exists()
        || dir.join("pyproject.toml").exists()
        || dir.join("setup.py").exists()
    {
        ProjectType::Python
    } else if dir.join("Gemfile").exists() {
        ProjectType::Ruby
    } else if dir.join("go.mod").exists() {
        ProjectType::Go
    } else if dir.join("Cargo.toml").exists() {
        ProjectType::Rust
    } else {
        ProjectType::Unknown
    }
}

pub fn generate_default(ip_range: &str) -> String {
    generate_for_project(ip_range, &ProjectType::Unknown)
}

pub fn generate_for_project(ip_range: &str, project: &ProjectType) -> String {
    let (hooks_section, run_section) = match project {
        ProjectType::Node => {
            let has_pnpm = std::path::Path::new("pnpm-lock.yaml").exists();
            let has_yarn = std::path::Path::new("yarn.lock").exists();
            let pm = if has_pnpm { "pnpm" } else if has_yarn { "yarn" } else { "npm" };
            (
                format!(r#"setup = ["{pm} install"]"#),
                format!(
                    r#"dev = "{pm} run dev"
# test = "{pm} test""#
                ),
            )
        }
        ProjectType::Python => (
            r#"setup = ["pip install -r requirements.txt"]"#.to_string(),
            r#"# dev = "python manage.py runserver"
# test = "pytest""#
                .to_string(),
        ),
        ProjectType::Ruby => (
            r#"setup = ["bundle install"]"#.to_string(),
            r#"# dev = "rails server"
# test = "bundle exec rspec""#
                .to_string(),
        ),
        ProjectType::Go => (
            r#"# setup = ["go mod download"]"#.to_string(),
            r#"# dev = "go run ."
# test = "go test ./...""#
                .to_string(),
        ),
        ProjectType::Rust => (
            r#"# setup = ["cargo build"]"#.to_string(),
            r#"# dev = "cargo run"
# test = "cargo test""#
                .to_string(),
        ),
        ProjectType::Unknown => (
            r#"# Commands to run after creating an instance
# setup = ["npm install"]"#
                .to_string(),
            r#"# Named commands for `silo run <name>` (receives bind() interception + SILO_* env vars)
# dev = "npm run dev"
# test = "npm test""#
                .to_string(),
        ),
    };

    format!(
        r#"[instance]
ip_range = "{ip_range}"

[hooks]
{hooks_section}
# Commands to run before each `silo exec` / `silo run`
# enter = []
# Commands to run before destroying an instance
# teardown = []

[worktree]
# Base directory for git worktrees (relative to repo root)
# base_dir = "../"
# .env* files are copied automatically (override with: copy = [".env"])

[run]
{run_section}
"#
    )
}
