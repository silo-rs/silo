use std::process::Command;

use colored::Colorize;
use eyre::Context;

use crate::ui;
use silo::config;
use silo::error::SiloError;

pub fn run(ip_range: &str) -> eyre::Result<()> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;

    let status = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(&cwd)
        .output()
        .context("failed to run git")?;

    if !status.status.success() {
        return Err(SiloError::NotGitRepo.into());
    }

    let config_path = cwd.join("silo.toml");
    if config_path.exists() {
        return Err(SiloError::ConfigAlreadyExists(config_path).into());
    }

    validate_ip_range(ip_range)?;

    let project = config::detect_project_type(&cwd);
    let content = config::generate_for_project(ip_range, &project);
    std::fs::write(&config_path, content)
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    ui::success(format!(
        "Initialized {} in {}",
        ui::accent("silo"),
        cwd.display()
    ));
    match project {
        config::ProjectType::Unknown => {}
        ref p => {
            let label = match p {
                config::ProjectType::Node => "node",
                config::ProjectType::Python => "python",
                config::ProjectType::Ruby => "ruby",
                config::ProjectType::Go => "go",
                config::ProjectType::Rust => "rust",
                config::ProjectType::Unknown => unreachable!(),
            };
            ui::info(format!(
                "detected {} project — config tailored",
                ui::accent(label)
            ));
        }
    }
    eprintln!("  config  {}", config_path.display().to_string().dimmed());
    eprintln!();
    ui::hint(format!(
        "run {} to create your first instance",
        ui::accent("silo add <name>").bold()
    ));

    Ok(())
}

fn validate_ip_range(range: &str) -> eyre::Result<()> {
    let network: ipnet::Ipv4Net = range.parse().map_err(|e: ipnet::AddrParseError| {
        SiloError::InvalidCidrRange(range.to_string(), e.to_string())
    })?;

    if network.network().octets()[0] != 127 {
        return Err(SiloError::IpNotLoopback(network.network()).into());
    }

    Ok(())
}
