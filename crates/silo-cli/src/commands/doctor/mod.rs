mod environment;
mod git;
mod helpers;
mod hosts;
mod network;
mod platform;
mod shell;

use colored::Colorize;
use serde::Serialize;

use crate::ui;

#[derive(Serialize)]
struct DoctorReport {
    version: String,
    checks: Vec<Check>,
    errors: usize,
    warnings: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    shell: Option<shell::ShellInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<environment::EnvironmentInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<network::NetworkInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    worktrees: Option<git::WorktreeInfo>,
}

#[derive(Serialize)]
pub struct Check {
    name: String,
    status: CheckStatus,
    detail: String,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum CheckStatus {
    Ok,
    Warn,
    Error,
    Info,
}

pub struct Checker {
    checks: Vec<Check>,
    warnings: usize,
    errors: usize,
}

impl Checker {
    const fn new() -> Self {
        Self {
            checks: Vec::new(),
            warnings: 0,
            errors: 0,
        }
    }

    pub fn ok(&mut self, name: impl Into<String>, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            status: CheckStatus::Ok,
            detail: detail.into(),
        });
    }

    pub fn warn(&mut self, name: impl Into<String>, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            status: CheckStatus::Warn,
            detail: detail.into(),
        });
        self.warnings += 1;
    }

    pub fn error(&mut self, name: impl Into<String>, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            status: CheckStatus::Error,
            detail: detail.into(),
        });
        self.errors += 1;
    }

    pub fn info(&mut self, name: impl Into<String>, detail: impl Into<String>) {
        self.checks.push(Check {
            name: name.into(),
            status: CheckStatus::Info,
            detail: detail.into(),
        });
    }
}

pub fn run(json: bool) -> eyre::Result<()> {
    let mut ck = Checker::new();

    ck.ok("silo", format!("v{}", env!("CARGO_PKG_VERSION")));

    platform::check_os(&mut ck);
    let shell_info = shell::check_shell(&mut ck);
    let env_info = environment::check_environment(&mut ck);
    git::check_git(&mut ck);
    let worktree_info = git::check_worktrees(&mut ck);
    helpers::check_sudoers(&mut ck);
    helpers::check_helpers(&mut ck);
    let bind_lib = helpers::check_bind_lib(&mut ck);
    helpers::check_injection(&mut ck, bind_lib.as_deref());
    let network_info = network::check_loopback(&mut ck);
    #[cfg(target_os = "linux")]
    platform::check_ebpf(&mut ck);
    hosts::check_hosts_entries(&mut ck);
    hosts::check_stale_hosts(&mut ck);

    if json {
        let report = DoctorReport {
            version: env!("CARGO_PKG_VERSION").to_string(),
            checks: ck.checks,
            errors: ck.errors,
            warnings: ck.warnings,
            shell: shell_info,
            environment: Some(env_info),
            network: Some(network_info),
            worktrees: worktree_info,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        eprintln!();
        eprintln!(
            "  {}",
            "Please include the above JSON output with bug reports.".dimmed()
        );
        if report.errors > 0 {
            std::process::exit(1);
        }
    } else {
        for check in &ck.checks {
            match check.status {
                CheckStatus::Ok => ui::check_ok(&check.name, &check.detail),
                CheckStatus::Warn => ui::check_warn(&check.name, &check.detail),
                CheckStatus::Error => ui::check_error(&check.name, &check.detail),
                CheckStatus::Info => ui::check_info(&check.name, &check.detail),
            }
        }

        eprintln!();
        if ck.errors > 0 {
            eprintln!(
                "  {} {}",
                "✗".red(),
                format!("{} error(s), {} warning(s)", ck.errors, ck.warnings)
                    .red()
                    .bold()
            );
            eprintln!();
            eprintln!(
                "  {}",
                "Run `silo doctor --json` and include the output with bug reports.".dimmed()
            );
            std::process::exit(1);
        } else if ck.warnings > 0 {
            eprintln!(
                "  {} {}",
                "⚠".yellow(),
                format!("no errors, {} warning(s)", ck.warnings)
                    .yellow()
                    .bold()
            );
        } else {
            eprintln!("  {} {}", "✓".green(), "all checks passed".green().bold());
        }
    }

    Ok(())
}
