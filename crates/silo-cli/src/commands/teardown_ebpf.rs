use colored::Colorize;

use crate::ui;

pub fn run() -> eyre::Result<()> {
    eprintln!(
        "{} {}",
        ui::accent("silo"),
        "removing pinned eBPF programs...".dimmed(),
    );

    crate::ebpf::teardown_pinned()?;

    eprintln!(
        "  {} {}",
        "✓".green(),
        "pinned eBPF programs removed from /sys/fs/bpf/silo/".green().bold()
    );

    Ok(())
}
