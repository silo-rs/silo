use colored::Colorize;

use crate::ui;

pub fn run() -> eyre::Result<()> {
    eprintln!(
        "{} {}",
        ui::accent("silo"),
        "setting up eBPF programs...".dimmed(),
    );

    crate::ebpf::setup_pinned()?;

    eprintln!(
        "  {} {}",
        "✓".green(),
        "eBPF programs pinned to /sys/fs/bpf/silo/".green().bold()
    );
    eprintln!(
        "  {}",
        "Subsequent `silo run` invocations will use eBPF without root.".dimmed()
    );

    Ok(())
}
