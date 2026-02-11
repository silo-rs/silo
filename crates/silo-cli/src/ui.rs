use colored::{ColoredString, Colorize};
use std::fmt::Display;

pub fn accent(text: &str) -> ColoredString {
    text.cyan()
}

pub fn success(msg: impl Display) {
    eprintln!("  {} {msg}", "✓".green());
}

pub fn warn(msg: impl Display) {
    eprintln!("  {} {msg}", "⚠".yellow());
}

pub fn info(msg: impl Display) {
    eprintln!("  {} {msg}", "○".dimmed());
}

pub fn hint(msg: impl Display) {
    eprintln!("  {}", format!("hint: {msg}").dimmed());
}

pub fn check_ok(label: &str, detail: impl Display) {
    eprintln!("  {} {}: {detail}", "✓".green(), label.bold());
}

pub fn check_warn(label: &str, detail: impl Display) {
    eprintln!("  {} {}: {detail}", "⚠".yellow(), label.bold());
}

pub fn check_error(label: &str, detail: impl Display) {
    eprintln!("  {} {}: {detail}", "✗".red(), label.bold());
}

pub fn check_info(label: &str, detail: impl Display) {
    eprintln!("  {} {}: {detail}", "○".dimmed(), label.bold());
}
