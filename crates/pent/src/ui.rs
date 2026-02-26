/// User-facing output helpers.
///
/// All output goes to stderr so stdout stays clean for piped data
/// (e.g. `pent config show | jq`).  The `console` crate automatically
/// strips ANSI codes when the output is not a terminal.
use console::style;

/// `✓ <msg>` in bold green — a step completed successfully.
pub fn ok(msg: impl std::fmt::Display) {
    eprintln!("{} {msg}", style("✓").green().bold());
}

/// `✗ <msg>` in bold red — a step that failed.
pub fn error(msg: impl std::fmt::Display) {
    eprintln!("{} {msg}", style("✗").red().bold());
}

/// `▲ <msg>` in bold yellow — a non-fatal warning.
pub fn warn(msg: impl std::fmt::Display) {
    eprintln!("{} {msg}", style("▲").yellow().bold());
}

/// Indented `  <label>  <value>` — a key/value status line.
pub fn status(label: &str, value: impl std::fmt::Display) {
    eprintln!("  {:<10} {value}", style(label).dim());
}
