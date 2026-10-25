//! A helper for the tests: it prints the pent directories.
//!
//! The functions [`pent_settings::PentDirs::from_env`] and
//! [`pent_settings::TrustStore::default_path`] read the environment of the
//! process. A test must not change the environment of the test process,
//! because that races the other tests. The test runs this program instead,
//! with the environment that it wants.
//!
//! The program prints three lines, and each value is a path or the word
//! `none`:
//!
//! ```text
//! config=/home/u/.config/pent
//! state=/home/u/.local/state/pent
//! trust=/home/u/.config/pent/trusted.toml
//! ```

use pent_settings::{PentDirs, TrustStore};

fn main() {
    let dirs = PentDirs::from_env();
    println!("config={}", show(dirs.as_ref().map(|d| d.config.clone())));
    println!("state={}", show(dirs.as_ref().map(|d| d.state.clone())));
    println!("trust={}", show(TrustStore::default_path()));
}

/// The path as text, or `none`.
fn show(path: Option<std::path::PathBuf>) -> String {
    path.map_or_else(|| "none".to_string(), |p| p.display().to_string())
}
