//! The Vault: encrypt files and folders into a single password-protected
//! `.vault` file, from a GUI or the command line.

pub mod archive;
pub mod cli;
pub mod crypto;
pub mod gui;

/// Minimum password length accepted when creating a new vault.
pub const MIN_PASSWORD_LEN: usize = 8;

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}
