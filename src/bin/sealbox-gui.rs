//! GUI-only launcher. On Windows it is built for the GUI subsystem, so
//! double-clicking it (or opening a .sbx file associated with it) never
//! flashes a console window. Use the `sealbox` binary for the command line.
#![cfg_attr(windows, windows_subsystem = "windows")]

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let sealbox = std::env::args_os().nth(1).map(PathBuf::from);
    match sealbox::gui::run(sealbox) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // There may be no console to print to, so show a dialog.
            rfd::MessageDialog::new()
                .set_level(rfd::MessageLevel::Error)
                .set_title("Sealbox")
                .set_description(format!("{e:#}"))
                .show();
            ExitCode::FAILURE
        }
    }
}
