use std::process::ExitCode;

use clap::Parser;
use sealbox::cli::{self, Cli};

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().collect();

    // `sealbox` with no arguments, or `sealbox some.sbx` (e.g. double-clicking a
    // .sbx file associated with the app), opens the GUI.
    let gui_target = match args.len() {
        1 => Some(None),
        2 if sealbox::is_sealbox_path(args[1].as_ref()) => Some(Some(args[1].clone().into())),
        _ => None,
    };
    let result = match gui_target {
        Some(sealbox) => {
            detach_console_if_owned();
            sealbox::gui::run(sealbox)
        }
        None => match Cli::parse().cmd {
            Some(cmd) => cli::run(cmd),
            None => sealbox::gui::run(None),
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// On Windows the binary is a console program so the CLI works normally. When
/// it is started by double-clicking, Windows opens a console window just for
/// it; hide that window when the GUI starts.
#[cfg(windows)]
fn detach_console_if_owned() {
    use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
    let mut pids = [0u32; 2];
    // Only this process attached → the console was created for us.
    if unsafe { GetConsoleProcessList(pids.as_mut_ptr(), 2) } == 1 {
        unsafe { FreeConsole() };
    }
}

#[cfg(not(windows))]
fn detach_console_if_owned() {}
