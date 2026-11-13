use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::archive::{self, EntryKind, Progress, Summary};
use crate::crypto::SealParams;
use crate::{human_size, password_strength};

const AFTER_HELP: &str = "\
Examples:
  sealbox seal -o backup.sbx ~/Documents notes.txt     Seal files/folders (asks password twice)
  sealbox seal -l 19 -f -o backup.sbx ~/Documents      Max compression (-l 1-19), overwrite (-f)
  sealbox list backup.sbx                              Show contents and sizes
  sealbox unseal backup.sbx -o ./restored              Unseal everything into ./restored
  sealbox unseal backup.sbx Documents/taxes            Unseal only some paths
  sealbox unseal backup.sbx --overwrite                Replace existing files
  sealbox add backup.sbx receipts/                     Add to an existing sealbox
  sealbox verify backup.sbx                            Check integrity, write nothing
  sealbox gui backup.sbx                               Open a sealbox in the GUI

Password:
  Read from (in order) --password-stdin, the SEALBOX_PASSWORD environment
  variable, or an interactive prompt. New sealboxes need a strong password.

Run without arguments to open the graphical interface.
Run 'sealbox <COMMAND> --help' for all options of a command.
Press Ctrl+C to cancel a running job safely: nothing half-written is left behind.";

#[derive(Parser)]
#[command(
    name = "sealbox",
    version,
    about = "Encrypt files and folders into a single password-protected .sbx file.",
    after_help = AFTER_HELP
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

fn compression_level() -> clap::builder::RangedI64ValueParser<i32> {
    clap::value_parser!(i32).range(1..=19)
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Seal files and folders into a new encrypted .sbx file
    #[command(visible_alias = "create")]
    Seal {
        /// Output sealbox file (".sbx" is appended if missing)
        #[arg(short, long)]
        output: PathBuf,
        /// Files and folders to put in the sealbox
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        /// Overwrite the output file if it already exists
        #[arg(short, long)]
        force: bool,
        /// Compression level: 1 (fastest) to 19 (smallest)
        #[arg(short, long, default_value_t = archive::DEFAULT_COMPRESSION_LEVEL,
              value_parser = compression_level())]
        level: i32,
        /// Read the password from the first line of standard input
        #[arg(long)]
        password_stdin: bool,
    },
    /// Decrypt a .sbx file and restore all or some of its contents
    #[command(visible_alias = "extract")]
    Unseal {
        /// Sealbox file to unseal
        sealbox: PathBuf,
        /// Only unseal these paths (files or folders, as shown by `list`)
        paths: Vec<String>,
        /// Destination folder (created if needed)
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
        /// Replace files that already exist in the destination
        #[arg(long)]
        overwrite: bool,
        /// Read the password from the first line of standard input
        #[arg(long)]
        password_stdin: bool,
    },
    /// Add files and folders to an existing .sbx file (same password)
    Add {
        /// Sealbox file to add to
        sealbox: PathBuf,
        /// Files and folders to add
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        /// Compression level: 1 (fastest) to 19 (smallest)
        #[arg(short, long, default_value_t = archive::DEFAULT_COMPRESSION_LEVEL,
              value_parser = compression_level())]
        level: i32,
        /// Read the password from the first line of standard input
        #[arg(long)]
        password_stdin: bool,
    },
    /// Show what is inside a .sbx file (requires the password)
    List {
        /// Sealbox file to inspect
        sealbox: PathBuf,
        /// Read the password from the first line of standard input
        #[arg(long)]
        password_stdin: bool,
    },
    /// Check that a .sbx file is complete and untampered, without unsealing it
    Verify {
        /// Sealbox file to check
        sealbox: PathBuf,
        /// Read the password from the first line of standard input
        #[arg(long)]
        password_stdin: bool,
    },
    /// Open the graphical interface
    Gui {
        /// Sealbox file to open right away
        sealbox: Option<PathBuf>,
    },
}

/// Get the password. For a new sealbox (`new = true`) an interactive prompt
/// asks twice, and the password must pass the strength policy.
fn get_password(from_stdin: bool, new: bool) -> Result<Zeroizing<String>> {
    let interactive = !from_stdin && std::env::var_os("SEALBOX_PASSWORD").is_none();
    let pw = if from_stdin {
        let mut line = Zeroizing::new(String::new());
        io::stdin().lock().read_line(&mut line)?;
        Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_owned())
    } else if !interactive {
        Zeroizing::new(std::env::var("SEALBOX_PASSWORD")?)
    } else {
        Zeroizing::new(rpassword::prompt_password("Password: ")?)
    };
    if pw.is_empty() {
        bail!("password must not be empty");
    }
    if new {
        // Check strength before asking for confirmation, so a weak password
        // is not typed twice for nothing.
        let strength = password_strength(&pw);
        if !strength.acceptable {
            bail!("password rejected. {}", strength.message);
        }
        if interactive {
            let again = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
            if *pw != *again {
                bail!("passwords do not match");
            }
        }
    }
    Ok(pw)
}

/// Run `job` while drawing a progress line on stderr (when it is a terminal).
/// Ctrl+C cancels the job cleanly instead of killing the process mid-write.
fn with_progress<T>(label: &str, job: impl FnOnce(&Progress) -> T) -> T {
    let progress = Progress::default();
    let cancel = progress.cancel.clone();
    let _ = ctrlc::set_handler(move || {
        if cancel.swap(true, Ordering::Relaxed) {
            // Second Ctrl+C: the user really wants out.
            std::process::exit(130);
        }
        eprintln!("\nCancelling… (press Ctrl+C again to force quit)");
    });
    let finished = Arc::new(AtomicBool::new(false));
    let show = io::stderr().is_terminal();
    let printer = show.then(|| {
        let (p, finished, label) = (progress.clone(), finished.clone(), label.to_owned());
        std::thread::spawn(move || {
            while !finished.load(Ordering::Relaxed) {
                eprint!("\r{label} {:5.1}%", p.fraction() * 100.0);
                let _ = io::stderr().flush();
                std::thread::sleep(Duration::from_millis(100));
            }
            eprint!("\r{}\r", " ".repeat(label.len() + 8));
        })
    });
    let out = job(&progress);
    finished.store(true, Ordering::Relaxed);
    if let Some(h) = printer {
        let _ = h.join();
    }
    out
}

fn print_summary(verb: &str, s: &Summary) {
    for w in &s.warnings {
        eprintln!("warning: {w}");
    }
    println!(
        "{verb} {} file(s), {} folder(s), {}.",
        s.files,
        s.dirs,
        human_size(s.bytes)
    );
}

/// ", 38% of original" style suffix, or nothing for empty input.
pub fn ratio(original: u64, sealed: u64) -> String {
    if original == 0 {
        String::new()
    } else {
        match sealed as f64 * 100.0 / original as f64 {
            p if p < 0.1 => ", <0.1% of original".to_string(),
            p if p < 10.0 => format!(", {p:.1}% of original"),
            p => format!(", {p:.0}% of original"),
        }
    }
}

pub fn run(cmd: Cmd) -> Result<()> {
    let params = SealParams::default();
    match cmd {
        Cmd::Seal {
            mut output,
            inputs,
            force,
            level,
            password_stdin,
        } => {
            if output
                .extension()
                .is_none_or(|e| !e.eq_ignore_ascii_case("sbx"))
            {
                output.as_mut_os_string().push(".sbx");
            }
            let pw = get_password(password_stdin, true)?;
            let s = with_progress("Sealing", |p| {
                archive::seal(&inputs, &output, pw.as_bytes(), &params, level, force, p)
            })?;
            print_summary("Sealed", &s);
            println!(
                "Sealbox written to {} ({}{})",
                output.display(),
                human_size(s.sealbox_size),
                ratio(s.bytes, s.sealbox_size)
            );
        }
        Cmd::Unseal {
            sealbox,
            paths,
            output,
            overwrite,
            password_stdin,
        } => {
            let pw = get_password(password_stdin, false)?;
            let s = with_progress("Unsealing", |p| {
                archive::unseal(
                    &sealbox,
                    pw.as_bytes(),
                    &params,
                    &output,
                    overwrite,
                    &paths,
                    p,
                )
            })?;
            print_summary("Unsealed", &s);
            println!("Into {}", output.display());
        }
        Cmd::Add {
            sealbox,
            inputs,
            level,
            password_stdin,
        } => {
            let pw = get_password(password_stdin, false)?;
            let s = with_progress("Adding", |p| {
                archive::add(&sealbox, &inputs, pw.as_bytes(), &params, level, p)
            })?;
            print_summary("Added", &s);
            println!(
                "{} is now {}",
                sealbox.display(),
                human_size(s.sealbox_size)
            );
        }
        Cmd::List {
            sealbox,
            password_stdin,
        } => {
            let pw = get_password(password_stdin, false)?;
            let contents = archive::list_contents(&sealbox, pw.as_bytes(), &params)?;
            let (mut files, mut total) = (0, 0);
            for e in &contents.entries {
                match e.kind {
                    EntryKind::Dir => println!("{:>10}  {}/", "", e.path),
                    EntryKind::File => {
                        files += 1;
                        total += e.size;
                        println!("{:>10}  {}", human_size(e.size), e.path);
                    }
                }
            }
            println!("{files} file(s), {} total when unsealed", human_size(total));
            println!(
                "Created with Sealbox {} (format {}, readable by Sealbox {} and newer)",
                contents.info.created_with, contents.info.format, contents.info.min_app
            );
        }
        Cmd::Verify {
            sealbox,
            password_stdin,
        } => {
            let pw = get_password(password_stdin, false)?;
            let s = with_progress("Verifying", |p| {
                archive::verify(&sealbox, pw.as_bytes(), &params, p)
            })?;
            println!(
                "OK: {} is intact ({} file(s), {} folder(s), {}).",
                sealbox.display(),
                s.files,
                s.dirs,
                human_size(s.bytes)
            );
        }
        Cmd::Gui { sealbox } => crate::gui::run(sealbox)?,
    }
    Ok(())
}
