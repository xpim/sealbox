use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::archive::{self, EntryKind, Progress, Summary};
use crate::crypto::VaultParams;
use crate::{MIN_PASSWORD_LEN, human_size};

#[derive(Parser)]
#[command(
    name = "vault",
    version,
    about = "Encrypt files and folders into a single password-protected .vault file.",
    after_help = "Run without arguments to open the graphical interface.\n\n\
        The password is read from (in order): --password-stdin, the VAULT_PASSWORD\n\
        environment variable, or an interactive prompt."
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Option<Cmd>,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Encrypt files and folders into a new .vault file
    Create {
        /// Output vault file (".vault" is appended if missing)
        #[arg(short, long)]
        output: PathBuf,
        /// Files and folders to put in the vault
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        /// Overwrite the output file if it already exists
        #[arg(short, long)]
        force: bool,
        /// Compression level: 1 (fastest) to 19 (smallest)
        #[arg(short, long, default_value_t = archive::DEFAULT_COMPRESSION_LEVEL,
              value_parser = clap::value_parser!(i32).range(1..=19))]
        level: i32,
        /// Read the password from the first line of standard input
        #[arg(long)]
        password_stdin: bool,
    },
    /// Decrypt a .vault file and restore its contents
    Extract {
        /// Vault file to extract
        vault: PathBuf,
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
    /// Show what is inside a .vault file (requires the password)
    List {
        /// Vault file to inspect
        vault: PathBuf,
        /// Read the password from the first line of standard input
        #[arg(long)]
        password_stdin: bool,
    },
    /// Open the graphical interface
    Gui {
        /// Vault file to open right away
        vault: Option<PathBuf>,
    },
}

fn get_password(from_stdin: bool, confirm: bool) -> Result<Zeroizing<String>> {
    let pw = if from_stdin {
        let mut line = Zeroizing::new(String::new());
        io::stdin().lock().read_line(&mut line)?;
        Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_owned())
    } else if let Ok(pw) = std::env::var("VAULT_PASSWORD") {
        Zeroizing::new(pw)
    } else {
        let pw = Zeroizing::new(rpassword::prompt_password("Password: ")?);
        if confirm {
            let again = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
            if *pw != *again {
                bail!("passwords do not match");
            }
        }
        pw
    };
    if pw.is_empty() {
        bail!("password must not be empty");
    }
    if confirm && pw.chars().count() < MIN_PASSWORD_LEN {
        bail!("password must be at least {MIN_PASSWORD_LEN} characters");
    }
    Ok(pw)
}

/// Run `job` while drawing a progress line on stderr (when it is a terminal).
fn with_progress<T>(label: &str, job: impl FnOnce(&Progress) -> T) -> T {
    let progress = Progress::default();
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

/// ", 38% of original" style suffix, or nothing for empty input.
pub fn ratio(original: u64, vault: u64) -> String {
    if original == 0 {
        String::new()
    } else {
        match vault as f64 * 100.0 / original as f64 {
            p if p < 0.1 => ", <0.1% of original".to_string(),
            p if p < 10.0 => format!(", {p:.1}% of original"),
            p => format!(", {p:.0}% of original"),
        }
    }
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

pub fn run(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Create {
            mut output,
            inputs,
            force,
            level,
            password_stdin,
        } => {
            if output
                .extension()
                .is_none_or(|e| !e.eq_ignore_ascii_case("vault"))
            {
                output.as_mut_os_string().push(".vault");
            }
            let pw = get_password(password_stdin, true)?;
            let s = with_progress("Encrypting", |p| {
                archive::create_vault(
                    &inputs,
                    &output,
                    pw.as_bytes(),
                    &VaultParams::default(),
                    level,
                    force,
                    p,
                )
            })?;
            print_summary("Encrypted", &s);
            println!(
                "Vault written to {} ({}{})",
                output.display(),
                human_size(s.vault_size),
                ratio(s.bytes, s.vault_size)
            );
        }
        Cmd::Extract {
            vault,
            output,
            overwrite,
            password_stdin,
        } => {
            let pw = get_password(password_stdin, false)?;
            let s = with_progress("Decrypting", |p| {
                archive::extract_vault(
                    &vault,
                    pw.as_bytes(),
                    &VaultParams::default(),
                    &output,
                    overwrite,
                    p,
                )
            })?;
            print_summary("Extracted", &s);
            println!("Into {}", output.display());
        }
        Cmd::List {
            vault,
            password_stdin,
        } => {
            let pw = get_password(password_stdin, false)?;
            let entries = archive::list_vault(&vault, pw.as_bytes(), &VaultParams::default())?;
            let (mut files, mut total) = (0, 0);
            for e in &entries {
                match e.kind {
                    EntryKind::Dir => println!("{:>10}  {}/", "", e.path),
                    EntryKind::File => {
                        files += 1;
                        total += e.size;
                        println!("{:>10}  {}", human_size(e.size), e.path);
                    }
                }
            }
            println!("{files} file(s), {} total", human_size(total));
        }
        Cmd::Gui { vault } => crate::gui::run(vault)?,
    }
    Ok(())
}
