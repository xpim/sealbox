//! Packing files/folders into a sealbox and extracting them again.
//!
//! The plaintext that goes through [`crate::crypto`] looks like this:
//!
//! ```text
//! u8 payload format (1 = zstd-compressed archive)
//! zstd frame containing:
//!   "TVIDX001"                     index magic
//!   u64 entry count
//!   per entry:
//!     u8  kind (1 = directory, 2 = file)
//!     u32 path length, then UTF-8 path ('/'-separated, relative)
//!     u32 unix permission bits (0 = unknown)
//!     i64 modification time, seconds since the Unix epoch
//!     u64 size in bytes (0 for directories)
//!   file contents, concatenated in index order
//! zero padding (Padmé) so the sealbox size reveals little about the content size
//! ```
//!
//! Compression happens before encryption (encrypted data does not compress).
//! The padding is applied to the *compressed* size, since that is what the
//! sealbox's file size would otherwise reveal. The payload format byte is
//! inside the encryption, so it is invisible on disk but leaves room for
//! future formats.
//!
//! The index comes first, so listing a sealbox only has to decrypt and
//! decompress the start of it.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use walkdir::WalkDir;

use crate::crypto::{DecryptReader, EncryptWriter, SealParams};

const INDEX_MAGIC: &[u8; 8] = b"TVIDX001";
const KIND_DIR: u8 = 1;
const KIND_FILE: u8 = 2;
const MAX_PATH_LEN: u32 = 32 * 1024;
const MAX_ENTRIES: u64 = 50_000_000;
/// Cap on the total size of all paths in the index. Compression lets a tiny
/// malicious sealbox claim a huge index; this bounds the memory it can take.
const MAX_INDEX_PATH_BYTES: u64 = 256 * 1024 * 1024;
const PAYLOAD_ZSTD: u8 = 1;
/// zstd level used when none is given (1 = fastest, 19 = smallest).
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Dir,
    File,
}

/// One item stored inside a sealbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub kind: EntryKind,
    /// Relative path with '/' separators, e.g. `photos/2024/beach.jpg`.
    pub path: String,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
}

/// Shared progress and cancellation state, so a GUI thread can observe a
/// running job.
#[derive(Clone, Default)]
pub struct Progress {
    pub done: Arc<AtomicU64>,
    pub total: Arc<AtomicU64>,
    pub cancel: Arc<AtomicBool>,
}

impl Progress {
    pub fn fraction(&self) -> f32 {
        let total = self.total.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            (self.done.load(Ordering::Relaxed) as f64 / total as f64) as f32
        }
    }
    fn check_cancel(&self) -> io::Result<()> {
        if self.cancel.load(Ordering::Relaxed) {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancelled by user",
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Default)]
pub struct Summary {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    /// Size of the sealbox file (only set when creating).
    pub sealbox_size: u64,
    /// Non-fatal issues, e.g. skipped symlinks.
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Path handling
// ---------------------------------------------------------------------------

/// Validate one path component for storing in, or extracting from, a sealbox.
fn check_component(c: &str) -> Result<()> {
    if c.is_empty() || c == "." || c == ".." {
        bail!("invalid path component {c:?}");
    }
    if c.contains(['/', '\\', '\0']) {
        bail!("path component {c:?} contains a forbidden character");
    }
    #[cfg(windows)]
    if c.contains(':') {
        // Would address an NTFS alternate data stream or a drive.
        bail!("path component {c:?} contains ':' which is not allowed on Windows");
    }
    // Defence in depth: the component must parse as one normal path element.
    let mut comps = Path::new(c).components();
    match (comps.next(), comps.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => bail!("invalid path component {c:?}"),
    }
}

/// Split and validate an archive path from a (possibly malicious) sealbox.
fn sanitize_archive_path(p: &str) -> Result<Vec<&str>> {
    let comps: Vec<&str> = p.split('/').collect();
    for c in &comps {
        check_component(c).with_context(|| format!("unsafe path in sealbox: {p:?}"))?;
    }
    Ok(comps)
}

fn os_name(name: &std::ffi::OsStr, full: &Path) -> Result<String> {
    let s = name
        .to_str()
        .ok_or_else(|| anyhow!("file name is not valid UTF-8: {}", full.display()))?;
    check_component(s).with_context(|| format!("cannot store {}", full.display()))?;
    Ok(s.to_owned())
}

// ---------------------------------------------------------------------------
// Creating sealboxes
// ---------------------------------------------------------------------------

struct Source {
    entry: Entry,
    path: PathBuf,
}

fn mtime_of(md: &fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn mode_of(md: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    md.permissions().mode() & 0o777
}
#[cfg(not(unix))]
fn mode_of(_md: &fs::Metadata) -> u32 {
    0
}

/// Walk the inputs and build the list of everything that will be stored.
/// Each input ends up at the top level of the sealbox under its own name.
fn collect(
    inputs: &[PathBuf],
    exclude: Option<&Path>,
    warnings: &mut Vec<String>,
) -> Result<Vec<Source>> {
    if inputs.is_empty() {
        bail!("nothing to add: no input files or folders given");
    }
    let mut out = Vec::new();
    let mut top_names = HashSet::new();
    for input in inputs {
        let abs = fs::canonicalize(input)
            .with_context(|| format!("cannot access {}", input.display()))?;
        let top = abs
            .file_name()
            .ok_or_else(|| anyhow!("cannot add a filesystem root: {}", input.display()))?;
        let top = os_name(top, &abs)?;
        if !top_names.insert(top.clone()) {
            bail!("two inputs share the name {top:?}; rename one or put them in a folder");
        }
        for item in WalkDir::new(&abs).follow_links(false).sort_by_file_name() {
            let item = item.with_context(|| format!("reading {}", abs.display()))?;
            let full = item.path();
            if exclude.is_some_and(|ex| ex == full) {
                continue;
            }
            let mut rel = vec![top.clone()];
            for c in full.strip_prefix(&abs).unwrap().components() {
                rel.push(os_name(c.as_os_str(), full)?);
            }
            let ft = item.file_type();
            let md = item
                .metadata()
                .with_context(|| format!("reading {}", full.display()))?;
            let kind = if ft.is_dir() {
                EntryKind::Dir
            } else if ft.is_file() {
                EntryKind::File
            } else {
                warnings.push(format!(
                    "skipped (symlink or special file): {}",
                    full.display()
                ));
                continue;
            };
            out.push(Source {
                entry: Entry {
                    kind,
                    path: rel.join("/"),
                    size: if kind == EntryKind::File { md.len() } else { 0 },
                    mode: mode_of(&md),
                    mtime: mtime_of(&md),
                },
                path: full.to_path_buf(),
            });
        }
    }
    Ok(out)
}

fn encode_index(entries: &[&Entry]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(INDEX_MAGIC);
    b.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for e in entries {
        b.push(match e.kind {
            EntryKind::Dir => KIND_DIR,
            EntryKind::File => KIND_FILE,
        });
        b.extend_from_slice(&(e.path.len() as u32).to_le_bytes());
        b.extend_from_slice(e.path.as_bytes());
        b.extend_from_slice(&e.mode.to_le_bytes());
        b.extend_from_slice(&e.mtime.to_le_bytes());
        b.extend_from_slice(&e.size.to_le_bytes());
    }
    b
}

/// Padmé padding (Nikitin et al., 2019): rounds a length up so that at most
/// O(log log n) bits of the size leak, with at most ~12% overhead.
fn padme(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    let e = 63 - len.leading_zeros() as u64; // floor(log2 len)
    let s = 64 - e.leading_zeros() as u64; // floor(log2 e) + 1
    let last_bits = e - s;
    let mask = (1u64 << last_bits) - 1;
    (len + mask) & !mask
}

fn copy_with_progress<R: Read, W: Write>(
    r: &mut R,
    w: &mut W,
    limit: u64,
    progress: &Progress,
) -> io::Result<u64> {
    let mut buf = vec![0u8; 256 * 1024];
    let mut copied = 0u64;
    while copied < limit {
        progress.check_cancel()?;
        let want = buf.len().min((limit - copied) as usize);
        let n = r.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n])?;
        copied += n as u64;
        progress.done.fetch_add(n as u64, Ordering::Relaxed);
    }
    Ok(copied)
}

/// Encrypt `inputs` (files and/or folders) into a new sealbox at `output`.
///
/// The sealbox is written to a temporary file next to `output` first and moved
/// into place only once it is complete, so a failure never leaves a broken
/// or half-written sealbox behind.
pub fn seal(
    inputs: &[PathBuf],
    output: &Path,
    password: &[u8],
    params: &SealParams,
    compression_level: i32,
    overwrite: bool,
    progress: &Progress,
) -> Result<Summary> {
    if password.is_empty() {
        bail!("password must not be empty");
    }
    if output.exists() && !overwrite {
        bail!(
            "{} already exists (use --force to overwrite)",
            output.display()
        );
    }
    let mut summary = Summary::default();
    let exclude = fs::canonicalize(output).ok();
    let sources = collect(inputs, exclude.as_deref(), &mut summary.warnings)?;

    let entries: Vec<&Entry> = sources.iter().map(|s| &s.entry).collect();
    let index = encode_index(&entries);
    let data_len: u64 = entries.iter().map(|e| e.size).sum();
    progress.total.store(data_len, Ordering::Relaxed);
    progress.done.store(0, Ordering::Relaxed);

    let dir = match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let tmp = tempfile::Builder::new()
        .prefix(".sealbox-tmp-")
        .tempfile_in(dir)
        .with_context(|| format!("cannot write in {}", dir.display()))?;
    let file = tmp.as_file().try_clone()?;
    let mut w = EncryptWriter::new(BufWriter::new(file), password, params)?;
    w.write_all(&[PAYLOAD_ZSTD])?;
    let mut w = zstd::Encoder::new(w, compression_level)?;
    // The AEAD already authenticates every byte; a zstd checksum adds nothing.
    w.include_checksum(false)?;
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get().min(8));
    if threads > 1 {
        w.multithread(threads as u32)?;
    }
    w.write_all(&index)?;

    for src in &sources {
        match src.entry.kind {
            EntryKind::Dir => summary.dirs += 1,
            EntryKind::File => {
                let f = File::open(&src.path)
                    .with_context(|| format!("cannot open {}", src.path.display()))?;
                let mut r = BufReader::new(f);
                let n = copy_with_progress(&mut r, &mut w, src.entry.size, progress)
                    .with_context(|| format!("reading {}", src.path.display()))?;
                // The index already promised `size` bytes: the file must not
                // shrink or grow while we read it.
                let mut extra = [0u8; 1];
                if n != src.entry.size || r.read(&mut extra)? != 0 {
                    bail!(
                        "{} changed while it was being added; try again",
                        src.path.display()
                    );
                }
                summary.files += 1;
                summary.bytes += n;
            }
        }
    }
    let mut w = w.finish()?;
    let len = w.plaintext_len();
    io::copy(&mut io::repeat(0).take(padme(len) - len), &mut w)?;
    let file = w.finish()?.into_inner().map_err(|e| e.into_error())?;
    file.sync_all()?;
    drop(file);

    if overwrite {
        tmp.persist(output)
    } else {
        tmp.persist_noclobber(output)
    }
    .map_err(|e| e.error)
    .with_context(|| format!("cannot write {}", output.display()))?;
    summary.sealbox_size = fs::metadata(output).map(|m| m.len()).unwrap_or(0);
    Ok(summary)
}

// ---------------------------------------------------------------------------
// Reading sealboxes
// ---------------------------------------------------------------------------

fn read_u8<R: Read>(r: &mut R) -> io::Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}
fn read_u32<R: Read>(r: &mut R) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}
fn read_u64<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn read_index<R: Read>(r: &mut R) -> Result<Vec<Entry>> {
    let bad = || anyhow!("sealbox contents are malformed");
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic)?;
    if &magic != INDEX_MAGIC {
        return Err(bad());
    }
    let count = read_u64(r)?;
    if count > MAX_ENTRIES {
        return Err(bad());
    }
    let mut entries = Vec::new();
    let mut path_bytes = 0u64;
    for _ in 0..count {
        let kind = match read_u8(r)? {
            KIND_DIR => EntryKind::Dir,
            KIND_FILE => EntryKind::File,
            _ => return Err(bad()),
        };
        let len = read_u32(r)?;
        path_bytes += len as u64;
        if len > MAX_PATH_LEN || path_bytes > MAX_INDEX_PATH_BYTES {
            return Err(bad());
        }
        let mut p = vec![0u8; len as usize];
        r.read_exact(&mut p)?;
        let path = String::from_utf8(p).map_err(|_| bad())?;
        sanitize_archive_path(&path)?;
        let mode = read_u32(r)?;
        let mtime = read_u64(r)? as i64;
        let size = read_u64(r)?;
        if kind == EntryKind::Dir && size != 0 {
            return Err(bad());
        }
        entries.push(Entry {
            kind,
            path,
            size,
            mode,
            mtime,
        });
    }
    Ok(entries)
}

type Decrypted = BufReader<DecryptReader<BufReader<File>>>;
type Payload = zstd::stream::read::Decoder<'static, Decrypted>;

/// Decrypt the sealbox and return a reader over the decompressed archive.
fn open_sealbox(sealbox: &Path, password: &[u8], params: &SealParams) -> Result<Payload> {
    let f = File::open(sealbox).with_context(|| format!("cannot open {}", sealbox.display()))?;
    let mut r = DecryptReader::new(BufReader::new(f), password, params)?;
    if read_u8(&mut r)? != PAYLOAD_ZSTD {
        bail!("sealbox contents use an unsupported format (made by a newer version?)");
    }
    let z = zstd::stream::read::Decoder::with_buffer(BufReader::new(r))?.single_frame();
    Ok(z)
}

/// Verify that the archive ended exactly where the index said it would,
/// then read the padding through to the end of the encrypted stream. That
/// authenticates the final chunk, proving the sealbox was not truncated.
fn finish_payload(mut z: Payload) -> Result<()> {
    let mut extra = [0u8; 1];
    if z.read(&mut extra)? != 0 {
        bail!("sealbox contents are malformed (unexpected trailing data)");
    }
    io::copy(&mut z.finish(), &mut io::sink())?;
    Ok(())
}

/// Decrypt only the index of a sealbox and return its entries.
pub fn list_contents(sealbox: &Path, password: &[u8], params: &SealParams) -> Result<Vec<Entry>> {
    let mut r = open_sealbox(sealbox, password, params)?;
    read_index(&mut r)
}

/// Create the directories for `comps` under `dest`, refusing to follow
/// symlinks or to go through anything that is not a real directory.
fn ensure_dirs(dest: &Path, comps: &[&str], created: &mut Vec<PathBuf>) -> Result<PathBuf> {
    let mut cur = dest.to_path_buf();
    for c in comps {
        cur.push(c);
        match fs::symlink_metadata(&cur) {
            Ok(md) if md.is_dir() => {}
            Ok(_) => bail!("{} exists and is not a folder", cur.display()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&cur).with_context(|| format!("cannot create {}", cur.display()))?;
                created.push(cur.clone());
            }
            Err(e) => return Err(e).with_context(|| format!("cannot access {}", cur.display())),
        }
    }
    Ok(cur)
}

#[cfg(unix)]
fn apply_mode(f: &File, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    if mode != 0 {
        // Never restore setuid/setgid/sticky bits from an untrusted sealbox.
        let _ = f.set_permissions(fs::Permissions::from_mode(mode & 0o777));
    }
}
#[cfg(not(unix))]
fn apply_mode(_f: &File, _mode: u32) {}

fn to_systime(secs: i64) -> Option<SystemTime> {
    if secs >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(secs as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(secs.unsigned_abs()))
    }
}

/// Decrypt a sealbox into `dest`. Existing files are only replaced when
/// `overwrite` is set. If anything goes wrong (wrong password, tampering,
/// disk full, cancel), everything this call created is removed again.
pub fn unseal(
    sealbox: &Path,
    password: &[u8],
    params: &SealParams,
    dest: &Path,
    overwrite: bool,
    progress: &Progress,
) -> Result<Summary> {
    let mut r = open_sealbox(sealbox, password, params)?;
    let entries = read_index(&mut r)?;

    // Check for conflicts before touching the disk.
    if !overwrite {
        let clashes: Vec<String> = entries
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .filter(|e| fs::symlink_metadata(dest.join(&e.path)).is_ok())
            .take(5)
            .map(|e| e.path.clone())
            .collect();
        if !clashes.is_empty() {
            bail!(
                "these already exist in {} (use --overwrite to replace them): {}",
                dest.display(),
                clashes.join(", ")
            );
        }
    }

    fs::create_dir_all(dest).with_context(|| format!("cannot create {}", dest.display()))?;
    progress
        .total
        .store(entries.iter().map(|e| e.size).sum(), Ordering::Relaxed);
    progress.done.store(0, Ordering::Relaxed);

    let mut created_dirs = Vec::new();
    let mut created_files = Vec::new();
    let result = (|| -> Result<Summary> {
        let mut summary = Summary::default();
        for e in &entries {
            let comps = sanitize_archive_path(&e.path)?;
            match e.kind {
                EntryKind::Dir => {
                    ensure_dirs(dest, &comps, &mut created_dirs)?;
                    summary.dirs += 1;
                }
                EntryKind::File => {
                    let (name, parents) = comps.split_last().unwrap();
                    let target = ensure_dirs(dest, parents, &mut created_dirs)?.join(name);
                    if let Ok(md) = fs::symlink_metadata(&target) {
                        if md.is_dir() {
                            bail!("{} exists and is a folder", target.display());
                        }
                        if !overwrite {
                            bail!("{} already exists", target.display());
                        }
                        // Removes symlinks themselves, never their targets.
                        fs::remove_file(&target)
                            .with_context(|| format!("cannot replace {}", target.display()))?;
                    }
                    // create_new: fails rather than following a symlink that
                    // appeared in the meantime.
                    let f = File::options()
                        .write(true)
                        .create_new(true)
                        .open(&target)
                        .with_context(|| format!("cannot create {}", target.display()))?;
                    created_files.push(target.clone());
                    let mut w = BufWriter::new(f);
                    let n = copy_with_progress(&mut r, &mut w, e.size, progress)?;
                    if n != e.size {
                        bail!("sealbox contents are malformed (file data too short)");
                    }
                    let f = w.into_inner().map_err(|e| e.into_error())?;
                    apply_mode(&f, e.mode);
                    if let Some(t) = to_systime(e.mtime) {
                        let _ = f.set_modified(t);
                    }
                    summary.files += 1;
                    summary.bytes += n;
                }
            }
        }
        finish_payload(r)?;
        Ok(summary)
    })();

    if result.is_err() {
        for f in created_files.iter().rev() {
            let _ = fs::remove_file(f);
        }
        for d in created_dirs.iter().rev() {
            let _ = fs::remove_dir(d);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: SealParams = SealParams {
        kdf: crate::crypto::KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        },
        chunk_size: 64 * 1024,
    };

    /// Incompressible test data (xorshift), so sealboxes span many chunks.
    fn pseudo_random(len: usize) -> Vec<u8> {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    #[test]
    fn compresses_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("log.txt");
        let text = "2026-11-13 INFO request handled in 12ms\n".repeat(100_000);
        fs::write(&src, &text).unwrap();
        let sealbox = tmp.path().join("v.sbx");
        let p = Progress::default();
        let s = seal(&[src], &sealbox, b"pw", &FAST, 3, false, &p).unwrap();
        assert!(
            s.sealbox_size < text.len() as u64 / 20,
            "sealbox {} bytes",
            s.sealbox_size
        );
        let out = tmp.path().join("out");
        unseal(&sealbox, b"pw", &FAST, &out, false, &p).unwrap();
        assert_eq!(fs::read_to_string(out.join("log.txt")).unwrap(), text);
    }

    #[test]
    fn padme_values() {
        assert_eq!(padme(0), 0);
        assert_eq!(padme(1), 1);
        for l in 2..100_000u64 {
            let p = padme(l);
            assert!(
                p >= l && (p - l) as f64 <= l as f64 * 0.12 + 1.0,
                "{l} -> {p}"
            );
        }
    }

    #[test]
    fn rejects_unsafe_paths() {
        for p in [
            "../x",
            "a/../b",
            "/etc/passwd",
            "a//b",
            "",
            ".",
            "a/./b",
            "a\\..\\b",
            "a/b\0",
        ] {
            assert!(sanitize_archive_path(p).is_err(), "{p:?} accepted");
        }
        assert!(sanitize_archive_path("a/b c/d.txt").is_ok());
    }

    #[test]
    fn full_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        fs::create_dir_all(src.join("docs/empty")).unwrap();
        fs::write(src.join("docs/a.txt"), b"hello").unwrap();
        let big: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        fs::write(src.join("big.bin"), &big).unwrap();
        let single = tmp.path().join("note.md");
        fs::write(&single, b"# note").unwrap();

        let sealbox = tmp.path().join("out.sbx");
        let p = Progress::default();
        let s = seal(&[src.clone(), single], &sealbox, b"pw", &FAST, 3, false, &p).unwrap();
        assert_eq!(s.files, 3);
        assert_eq!(p.fraction(), 1.0);

        let raw = fs::read(&sealbox).unwrap();
        assert!(!raw.windows(5).any(|w| w == b"a.txt"), "file name leaked");
        assert!(!raw.windows(5).any(|w| w == b"hello"), "content leaked");

        let names: Vec<String> = list_contents(&sealbox, b"pw", &FAST)
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert!(names.contains(&"src/docs/empty".to_string()));
        assert!(names.contains(&"note.md".to_string()));
        assert!(list_contents(&sealbox, b"wrong", &FAST).is_err());

        let out = tmp.path().join("out");
        unseal(&sealbox, b"pw", &FAST, &out, false, &p).unwrap();
        assert_eq!(fs::read(out.join("src/docs/a.txt")).unwrap(), b"hello");
        assert_eq!(fs::read(out.join("src/big.bin")).unwrap(), big);
        assert_eq!(fs::read(out.join("note.md")).unwrap(), b"# note");
        assert!(out.join("src/docs/empty").is_dir());

        // Second extract refuses to clobber, then works with overwrite.
        assert!(unseal(&sealbox, b"pw", &FAST, &out, false, &p).is_err());
        unseal(&sealbox, b"pw", &FAST, &out, true, &p).unwrap();
        // Refuse to overwrite the sealbox itself without the flag.
        assert!(
            seal(
                std::slice::from_ref(&out),
                &sealbox,
                b"pw",
                &FAST,
                3,
                false,
                &p
            )
            .is_err()
        );
    }

    #[test]
    fn failed_extract_cleans_up() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("d");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a"), vec![1u8; 10]).unwrap();
        fs::write(src.join("b"), pseudo_random(3_000_000)).unwrap();
        let sealbox = tmp.path().join("v.sbx");
        seal(
            &[src],
            &sealbox,
            b"pw",
            &FAST,
            3,
            false,
            &Progress::default(),
        )
        .unwrap();
        // Corrupt the end of the file: the start decrypts, the end does not.
        let mut raw = fs::read(&sealbox).unwrap();
        let n = raw.len();
        raw[n - 5] ^= 0xff;
        fs::write(&sealbox, raw).unwrap();
        let out = tmp.path().join("out");
        assert!(unseal(&sealbox, b"pw", &FAST, &out, false, &Progress::default()).is_err());
        assert_eq!(
            fs::read_dir(&out).unwrap().count(),
            0,
            "partial output left behind"
        );
    }

    #[cfg(unix)]
    #[test]
    fn does_not_write_through_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("d");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("f"), b"payload").unwrap();
        let sealbox = tmp.path().join("v.sbx");
        seal(
            &[src],
            &sealbox,
            b"pw",
            &FAST,
            3,
            false,
            &Progress::default(),
        )
        .unwrap();

        let out = tmp.path().join("out");
        let elsewhere = tmp.path().join("elsewhere");
        fs::create_dir_all(&out).unwrap();
        fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, out.join("d")).unwrap();
        assert!(unseal(&sealbox, b"pw", &FAST, &out, true, &Progress::default()).is_err());
        assert!(!elsewhere.join("f").exists());
    }
}
