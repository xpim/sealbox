//! Packing files/folders into a sealbox and unsealing them again.
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
//!
//! Unsealing is *staged*: every file is first written under a temporary name
//! next to its destination, and only renamed into place once the whole
//! sealbox has been decrypted and authenticated. A corrupt sealbox, a cancel
//! or a full disk therefore never leaves partial output behind, and never
//! destroys existing files.

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
use crate::human_size;

const INDEX_MAGIC: &[u8; 8] = b"TVIDX001";
const KIND_DIR: u8 = 1;
const KIND_FILE: u8 = 2;
const MAX_PATH_LEN: u32 = 32 * 1024;
/// Caps on what an index may claim. Compression lets a tiny malicious
/// sealbox claim a huge index; these bound the memory it can take
/// (roughly 100 bytes per entry plus the path bytes).
const MAX_ENTRIES: u64 = 5_000_000;
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

/// Shared progress and cancellation state, so a GUI thread or Ctrl+C handler
/// can observe and stop a running job.
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
            Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"))
        } else {
            Ok(())
        }
    }
    fn reset(&self, total: u64) {
        self.total.store(total, Ordering::Relaxed);
        self.done.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug, Default)]
pub struct Summary {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    /// Size of the sealbox file (set when sealing or adding).
    pub sealbox_size: u64,
    /// Non-fatal issues, e.g. skipped symlinks.
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Path handling
// ---------------------------------------------------------------------------

/// Portable validation of one path component: safe on every platform to
/// store in, or read from, a sealbox.
fn check_component(c: &str) -> Result<()> {
    if c.is_empty() || c == "." || c == ".." {
        bail!("invalid path component {c:?}");
    }
    if c.contains(['/', '\\', '\0']) {
        bail!("path component {c:?} contains a forbidden character");
    }
    // Defence in depth: the component must parse as one normal path element.
    let mut comps = Path::new(c).components();
    match (comps.next(), comps.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => bail!("invalid path component {c:?}"),
    }
}

/// Why a name cannot be created on Windows, if it cannot. Covers illegal
/// characters (incl. ':' which would address an NTFS alternate data stream),
/// names Windows silently alters (trailing dot/space) and reserved device
/// names such as `CON` or `com1.txt`.
pub(crate) fn windows_name_problem(c: &str) -> Option<&'static str> {
    if c.chars()
        .any(|ch| matches!(ch, '<' | '>' | ':' | '"' | '|' | '?' | '*') || (ch as u32) < 32)
    {
        return Some("contains a character that Windows does not allow");
    }
    if c.ends_with('.') || c.ends_with(' ') {
        return Some("ends with a dot or space, which Windows does not allow");
    }
    let stem = c
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ["COM", "LPT"].iter().any(|dev| {
            stem.strip_prefix(dev).is_some_and(|n| {
                matches!(
                    n,
                    "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        });
    reserved.then_some("is a reserved device name on Windows")
}

/// Validation for a component that is about to be created on this machine.
fn check_component_for_disk(c: &str) -> Result<()> {
    check_component(c)?;
    if cfg!(windows)
        && let Some(why) = windows_name_problem(c)
    {
        bail!("{c:?} {why}");
    }
    Ok(())
}

/// Split and validate an archive path from a (possibly malicious) sealbox.
fn sanitize_archive_path(p: &str) -> Result<Vec<&str>> {
    let comps: Vec<&str> = p.split('/').collect();
    for c in &comps {
        check_component(c).with_context(|| format!("unsafe path in sealbox: {p:?}"))?;
    }
    Ok(comps)
}

/// Key used to detect paths that would collide on this machine's file
/// system (case-insensitive on Windows and, by default, macOS).
fn collision_key(p: &str) -> String {
    if cfg!(any(windows, target_os = "macos")) {
        p.to_lowercase()
    } else {
        p.to_owned()
    }
}

fn top_level(p: &str) -> &str {
    p.split('/').next().unwrap_or(p)
}

fn os_name(name: &std::ffi::OsStr, full: &Path) -> Result<String> {
    let s = name
        .to_str()
        .ok_or_else(|| anyhow!("file name is not valid UTF-8: {}", full.display()))?;
    check_component(s).with_context(|| format!("cannot store {}", full.display()))?;
    Ok(s.to_owned())
}

// ---------------------------------------------------------------------------
// Writing sealboxes
// ---------------------------------------------------------------------------

/// Where the data of an entry comes from while writing a sealbox.
enum Source {
    Dir,
    Disk(PathBuf),
    /// The next `size` bytes of an existing sealbox being rewritten.
    Existing,
}

struct Item {
    entry: Entry,
    source: Source,
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
) -> Result<Vec<Item>> {
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
        if !top_names.insert(collision_key(&top)) {
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
            let (kind, source) = if ft.is_dir() {
                (EntryKind::Dir, Source::Dir)
            } else if ft.is_file() {
                (EntryKind::File, Source::Disk(full.to_path_buf()))
            } else {
                warnings.push(format!(
                    "skipped (symlink or special file): {}",
                    full.display()
                ));
                continue;
            };
            out.push(Item {
                entry: Entry {
                    kind,
                    path: rel.join("/"),
                    size: if kind == EntryKind::File { md.len() } else { 0 },
                    mode: mode_of(&md),
                    mtime: mtime_of(&md),
                },
                source,
            });
        }
    }
    Ok(out)
}

fn encode_index<'a>(entries: impl ExactSizeIterator<Item = &'a Entry>) -> Vec<u8> {
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

/// Write `items` as a new sealbox at `output`. Data for `Source::Existing`
/// items is read, in order, from `existing`, which is fully verified before
/// the new sealbox replaces anything.
///
/// The sealbox is written to a temporary file next to `output` first and moved
/// into place only once it is complete, so a failure never leaves a broken
/// or half-written sealbox behind.
#[allow(clippy::too_many_arguments)]
fn write_sealbox(
    items: &[Item],
    mut existing: Option<Payload>,
    output: &Path,
    password: &[u8],
    params: &SealParams,
    compression_level: i32,
    overwrite: bool,
    progress: &Progress,
) -> Result<Summary> {
    let mut summary = Summary::default();
    let index = encode_index(items.iter().map(|i| &i.entry));
    progress.reset(items.iter().map(|i| i.entry.size).sum());

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

    for item in items {
        let size = item.entry.size;
        match &item.source {
            Source::Dir => summary.dirs += 1,
            Source::Disk(path) => {
                let f =
                    File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
                let mut r = BufReader::new(f);
                let n = copy_with_progress(&mut r, &mut w, size, progress)
                    .with_context(|| format!("reading {}", path.display()))?;
                // The index already promised `size` bytes: the file must not
                // shrink or grow while we read it.
                let mut extra = [0u8; 1];
                if n != size || r.read(&mut extra)? != 0 {
                    bail!(
                        "{} changed while it was being added; try again",
                        path.display()
                    );
                }
                summary.files += 1;
                summary.bytes += n;
            }
            Source::Existing => {
                let r = existing.as_mut().expect("existing sealbox reader");
                let n = copy_with_progress(r, &mut w, size, progress)?;
                if n != size {
                    bail!("sealbox contents are malformed (file data too short)");
                }
            }
        }
    }
    if let Some(r) = existing {
        // Authenticate the rest of the old sealbox before replacing it.
        finish_payload(r)?;
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

/// Encrypt `inputs` (files and/or folders) into a new sealbox at `output`.
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
    let mut warnings = Vec::new();
    let exclude = fs::canonicalize(output).ok();
    let items = collect(inputs, exclude.as_deref(), &mut warnings)?;
    let mut summary = write_sealbox(
        &items,
        None,
        output,
        password,
        params,
        compression_level,
        overwrite,
        progress,
    )?;
    summary.warnings = warnings;
    Ok(summary)
}

/// Add `inputs` to an existing sealbox, keeping its password. The sealbox is
/// rewritten (with a fresh salt and nonce) and atomically replaced; the old
/// contents are fully verified first.
pub fn add(
    sealbox: &Path,
    inputs: &[PathBuf],
    password: &[u8],
    params: &SealParams,
    compression_level: i32,
    progress: &Progress,
) -> Result<Summary> {
    let mut existing = open_sealbox(sealbox, password, params)?;
    let old = read_index(&mut existing)?;
    let mut warnings = Vec::new();
    let exclude = fs::canonicalize(sealbox).ok();
    let new = collect(inputs, exclude.as_deref(), &mut warnings)?;

    let taken: HashSet<String> = old
        .iter()
        .map(|e| collision_key(top_level(&e.path)))
        .collect();
    for item in &new {
        let top = top_level(&item.entry.path);
        if taken.contains(&collision_key(top)) {
            bail!("the sealbox already contains an item named {top:?}");
        }
    }
    let new_dirs = new
        .iter()
        .filter(|i| matches!(i.source, Source::Dir))
        .count() as u64;
    let items: Vec<Item> = old
        .into_iter()
        .map(|entry| Item {
            source: match entry.kind {
                EntryKind::Dir => Source::Dir,
                EntryKind::File => Source::Existing,
            },
            entry,
        })
        .chain(new)
        .collect();
    let mut summary = write_sealbox(
        &items,
        Some(existing),
        sealbox,
        password,
        params,
        compression_level,
        true,
        progress,
    )?;
    // `files`/`bytes` already count only files read from disk (the new ones).
    summary.dirs = new_dirs;
    summary.warnings = warnings;
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

/// Read and discard the data of one file entry.
fn skip_file(r: &mut Payload, size: u64, progress: &Progress) -> Result<()> {
    if copy_with_progress(r, &mut io::sink(), size, progress)? != size {
        bail!("sealbox contents are malformed (file data too short)");
    }
    Ok(())
}

/// Decrypt only the index of a sealbox and return its entries.
pub fn list_contents(sealbox: &Path, password: &[u8], params: &SealParams) -> Result<Vec<Entry>> {
    let mut r = open_sealbox(sealbox, password, params)?;
    read_index(&mut r)
}

/// Decrypt and authenticate the whole sealbox without writing anything.
pub fn verify(
    sealbox: &Path,
    password: &[u8],
    params: &SealParams,
    progress: &Progress,
) -> Result<Summary> {
    let mut r = open_sealbox(sealbox, password, params)?;
    let entries = read_index(&mut r)?;
    progress.reset(entries.iter().map(|e| e.size).sum());
    let mut summary = Summary::default();
    for e in &entries {
        match e.kind {
            EntryKind::Dir => summary.dirs += 1,
            EntryKind::File => {
                skip_file(&mut r, e.size, progress)?;
                summary.files += 1;
                summary.bytes += e.size;
            }
        }
    }
    finish_payload(r)?;
    Ok(summary)
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
    // Staging files start out 0600. Without a stored mode, use the usual 0644.
    let mode = if mode == 0 { 0o644 } else { mode };
    // Never restore setuid/setgid/sticky bits from an untrusted sealbox.
    let _ = f.set_permissions(fs::Permissions::from_mode(mode & 0o777));
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

/// The set of paths chosen for a selective unseal. A path is selected when
/// it, or any folder above it, is in the set. An empty set selects all.
struct Selection<'a>(HashSet<&'a str>);

impl Selection<'_> {
    fn contains(&self, path: &str) -> bool {
        self.0.is_empty()
            || self.0.contains(path)
            || path
                .match_indices('/')
                .any(|(i, _)| self.0.contains(&path[..i]))
    }
}

/// Checks that need the full index, done before anything touches the disk:
/// names valid on this OS, no duplicate or colliding paths, no file that is
/// also used as a folder.
fn check_layout(entries: &[&Entry]) -> Result<()> {
    let mut files = HashSet::new();
    let mut dirs = HashSet::new();
    for e in entries {
        for c in e.path.split('/') {
            check_component_for_disk(c).with_context(|| format!("cannot unseal {:?}", e.path))?;
        }
        let key = collision_key(&e.path);
        let clash = match e.kind {
            EntryKind::File => dirs.contains(&key) || !files.insert(key),
            EntryKind::Dir => files.contains(&key) || !dirs.insert(key),
        };
        if clash {
            bail!(
                "sealbox contains {:?} more than once (or with different letter case)",
                e.path
            );
        }
    }
    for e in entries {
        let key = collision_key(&e.path);
        for (i, _) in key.match_indices('/') {
            if files.contains(&key[..i]) {
                bail!(
                    "sealbox uses {:?} both as a file and as a folder",
                    &e.path[..i]
                );
            }
        }
    }
    Ok(())
}

/// Free space on the file system that will hold `dest` (which may not exist
/// yet).
fn available_space(dest: &Path) -> Option<u64> {
    let mut p = dest;
    loop {
        if p.exists() {
            return fs2::available_space(p).ok();
        }
        p = match p.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
    }
}

struct Staged {
    tmp: tempfile::TempPath,
    target: PathBuf,
}

/// Decrypt a sealbox into `dest`. With a non-empty `only`, unseal just those
/// paths (files, or folders including everything below them). Existing files
/// are only replaced when `overwrite` is set.
///
/// Files are staged under temporary names and moved into place only after
/// the whole sealbox has been authenticated. If anything goes wrong (wrong
/// password, tampering, disk full, cancel) nothing is left behind and no
/// existing file is touched.
pub fn unseal(
    sealbox: &Path,
    password: &[u8],
    params: &SealParams,
    dest: &Path,
    overwrite: bool,
    only: &[String],
    progress: &Progress,
) -> Result<Summary> {
    let mut r = open_sealbox(sealbox, password, params)?;
    let entries = read_index(&mut r)?;

    // --- Checks before touching the disk -------------------------------
    let only = Selection(only.iter().map(|o| o.trim_matches('/')).collect());
    if !only.0.is_empty() {
        // Every path in the sealbox, plus every folder above one.
        let known: HashSet<&str> = entries
            .iter()
            .flat_map(|e| {
                let p = e.path.as_str();
                p.match_indices('/').map(move |(i, _)| &p[..i]).chain([p])
            })
            .collect();
        if let Some(missing) = only.0.iter().find(|o| !known.contains(*o)) {
            bail!("not found in the sealbox: {missing:?}");
        }
    }
    let selected: Vec<&Entry> = entries.iter().filter(|e| only.contains(&e.path)).collect();
    check_layout(&selected)?;
    if !overwrite {
        let clashes: Vec<&str> = selected
            .iter()
            .filter(|e| e.kind == EntryKind::File)
            .filter(|e| fs::symlink_metadata(dest.join(&e.path)).is_ok())
            .take(5)
            .map(|e| e.path.as_str())
            .collect();
        if !clashes.is_empty() {
            bail!(
                "these already exist in {} (use --overwrite to replace them): {}",
                dest.display(),
                clashes.join(", ")
            );
        }
    }
    let needed: u64 = selected.iter().map(|e| e.size).sum();
    if let Some(free) = available_space(dest)
        && needed > free
    {
        bail!(
            "not enough free space in {}: need {}, only {} available",
            dest.display(),
            human_size(needed),
            human_size(free)
        );
    }

    // --- Stage everything ---------------------------------------------
    // Progress covers all data, since unselected files must be decrypted too.
    progress.reset(entries.iter().map(|e| e.size).sum());
    let dest_existed = dest.exists();
    fs::create_dir_all(dest).with_context(|| format!("cannot create {}", dest.display()))?;
    let mut created_dirs = Vec::new();
    let mut staged: Vec<Staged> = Vec::new();
    let mut summary = Summary::default();

    let result = (|| -> Result<()> {
        for e in &entries {
            let selected = only.contains(&e.path);
            let comps = sanitize_archive_path(&e.path)?;
            match e.kind {
                EntryKind::Dir => {
                    if selected {
                        ensure_dirs(dest, &comps, &mut created_dirs)?;
                        summary.dirs += 1;
                    }
                }
                EntryKind::File if !selected => skip_file(&mut r, e.size, progress)?,
                EntryKind::File => {
                    let (name, parents) = comps.split_last().unwrap();
                    let parent = ensure_dirs(dest, parents, &mut created_dirs)?;
                    let target = parent.join(name);
                    if let Ok(md) = fs::symlink_metadata(&target) {
                        if md.is_dir() {
                            bail!("{} exists and is a folder", target.display());
                        }
                        if !overwrite {
                            bail!("{} already exists", target.display());
                        }
                    }
                    let tmp = tempfile::Builder::new()
                        .prefix(".sealbox-part-")
                        .tempfile_in(&parent)
                        .with_context(|| format!("cannot write in {}", parent.display()))?;
                    // Keep only the path (no open handle per staged file, so
                    // huge sealboxes do not exhaust file descriptors).
                    let (f, tmp) = tmp.into_parts();
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
                    drop(f);
                    staged.push(Staged { tmp, target });
                    summary.files += 1;
                    summary.bytes += n;
                }
            }
        }
        // Everything decrypted fine and the end of the sealbox is
        // authenticated: only now move files into place.
        finish_payload(r)?;
        let total = staged.len();
        for (i, s) in staged.drain(..).enumerate() {
            let target = s.target;
            let res = if overwrite {
                s.tmp.persist(&target)
            } else {
                s.tmp.persist_noclobber(&target)
            };
            res.map_err(|e| e.error).with_context(|| {
                format!(
                    "cannot move {} into place ({i} of {total} files were already unsealed)",
                    target.display()
                )
            })?;
        }
        Ok(())
    })();

    if let Err(e) = result {
        drop(staged); // deletes all staged temp files
        for d in created_dirs.iter().rev() {
            let _ = fs::remove_dir(d);
        }
        if !dest_existed {
            let _ = fs::remove_dir(dest);
        }
        return Err(e);
    }
    Ok(summary)
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
    const PW: &[u8] = b"pw";

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

    fn p() -> Progress {
        Progress::default()
    }

    /// Build a sealbox by hand, bypassing all the checks `seal` does, the
    /// way an attacker would.
    fn craft(path: &Path, entries: &[(EntryKind, &str, &[u8])]) {
        let es: Vec<Entry> = entries
            .iter()
            .map(|(k, p, d)| Entry {
                kind: *k,
                path: p.to_string(),
                size: d.len() as u64,
                mode: 0o644,
                mtime: 0,
            })
            .collect();
        let f = File::create(path).unwrap();
        let mut w = EncryptWriter::new(f, PW, &FAST).unwrap();
        w.write_all(&[PAYLOAD_ZSTD]).unwrap();
        let mut z = zstd::Encoder::new(w, 3).unwrap();
        z.write_all(&encode_index(es.iter())).unwrap();
        for (_, _, d) in entries {
            z.write_all(d).unwrap();
        }
        z.finish().unwrap().finish().unwrap();
    }

    fn corrupt_tail(path: &Path) {
        let mut raw = fs::read(path).unwrap();
        let n = raw.len();
        raw[n - 5] ^= 0xff;
        fs::write(path, raw).unwrap();
    }

    #[test]
    fn compresses_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("log.txt");
        let text = "2026-11-13 INFO request handled in 12ms\n".repeat(100_000);
        fs::write(&src, &text).unwrap();
        let sb = tmp.path().join("v.sbx");
        let s = seal(&[src], &sb, PW, &FAST, 3, false, &p()).unwrap();
        assert!(
            s.sealbox_size < text.len() as u64 / 20,
            "sealbox {} bytes",
            s.sealbox_size
        );
        let out = tmp.path().join("out");
        unseal(&sb, PW, &FAST, &out, false, &[], &p()).unwrap();
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
    fn windows_names() {
        for bad in [
            "CON",
            "con.txt",
            "Nul",
            "aux.tar.gz",
            "COM1",
            "lpt9.log",
            "COM²",
            "a:b",
            "x?",
            "trail.",
            "trail ",
            "tab\t",
        ] {
            assert!(windows_name_problem(bad).is_some(), "{bad:?} accepted");
        }
        for ok in [
            "CONSOLE",
            "com10",
            "falcon.txt",
            "a b",
            ".hidden",
            "naïve.txt",
        ] {
            assert!(windows_name_problem(ok).is_none(), "{ok:?} rejected");
        }
    }

    #[test]
    fn full_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        fs::create_dir_all(src.join("docs/empty")).unwrap();
        fs::write(src.join("docs/a.txt"), b"hello").unwrap();
        let big = pseudo_random(3_000_000);
        fs::write(src.join("big.bin"), &big).unwrap();
        let single = tmp.path().join("note.md");
        fs::write(&single, b"# note").unwrap();

        let sb = tmp.path().join("out.sbx");
        let prog = p();
        let s = seal(&[src.clone(), single], &sb, PW, &FAST, 3, false, &prog).unwrap();
        assert_eq!(s.files, 3);
        assert_eq!(prog.fraction(), 1.0);

        let raw = fs::read(&sb).unwrap();
        assert!(!raw.windows(5).any(|w| w == b"a.txt"), "file name leaked");
        assert!(!raw.windows(5).any(|w| w == b"hello"), "content leaked");

        let names: Vec<String> = list_contents(&sb, PW, &FAST)
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert!(names.contains(&"src/docs/empty".to_string()));
        assert!(names.contains(&"note.md".to_string()));
        assert!(list_contents(&sb, b"wrong", &FAST).is_err());
        assert_eq!(verify(&sb, PW, &FAST, &p()).unwrap().files, 3);

        let out = tmp.path().join("out");
        unseal(&sb, PW, &FAST, &out, false, &[], &p()).unwrap();
        assert_eq!(fs::read(out.join("src/docs/a.txt")).unwrap(), b"hello");
        assert_eq!(fs::read(out.join("src/big.bin")).unwrap(), big);
        assert_eq!(fs::read(out.join("note.md")).unwrap(), b"# note");
        assert!(out.join("src/docs/empty").is_dir());

        // Second unseal refuses to clobber, then works with overwrite.
        assert!(unseal(&sb, PW, &FAST, &out, false, &[], &p()).is_err());
        unseal(&sb, PW, &FAST, &out, true, &[], &p()).unwrap();
        let leftovers = WalkDir::new(&out)
            .into_iter()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".sealbox-")
            })
            .count();
        assert_eq!(leftovers, 0, "staging files left behind");
        // Refuse to overwrite the sealbox itself without the flag.
        assert!(seal(std::slice::from_ref(&out), &sb, PW, &FAST, 3, false, &p()).is_err());
    }

    #[test]
    fn failed_unseal_leaves_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("d");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a"), vec![1u8; 10]).unwrap();
        fs::write(src.join("b"), pseudo_random(3_000_000)).unwrap();
        let sb = tmp.path().join("v.sbx");
        seal(&[src], &sb, PW, &FAST, 3, false, &p()).unwrap();
        corrupt_tail(&sb);
        let out = tmp.path().join("out");
        assert!(unseal(&sb, PW, &FAST, &out, false, &[], &p()).is_err());
        assert!(!out.exists(), "partial output left behind");
        assert!(verify(&sb, PW, &FAST, &p()).is_err());
    }

    #[test]
    fn failed_overwrite_keeps_existing_files() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("d");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a"), b"new").unwrap();
        fs::write(src.join("b"), pseudo_random(3_000_000)).unwrap();
        let sb = tmp.path().join("v.sbx");
        seal(&[src], &sb, PW, &FAST, 3, false, &p()).unwrap();
        corrupt_tail(&sb);

        let out = tmp.path().join("out");
        fs::create_dir_all(out.join("d")).unwrap();
        fs::write(out.join("d/a"), b"precious original").unwrap();
        assert!(unseal(&sb, PW, &FAST, &out, true, &[], &p()).is_err());
        assert_eq!(fs::read(out.join("d/a")).unwrap(), b"precious original");
        assert_eq!(
            fs::read_dir(out.join("d")).unwrap().count(),
            1,
            "staging files left behind"
        );
    }

    #[test]
    fn cancel_leaves_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("big");
        fs::write(&src, pseudo_random(2_000_000)).unwrap();
        let sb = tmp.path().join("v.sbx");
        let cancelled = p();
        cancelled.cancel.store(true, Ordering::Relaxed);
        assert!(
            seal(
                std::slice::from_ref(&src),
                &sb,
                PW,
                &FAST,
                3,
                false,
                &cancelled
            )
            .is_err()
        );
        assert_eq!(
            fs::read_dir(tmp.path()).unwrap().count(),
            1,
            "temp sealbox left behind"
        );

        seal(&[src], &sb, PW, &FAST, 3, false, &p()).unwrap();
        let out = tmp.path().join("out");
        assert!(unseal(&sb, PW, &FAST, &out, false, &[], &cancelled).is_err());
        assert!(!out.exists());
    }

    #[test]
    fn selective_unseal() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("d");
        fs::create_dir_all(src.join("keep/sub")).unwrap();
        fs::create_dir_all(src.join("skip")).unwrap();
        fs::write(src.join("keep/sub/x"), b"x").unwrap();
        fs::write(src.join("skip/y"), b"y").unwrap();
        fs::write(src.join("z"), b"z").unwrap();
        fs::write(src.join("keepsake"), b"not a child of keep").unwrap();
        let sb = tmp.path().join("v.sbx");
        seal(&[src], &sb, PW, &FAST, 3, false, &p()).unwrap();

        let out = tmp.path().join("out");
        let only = ["d/keep/".to_string(), "d/z".to_string()];
        let s = unseal(&sb, PW, &FAST, &out, false, &only, &p()).unwrap();
        assert_eq!(s.files, 2);
        assert!(out.join("d/keep/sub/x").exists());
        assert!(out.join("d/z").exists());
        assert!(!out.join("d/skip").exists());
        assert!(!out.join("d/keepsake").exists());
        assert!(unseal(&sb, PW, &FAST, &out, false, &["d/nope".into()], &p()).is_err());
    }

    #[test]
    fn add_to_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a.txt");
        let b = tmp.path().join("b");
        fs::write(&a, b"first").unwrap();
        fs::create_dir(&b).unwrap();
        fs::write(b.join("c.bin"), pseudo_random(500_000)).unwrap();
        let sb = tmp.path().join("v.sbx");
        seal(std::slice::from_ref(&a), &sb, PW, &FAST, 3, false, &p()).unwrap();

        let s = add(&sb, std::slice::from_ref(&b), PW, &FAST, 3, &p()).unwrap();
        assert_eq!((s.files, s.dirs), (1, 1));
        assert!(
            add(&sb, &[a], PW, &FAST, 3, &p()).is_err(),
            "duplicate name accepted"
        );
        assert!(add(&sb, std::slice::from_ref(&b), b"wrong", &FAST, 3, &p()).is_err());

        let out = tmp.path().join("out");
        unseal(&sb, PW, &FAST, &out, false, &[], &p()).unwrap();
        assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"first");
        assert_eq!(
            fs::read(out.join("b/c.bin")).unwrap(),
            fs::read(b.join("c.bin")).unwrap()
        );
    }

    #[test]
    fn rejects_malicious_layouts() {
        let tmp = tempfile::tempdir().unwrap();
        let cases: [&[(EntryKind, &str, &[u8])]; 3] = [
            &[(EntryKind::File, "x", b"1"), (EntryKind::File, "x", b"2")],
            &[(EntryKind::File, "x", b"1"), (EntryKind::File, "x/y", b"2")],
            &[(EntryKind::File, "../escape", b"1")],
        ];
        for (i, entries) in cases.iter().enumerate() {
            let sb = tmp.path().join(format!("{i}.sbx"));
            craft(&sb, entries);
            let out = tmp.path().join(format!("out{i}"));
            assert!(
                unseal(&sb, PW, &FAST, &out, true, &[], &p()).is_err(),
                "case {i}"
            );
            assert!(!out.exists(), "case {i} wrote output");
        }
        assert!(!tmp.path().join("escape").exists());
    }

    #[cfg(unix)]
    #[test]
    fn does_not_write_through_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("d");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("f"), b"payload").unwrap();
        let sb = tmp.path().join("v.sbx");
        seal(&[src], &sb, PW, &FAST, 3, false, &p()).unwrap();

        let out = tmp.path().join("out");
        let elsewhere = tmp.path().join("elsewhere");
        fs::create_dir_all(&out).unwrap();
        fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, out.join("d")).unwrap();
        assert!(unseal(&sb, PW, &FAST, &out, true, &[], &p()).is_err());
        assert!(!elsewhere.join("f").exists());
    }
}
