//! Format guards for sealbox format v1. See FORMAT.md.
//!
//! These tests pin the on-disk format. If one fails, you changed the format.
//! That may be intended, but then it must be a deliberate, versioned change:
//! bump `FORMAT` / `MIN_READER_FORMAT` / `MIN_READER_APP` in `archive.rs` as
//! described in FORMAT.md, and keep the v1 vectors passing (old sealboxes
//! must keep opening). Never "fix" these tests by regenerating the vectors.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use sealbox::archive::{self, EntryKind, Progress};
use sealbox::crypto::{DecryptReader, EncryptWriter, SealParams};

const PASSWORD: &[u8] = b"correct horse battery staple";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// Known-answer test for the outer (crypto) layer, also listed in FORMAT.md.
// Independently reproduced with argon2-cffi + libsodium (PyNaCl).
const KAT_PLAINTEXT: &[u8] = b"Sealbox format v1 known-answer test\n";
const KAT_SEALBOX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                           202122232425262728292a2b2c2d2e2f303132\
                           2580b1c97fa306ed00d2d629d68767741cf14193a552fe373cba0014fa131428\
                           ed6c92caef01c7e4b7d4b9cbb7a6d4706e1311f8";

fn kat_salt() -> [u8; 32] {
    std::array::from_fn(|i| i as u8)
}

fn kat_nonce() -> [u8; 19] {
    std::array::from_fn(|i| 0x20 + i as u8)
}

#[test]
fn crypto_layer_known_answer_encrypt() {
    let params = SealParams::default();
    let mut w =
        EncryptWriter::with_salt_and_nonce(Vec::new(), PASSWORD, &params, kat_salt(), kat_nonce())
            .unwrap();
    w.write_all(KAT_PLAINTEXT).unwrap();
    assert_eq!(hex(&w.finish().unwrap()), KAT_SEALBOX);
}

#[test]
fn crypto_layer_known_answer_decrypt() {
    let ct = unhex(KAT_SEALBOX);
    let mut r = DecryptReader::new(&ct[..], PASSWORD, &SealParams::default()).unwrap();
    let mut pt = Vec::new();
    r.read_to_end(&mut pt).unwrap();
    assert_eq!(pt, KAT_PLAINTEXT);
}

#[test]
fn format_constants_are_v1() {
    // A newly written sealbox must carry exactly this version header. If you
    // change the format on purpose, update FORMAT.md and add new vectors.
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("f.txt");
    fs::write(&src, b"x").unwrap();
    let sb = tmp.path().join("new.sbx");
    let params = SealParams::default();
    archive::seal(
        &[src],
        &sb,
        PASSWORD,
        &params,
        3,
        false,
        &Progress::default(),
    )
    .unwrap();
    let info = archive::list_contents(&sb, PASSWORD, &params).unwrap().info;
    assert_eq!(info.format, 1, "payload format changed");
    assert_eq!(info.min_format, 1, "minimum reader format changed");
    assert_eq!(info.min_app, "0.1.0", "minimum reader version changed");
    assert_eq!(info.created_with, archive::APP_VERSION);
}

/// A real sealbox written by Sealbox 0.1.0. Every future version must open it.
#[test]
fn frozen_v1_sealbox_still_opens() {
    let sb = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/v1-sample.sbx");
    let params = SealParams::default();

    let contents = archive::list_contents(&sb, PASSWORD, &params).unwrap();
    assert_eq!(contents.info.format, 1);
    assert_eq!(contents.info.created_with, "0.1.0");
    let listing: Vec<(EntryKind, &str, u64, i64)> = contents
        .entries
        .iter()
        .map(|e| (e.kind, e.path.as_str(), e.size, e.mtime))
        .collect();
    let t = 1_767_225_600; // 2026-01-01T00:00:00Z
    assert_eq!(
        listing,
        [
            (EntryKind::Dir, "sample", 0, t),
            (EntryKind::Dir, "sample/docs", 0, t),
            (EntryKind::Dir, "sample/docs/empty", 0, t),
            (EntryKind::File, "sample/docs/notes.md", 39, t),
            (EntryKind::File, "sample/hello.txt", 16, t),
        ]
    );

    archive::verify(&sb, PASSWORD, &params, &Progress::default()).unwrap();

    let out = tempfile::tempdir().unwrap();
    archive::unseal(
        &sb,
        PASSWORD,
        &params,
        out.path(),
        false,
        &[],
        &Progress::default(),
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(out.path().join("sample/hello.txt")).unwrap(),
        "Hello, Sealbox!\n"
    );
    assert_eq!(
        fs::read_to_string(out.path().join("sample/docs/notes.md")).unwrap(),
        "# Notes\n\nFrozen format v1 test vector.\n"
    );
    assert!(out.path().join("sample/docs/empty").is_dir());
}
