# Changelog

All notable changes to Sealbox are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Sealbox uses
[Semantic Versioning](https://semver.org/) (see CONTRIBUTING.md).

## [Unreleased]

## [0.1.0] - 2026-11-14

First public release.

### Added

- Seal files and folders into a single encrypted `.sbx` file, and unseal
  them again, from a GUI (drag and drop) or the CLI.
- Argon2id key derivation and XChaCha20-Poly1305 (STREAM) encryption. Every
  byte is authenticated, and file names, sizes and structure are encrypted.
- No identifying header: a sealbox is indistinguishable from random data.
- zstd compression before encryption, with Padmé padding of the result.
- `unseal` for selected paths, `add` to an existing sealbox, `verify`
  without unsealing, and `list`.
- GUI: selective unseal, add and verify, password strength meter, and a
  progress bar with cancel.
- A version header inside the encryption: sealboxes record which Sealbox
  version created them, and newer sealboxes name the version they need.
- `sealbox-gui`, a GUI-only binary that opens without a console window on
  Windows.

### Security

- Unsealing is staged and atomic: damaged or tampered sealboxes, cancels and
  full disks leave nothing behind and never destroy existing files.
- Malicious sealboxes are rejected before anything is written: path
  traversal, symlinks, duplicate or case-colliding paths, Windows-reserved
  names, and oversized indexes.
- Strong passwords are required (zxcvbn score of 3 or more), and passwords
  are Unicode-normalised so they work across operating systems.
