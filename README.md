# Sealbox

Drag files and folders into a window, pick a password, and seal everything into
a single encrypted `.sbx` file. Unseal it with the same password to get your
files back. It runs on Windows, Linux and macOS, with both a GUI and a CLI.

> **Status:** pre-1.0 and **not independently audited**. See
> [SECURITY.md](SECURITY.md) for what that means and how to report problems.

## Install

Download the archive for your system from the
[Releases page](https://github.com/xpim/sealbox/releases), unpack it and run `sealbox-gui` (or `sealbox` for the CLI). Each
archive contains both programs, this README, the license and the licenses of
the bundled open-source components.

The Linux build runs on any x86-64 distribution with glibc 2.28 or newer
(Debian 10+, Ubuntu 20.04+, RHEL 8+, Fedora 29+). Windows builds are for
x86-64, macOS builds for Apple Silicon and Intel.

### Verify the download

Every release lists SHA-256 checksums (`SHA256SUMS.txt`) and has a build
attestation proving it was built from this repository by GitHub Actions:

```sh
sha256sum -c SHA256SUMS.txt --ignore-missing      # macOS: shasum -a 256 -c …
gh attestation verify sealbox-v0.1.0-x86_64-unknown-linux-gnu.tar.gz --repo xpim/sealbox
```

### Opening an unsigned app

The binaries are not code-signed (signing requires paid certificates), so
your system warns the first time you open them:

* **macOS:** right-click `sealbox-gui` → **Open** → **Open**. Or remove the
  quarantine flag: `xattr -d com.apple.quarantine sealbox sealbox-gui`.
* **Windows:** in the SmartScreen dialog, click **More info** → **Run anyway**.
* **Linux:** no warning. If needed, run `chmod +x sealbox sealbox-gui`.

## Build from source

Install Rust 1.95 or newer from https://rustup.rs. You also need a C compiler for the bundled
zstd library; the standard Rust setup already provides one (MSVC Build Tools on
Windows, Xcode Command Line Tools on macOS, gcc/clang on Linux). Then:

```sh
cargo build --release
```

This builds two binaries in `target/release/`:

* `sealbox` (`sealbox.exe`): CLI and GUI in one.
* `sealbox-gui` (`sealbox-gui.exe`): GUI only. On Windows it opens without a
  console window, so use this one for double-clicking and for associating
  `.sbx` files.

Build on each OS to get a native binary for it. CI tests all three on every
push, and tagged versions are released automatically (see
[CONTRIBUTING.md](CONTRIBUTING.md)).

## GUI

Run `sealbox-gui` (or `sealbox` with no arguments).

* **Seal:** drag files and folders into the window (or use *Add files…* /
  *Add folder…*), enter the password twice, then click **Seal…**. A meter
  shows how strong the password is; weak passwords are refused.
* **Open:** drop a `.sbx` file onto the window, or use **Open sealbox…**, and
  enter the password to see the contents. Then:
  * **Unseal all to…**, or tick files/folders and **Unseal N selected to…**
  * **Add files…** / **Add folder…**, or drop files onto the open sealbox
  * **Verify** checks the whole sealbox is intact without unsealing it

Closing the window during a job cancels it safely first. Files dropped while
a job runs are handled when it finishes.

`sealbox-gui some.sbx` opens the GUI with that sealbox, so you can associate
the `.sbx` extension with it in your OS.

## CLI

```sh
sealbox seal -o backup.sbx ~/Documents/taxes notes.txt   # asks for password twice
sealbox seal -l 19 -o small.sbx ~/Documents             # max compression (1-19, default 3)
sealbox list backup.sbx
sealbox unseal backup.sbx -o ./restored                 # --overwrite to replace files
sealbox unseal backup.sbx taxes/2025 notes.txt -o ./r   # only these paths
sealbox add backup.sbx receipts/                         # add to an existing sealbox
sealbox verify backup.sbx                                # check integrity, write nothing
```

`create` and `extract` work as aliases for `seal` and `unseal`. Press Ctrl+C
to cancel a running job: it stops cleanly and leaves nothing half-written.

For scripts, pass the password via `--password-stdin` or the `SEALBOX_PASSWORD`
environment variable instead of the interactive prompt. Note that environment
variables can be visible to other processes of the same user.

## Security design

| Part | Choice |
|---|---|
| Key derivation | **Argon2id** (memory-hard), 256 MiB, 3 passes, 4 lanes, random 32-byte salt per sealbox |
| Compression | **zstd** (level 3 by default), applied *before* encryption, since encrypted data does not compress |
| Encryption | **XChaCha20-Poly1305** AEAD in the **STREAM** construction, 1 MiB chunks, random nonce per sealbox |
| Integrity | Every chunk is authenticated. Reordering, truncating, appending or flipping any bit, header included, is detected |
| Metadata | File names, folder structure, sizes and counts live **inside** the encrypted payload. The compressed size is padded (Padmé) so the sealbox size reveals little |
| Anonymity | No magic number, version or parameter block: every byte is random salt/nonce or ciphertext, so the file doesn't reveal which program made it |
| Implementation | Audited RustCrypto crates (`argon2`, `chacha20poly1305`), no custom crypto primitives |

Someone who has a `.sbx` file but not the password sees only random bytes:
nothing in the file identifies it as a sealbox or names this program. The
`.sbx` file name extension is the only hint, and you can rename the file
freely. The GUI and the `sealbox some.sbx` shortcut use the extension to
recognise sealboxes, but `sealbox list`/`unseal` accept any file name.

Without the password, the only way to get the data back is to guess it, and
Argon2id makes each guess expensive. New sealboxes therefore require a strong
password: at least 8 characters and a [zxcvbn](https://github.com/dropbox/zxcvbn)
score of 3 or more (which rejects common passwords, keyboard patterns and the
like). Passwords are Unicode-normalised (NFC), so the same password works no
matter which OS or keyboard typed it. There is no recovery if the password is
lost.

Unsealing is hardened against malicious or damaged sealboxes:

* **Staged:** every file is written under a temporary name and moved into
  place only after the *whole* sealbox has been decrypted and authenticated.
  A damaged sealbox, a cancel or a full disk leaves nothing behind and never
  destroys existing files, even with `--overwrite`.
* **Checked up front:** absolute paths, `..`, duplicate paths (including
  case-only differences on Windows/macOS), files that are also used as folders,
  names Windows cannot represent (`CON`, `a:b`, trailing dots, …) and missing
  disk space are all rejected before anything is written.
* **No symlink tricks:** it never writes through symlinks, never restores
  setuid/setgid bits, and refuses to overwrite existing files unless asked.
* **Bounded:** the file list a sealbox may claim is capped, so a malicious
  sealbox cannot exhaust memory.

Sealing and adding write to a temporary file that replaces the target only
when complete, so a sealbox is never half-written. Adding verifies the whole
existing sealbox before replacing it.

### File format

The `.sbx` format is fully specified in [FORMAT.md](FORMAT.md), with test
vectors. In short: a random salt and nonce, then ciphertext. Inside the
encryption there is a version header, a zstd-compressed list of files with
their contents, and padding.

### Versions and compatibility

`sealbox list` (and the GUI) shows which Sealbox version created a sealbox.

* **Newer sealbox, older Sealbox:** if a future format change is something an
  older Sealbox cannot handle, it says exactly which version is needed, e.g.
  *"this sealbox was created with Sealbox 2.3.0 and needs Sealbox 2.0.0 or
  newer to open it (this is Sealbox 1.4.0)"*. Changes that older versions can
  still read (new header fields) keep working with them.
* **The one exception:** the version header is inside the encryption, so a
  future change to the *outer* layer cannot be reported this way: an old
  Sealbox cannot decrypt the file far enough to read it. The error then lists
  "made by a newer version of Sealbox" as one of the possible causes, next to
  a wrong password or damage. To avoid this, the outer layer is kept stable.
  If it ever has to change, newer versions will keep opening older sealboxes.

## Contributing

Bug reports, ideas and pull requests are welcome; see
[CONTRIBUTING.md](CONTRIBUTING.md). Report security problems privately as
described in [SECURITY.md](SECURITY.md). Changes are listed in
[CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE). Release archives include the licenses of all bundled
third-party components (`THIRD_PARTY_LICENSES.html`).
