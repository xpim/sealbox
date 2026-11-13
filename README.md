# Sealbox

Drag files and folders into a window, pick a password, and seal everything into
a single encrypted `.sbx` file. Unseal it with the same password to get your
files back. It runs on Windows, Linux and macOS, with both a GUI and a CLI, from
one self-contained binary.

## Build

Install Rust from https://rustup.rs. You also need a C compiler for the bundled
zstd library; the standard Rust setup already provides one (MSVC Build Tools on
Windows, Xcode Command Line Tools on macOS, gcc/clang on Linux). Then:

```sh
cargo build --release
# binary: target/release/sealbox  (sealbox.exe on Windows)
```

Build on each OS to get a native binary for it. The included GitHub Actions
workflow (`.github/workflows/build.yml`) builds and tests all three on every push.

## GUI

Run `sealbox` with no arguments (or double-click it).

* **Seal:** drag files and folders into the window (or use *Add files…* /
  *Add folder…*), enter the password twice, then click **Seal…**.
* **Unseal:** drop a `.sbx` file onto the window, or use **Open sealbox…**.
  Enter the password to see the contents, then click **Unseal all to…**.

`sealbox some.sbx` opens the GUI with that sealbox, so you can associate the
`.sbx` extension with the binary in your OS.

## CLI

```sh
sealbox seal -o backup.sbx ~/Documents/taxes notes.txt   # asks for password twice
sealbox seal -l 19 -o small.sbx ~/Documents             # max compression (1-19, default 3)
sealbox list backup.sbx
sealbox unseal backup.sbx -o ./restored                 # --overwrite to replace files
```

`create` and `extract` work as aliases for `seal` and `unseal`.

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
Argon2id makes each guess expensive. **Use a strong passphrase:** that is the
one thing the encryption cannot fix for you. There is no recovery if the
password is lost.

Unsealing is hardened against malicious sealboxes. It rejects absolute paths,
`..` and other path tricks, it never writes through symlinks, and it refuses to
overwrite existing files unless asked. If decryption fails partway through,
everything already written is removed again. Sealboxes are written to a
temporary file and moved into place only when complete.

### File format (v1)

```
salt[32] | nonce_prefix[19] | STREAM ciphertext chunks...
```

There is no header beyond the random salt and nonce. The format parameters
(Argon2id 256 MiB / 3 passes / 4 lanes, 1 MiB chunks) are fixed constants of
v1, not stored in the file. A future format version would be detected by trial
decryption rather than by a version field.

The decrypted payload is a one-byte payload format marker (`1` = zstd), a zstd
frame holding the index (paths, sizes, mtimes, permissions) followed by the
file data, and then padding. The marker is encrypted, so it is invisible on
disk. See `src/crypto.rs` and `src/archive.rs`.

## Tests

```sh
cargo test --release
```
