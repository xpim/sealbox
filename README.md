# The Vault

Drag files and folders into a window, pick a password, and save everything as a
single encrypted `.vault` file. Open the vault again with the same password to
get your files back. It runs on Windows, Linux and macOS, with both a GUI and a
CLI, from one self-contained binary.

## Build

Install Rust from https://rustup.rs, then:

```sh
cargo build --release
# binary: target/release/vault  (vault.exe on Windows)
```

Build on each OS to get a native binary for it. The included GitHub Actions
workflow (`.github/workflows/build.yml`) builds and tests all three on every push.

## GUI

Run `vault` with no arguments (or double-click it).

* **Create:** drag files and folders into the window (or use *Add files…* /
  *Add folder…*), enter the password twice, then click **Save as vault…**.
* **Open:** drop a `.vault` file onto the window, or use **Open vault…**. Enter
  the password to see the contents, then click **Extract all to…**.

`vault some.vault` opens the GUI with that vault, so you can associate the
`.vault` extension with the binary in your OS.

## CLI

```sh
vault create -o backup.vault ~/Documents/taxes notes.txt   # asks for password twice
vault list backup.vault
vault extract backup.vault -o ./restored                  # --overwrite to replace files
```

For scripts, pass the password via `--password-stdin` or the `VAULT_PASSWORD`
environment variable instead of the interactive prompt. Note that environment
variables can be visible to other processes of the same user.

## Security design

| Part | Choice |
|---|---|
| Key derivation | **Argon2id** (memory-hard), 256 MiB, 3 passes, 4 lanes, random 32-byte salt per vault |
| Encryption | **XChaCha20-Poly1305** AEAD in the **STREAM** construction, 1 MiB chunks, random nonce per vault |
| Integrity | Every chunk is authenticated. Reordering, truncating, appending or flipping any bit, header included, is detected |
| Metadata | File names, folder structure, sizes and counts live **inside** the encrypted payload. Total size is padded (Padmé) so the vault size reveals little |
| Anonymity | No magic number, version or parameter block: every byte is random salt/nonce or ciphertext, so the file doesn't reveal which program made it |
| Implementation | Audited RustCrypto crates (`argon2`, `chacha20poly1305`), no custom crypto primitives |

Someone who has a `.vault` file but not the password sees only random
bytes: nothing in the file identifies it as a vault or names this program.
The `.vault` file name extension is the only hint, and you can rename the file
freely. The GUI and the `vault some.vault` shortcut use the extension to
recognise vaults, but `vault list`/`extract` accept any file name. With the password they can't get the data back except by guessing it,
and Argon2id makes each guess expensive. **Use a strong passphrase:** that is
the one thing the encryption cannot fix for you. There is no recovery if the
password is lost.

Extraction is hardened against malicious vaults. It rejects absolute paths,
`..` and other path tricks, it never writes through symlinks, and it refuses to
overwrite existing files unless asked. If decryption fails partway through,
everything already written is removed again. Vaults are written to a temporary
file and moved into place only when complete.

### File format (v1)

```
salt[32] | nonce_prefix[19] | STREAM ciphertext chunks...
```

There is no header beyond the random salt and nonce. The format parameters
(Argon2id 256 MiB / 3 passes / 4 lanes, 1 MiB chunks) are fixed constants of
v1, not stored in the file. A future format version would be detected by trial
decryption rather than by a version field. The decrypted payload is an index (paths, sizes, mtimes, permissions), then
the file data, then padding. See `src/crypto.rs` and `src/archive.rs`.

## Tests

```sh
cargo test --release
```
