# Contributing to Sealbox

Thanks for your interest! Bug reports, ideas and pull requests are welcome.
For security problems, follow [SECURITY.md](SECURITY.md) instead of opening an
issue.

## Building and testing

You need Rust (see `rust-version` in `Cargo.toml` for the minimum) and a C
compiler (for the bundled zstd library).

```sh
cargo build                     # debug build
cargo run                       # start the GUI
cargo run -- seal --help        # use the CLI
cargo test                      # all tests, including format test vectors
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo deny check                # optional: dependency advisories and licenses
```

CI runs all of these on Linux, Windows and macOS for every pull request.

## Code layout

| File | What it does |
|---|---|
| `src/crypto.rs` | Outer layer: Argon2id key derivation and STREAM encryption |
| `src/archive.rs` | Payload: version header, index, sealing, unsealing, adding, verifying |
| `src/cli.rs` | Command-line interface (clap) |
| `src/gui.rs` | Graphical interface (egui/eframe) |
| `src/bin/sealbox-gui.rs` | GUI-only launcher (no console window on Windows) |
| `tests/format_v1.rs` | Format guards and test vectors |
| `FORMAT.md` | File format specification |

## Guidelines

* **Commits** follow [Conventional Commits](https://www.conventionalcommits.org/):
  `feat: …`, `fix: …`, `docs: …`, `refactor: …`, with `!` for breaking
  changes (`feat!: …`). The commit types drive the version bump (see below).
* **Tests:** add tests for new behaviour and bug fixes. Unsealing code in
  particular must stay safe against malicious sealboxes.
* **Changelog:** add user-visible changes to `CHANGELOG.md` under
  *Unreleased*.
* **The file format is a promise.** Changes to what is written to or read
  from `.sbx` files must follow the versioning rules in
  [FORMAT.md](FORMAT.md). The v1 test vectors in `tests/format_v1.rs` must
  keep passing unchanged: existing sealboxes must always open. Never
  regenerate them to make a test pass.
* **No custom cryptography.** Use established, reviewed primitives.

## Versioning

There are two independent version numbers:

* **The app version** (`version` in `Cargo.toml`) follows
  [Semantic Versioning](https://semver.org/):
  * **major:** older Sealbox versions can no longer open new sealboxes, or a
    CLI command or option is removed or renamed;
  * **minor:** new features, including compatible format additions;
  * **patch:** bug fixes only.

  Before 1.0, breaking changes bump the minor version instead (0.1 → 0.2).
  Version 1.0 means: format 1 is final, and every 1.x release opens every
  sealbox made by any 1.x release.
* **The file format version** (`FORMAT`, `MIN_READER_FORMAT`,
  `MIN_READER_APP` in `src/archive.rs`) changes only when the file layout
  changes, following FORMAT.md.

## Releasing (maintainers)

1. Decide the version from the commits since the last tag (`feat` → minor,
   `fix` → patch, `!` → major; before 1.0, `!` → minor).
2. Set `version` in `Cargo.toml` and run `cargo build` to update
   `Cargo.lock`.
3. In `CHANGELOG.md`, rename *Unreleased* to `## [X.Y.Z] - YYYY-MM-DD` and
   add a fresh, empty *Unreleased* section above it.
4. Commit (`chore(release): vX.Y.Z`), tag and push:

   ```sh
   git tag -a vX.Y.Z -m "Sealbox X.Y.Z"
   git push origin main vX.Y.Z
   ```

The release workflow then checks that the tag matches `Cargo.toml` and the
changelog, runs the tests, and builds archives for Linux, Windows and macOS
(Apple Silicon and Intel). It also generates the third-party license notices
and publishes a GitHub Release with SHA-256 checksums and build provenance
attestations. Releases below 1.0 are marked as pre-releases.
