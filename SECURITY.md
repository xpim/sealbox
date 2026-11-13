# Security policy

Sealbox protects people's files, so security reports get priority.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub:
open the repository's **Security** tab and choose **Report a vulnerability**
(private vulnerability reporting).

Please include:

* what the problem is and what an attacker could achieve;
* steps or a proof of concept to reproduce it;
* the Sealbox version (`sealbox --version`) and your operating system.

Never send a sealbox containing real data, or a real password.

You can expect an acknowledgement within a week. Once a fix is released, the
issue will be disclosed in a GitHub security advisory, crediting you unless
you prefer otherwise.

## Supported versions

Security fixes go into the latest release. Sealbox is pre-1.0, so please
update to the newest version before reporting.

## Scope

In scope, for example:

* recovering any contents of a sealbox (file names, sizes, data) without the
  password, or learning more than the documented size leakage;
* modifying a sealbox without detection;
* a malicious sealbox that, when listed, verified or unsealed, writes outside
  the chosen folder, follows symlinks, overwrites files without permission,
  or crashes or hangs Sealbox;
* weaknesses in key derivation, encryption or the use of randomness.

Out of scope:

* guessing weak passwords. Sealbox enforces a strength policy and uses
  Argon2id, but no tool can protect a guessable password;
* attackers who already control the computer while you use Sealbox
  (malware, keyloggers, reading memory);
* the size of a sealbox revealing the approximate size of its contents (see
  "Limitations" below).

## Status and limitations

**Sealbox has not had an independent security audit.** It uses well-reviewed
building blocks (Argon2id, XChaCha20-Poly1305 in the STREAM construction,
from the RustCrypto project) and does not implement its own cryptographic
primitives. The file format is documented in [FORMAT.md](FORMAT.md), with
test vectors confirmed against independent implementations. Still, judge
for yourself whether that is enough for your use.

Known limitations:

* **Size:** a sealbox's size reveals the approximate (padded) size of its
  compressed contents.
* **Memory:** passwords and decrypted data are wiped from memory where
  practical, but not every copy can be guaranteed to be erased (e.g. by the
  operating system, the GUI toolkit or swap).
* **Environment variable:** `SEALBOX_PASSWORD` can be visible to other
  processes of the same user. Prefer the interactive prompt or
  `--password-stdin`.
* **Unsigned binaries:** release binaries are not code-signed. Verify
  downloads with the published checksums and build attestations (see the
  README).
