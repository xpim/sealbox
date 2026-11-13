# Sealbox file format, version 1

This document specifies the `.sbx` format precisely enough to write an
independent, compatible implementation. The reference implementation is in
`src/crypto.rs` (outer layer) and `src/archive.rs` (payload). All integers
are little-endian unless stated otherwise.

A sealbox has two layers:

1. an **outer layer**, which encrypts and authenticates a byte stream (the
   *payload*) with a password;
2. the **payload**, which holds a version header, the list of files and
   folders, and their contents.

Design goal: without the password, a sealbox is indistinguishable from random
bytes. There is no magic number, version field or parameter block on disk.

## 1. Outer layer

```
offset  size  field
0       32    salt          random
32      19    nonce prefix  random
51      ...   ciphertext chunks
```

### Key derivation

```
key = Argon2id(password, salt, m = 262144 KiB (256 MiB), t = 3, p = 4,
               version = 0x13, output length = 32 bytes)
```

If the password is valid UTF-8, it is first converted to Unicode
Normalization Form C (NFC). Otherwise its raw bytes are used. ASCII passwords
are unaffected.

These parameters are not stored in the file. They are fixed for this outer
layer (see [Versioning](#4-versioning-rules)).

### Encryption

The payload is split into chunks of **1 MiB (1,048,576 bytes)** of plaintext.
Every chunk except the last is exactly 1 MiB. The last chunk holds 0 to 1 MiB
and is always present, even if empty.

Each chunk is encrypted with **XChaCha20-Poly1305** (IETF variant, 24-byte
nonce, 16-byte tag appended), using the
[STREAM](https://eprint.iacr.org/2015/189) construction, "BE32" flavour:

```
nonce(i) = nonce_prefix (19 bytes) || u32 big-endian i || last_flag (1 byte)
last_flag = 0x01 for the final chunk, 0x00 otherwise
aad       = the 51-byte header (salt || nonce prefix), for every chunk
```

`i` is the chunk index, starting at 0. So a full ciphertext chunk is
1,048,592 bytes. A reader knows a chunk is the last one when the end of the
file follows it. Any authentication failure means a wrong password, damage,
tampering, truncation, appended data, or different outer-layer parameters
(e.g. a newer Sealbox). These cases cannot be told apart, by design.

## 2. Payload

The decrypted payload is:

```
version header
body (depends on the format in the version header; format 1 below)
padding
```

### 2.1 Version header

This layout is **frozen for all future versions**, so that any Sealbox can
read the version header of any sealbox:

```
u32  N                header length in bytes (4 <= N <= 65536)
N bytes:
  u16  format         payload format this sealbox was written in
  u16  min_format     oldest reader format able to read it
  u8   len, then len bytes UTF-8   Sealbox version that created it ("0.1.0")
  u8   len, then len bytes UTF-8   first Sealbox version able to read it
  ...                 future fields; readers MUST ignore unknown trailing bytes
```

A reader that supports formats up to `R` MUST refuse a sealbox with
`min_format > R`, and SHOULD tell the user the required Sealbox version (the
fourth field). If `format > R` but `min_format <= R`, the reader proceeds and
interprets the body as format `R`. The version strings are informational;
readers should tolerate them being missing.

### 2.2 Format 1 body

A single [zstd](https://www.rfc-editor.org/rfc/rfc8878) frame. Content
checksums are not needed, because the outer layer authenticates everything.
Decompressed, it contains:

```
"TVIDX001"            8-byte index magic
u64   count           number of entries
count × entry:
  u8    kind          1 = folder, 2 = file
  u32   path length
  bytes path          UTF-8, relative, '/'-separated
  u32   mode          Unix permission bits (0 = unknown)
  i64   mtime         modification time, seconds since the Unix epoch
  u64   size          file size in bytes (0 for folders)
file data             contents of all file entries, concatenated in index order
```

Rules for writers:

* Every path component is non-empty, is not `.` or `..`, and contains no
  `/`, `\` or NUL.
* Each top-level item is stored under its own name, and paths are unique.
* Folders are listed before their contents. Readers must not rely on this.

Readers MUST validate paths and SHOULD reject sealboxes with duplicate paths
or paths used both as a file and as a folder. The reference implementation
also limits entries to 5,000,000, a path to 32 KiB and all paths together to
256 MiB.

### 2.3 Padding

After the zstd frame, zero bytes are appended until the payload length is
`padme(L)`, where `L` is the length of version header plus body:

```
padme(L) = L                                  if L < 2
E = floor(log2 L);  S = floor(log2 E) + 1;  mask = 2^(E - S) - 1
padme(L) = (L + mask) & ~mask
```

Readers must ignore the padding, but must read the payload through to its end:
only then is the final chunk authenticated, proving the file was not
truncated.

## 3. Test vectors

### Outer layer (known answer)

```
password      "correct horse battery staple"
salt          000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
nonce prefix  202122232425262728292a2b2c2d2e2f303132
plaintext     "Sealbox format v1 known-answer test\n"   (36 bytes, one chunk)
sealbox       000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
              202122232425262728292a2b2c2d2e2f303132
              2580b1c97fa306ed00d2d629d68767741cf14193a552fe373cba0014fa131428
              ed6c92caef01c7e4b7d4b9cbb7a6d4706e1311f8
```

This vector was reproduced independently with argon2-cffi and libsodium.

### Complete sealbox

`tests/vectors/v1-sample.sbx` was written by Sealbox 0.1.0 with the password
`correct horse battery staple`. It contains:

```
kind    path                    size  mtime
folder  sample                     0  1767225600
folder  sample/docs                0  1767225600
folder  sample/docs/empty          0  1767225600
file    sample/docs/notes.md      39  1767225600   "# Notes\n\nFrozen format v1 test vector.\n"
file    sample/hello.txt          16  1767225600   "Hello, Sealbox!\n"
```

Both vectors are checked by `tests/format_v1.rs`.

## 4. Versioning rules

* **Outer layer:** keep it stable. If it ever has to change, readers must
  also try the old parameters (trial decryption) so existing sealboxes keep
  opening.
* **Version header:** frozen layout. New fields may only be appended.
* **Compatible payload changes** (old readers still work, e.g. a new header
  field): raise `format`, keep `min_format` and the minimum version.
* **Breaking payload changes:** raise `format` and `min_format`, and set the
  minimum Sealbox version to the release that introduces it.
* **Old formats stay readable:** never drop support for reading an older
  format, and keep its test vectors passing.
