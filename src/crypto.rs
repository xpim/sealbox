//! Encrypted container layer of the `.vault` format.
//!
//! On-disk layout (all integers little-endian):
//!
//! ```text
//! offset  size  field
//! 0       8     magic  "THEVAULT"
//! 8       2     format version (1)
//! 10      1     KDF id (1 = Argon2id v1.3)
//! 11      4     Argon2 memory cost in KiB
//! 15      4     Argon2 time cost (iterations)
//! 19      4     Argon2 parallelism
//! 23      32    random salt
//! 55      19    random STREAM nonce prefix
//! 74      4     plaintext chunk size
//! 78      ...   ciphertext chunks
//! ```
//!
//! The key is derived from the password with Argon2id. The payload is
//! encrypted with XChaCha20-Poly1305 in the STREAM construction (Hoang,
//! Reyhanitabar, Rogaway, Vizár 2015). Every chunk is authenticated and
//! carries its position, plus a flag for the final chunk, in its nonce. So
//! reordering, dropping, truncating or appending chunks is detected. The whole
//! header is bound to every chunk as associated data, so tampering with the
//! header is detected too.
//!
//! Nothing about the contents is stored in plaintext. File names, sizes,
//! counts and data all live inside the encrypted payload.

use std::io::{self, Read, Write};

use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::{KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use rand::RngCore;
use rand::rngs::OsRng;
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8; 8] = b"THEVAULT";
pub const FORMAT_VERSION: u16 = 1;
const KDF_ARGON2ID: u8 = 1;
pub const HEADER_LEN: usize = 78;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 19; // 24-byte XChaCha nonce minus 5 bytes STREAM counter/flag
const TAG_LEN: usize = 16;
pub const DEFAULT_CHUNK_SIZE: u32 = 1024 * 1024;

/// Upper bounds accepted when *reading* a header, so that a malicious file
/// cannot make us allocate absurd amounts of memory or spin forever.
const MAX_M_COST_KIB: u32 = 4 * 1024 * 1024; // 4 GiB
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u32 = 64;
const MAX_CHUNK_SIZE: u32 = 64 * 1024 * 1024;

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// 256 MiB, 3 passes, 4 lanes. Takes roughly half a second to a second on a
    /// modern machine, which makes guessing passwords offline very expensive.
    fn default() -> Self {
        Self {
            m_cost_kib: 256 * 1024,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

#[derive(Clone, Debug)]
struct Header {
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    chunk_size: u32,
}

impl Header {
    fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..8].copy_from_slice(MAGIC);
        b[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        b[10] = KDF_ARGON2ID;
        b[11..15].copy_from_slice(&self.kdf.m_cost_kib.to_le_bytes());
        b[15..19].copy_from_slice(&self.kdf.t_cost.to_le_bytes());
        b[19..23].copy_from_slice(&self.kdf.p_cost.to_le_bytes());
        b[23..55].copy_from_slice(&self.salt);
        b[55..74].copy_from_slice(&self.nonce);
        b[74..78].copy_from_slice(&self.chunk_size.to_le_bytes());
        b
    }

    fn from_bytes(b: &[u8; HEADER_LEN]) -> Result<Self> {
        if &b[0..8] != MAGIC {
            bail!("not a .vault file (bad magic bytes)");
        }
        let version = u16::from_le_bytes([b[8], b[9]]);
        if version != FORMAT_VERSION {
            bail!(
                "unsupported vault format version {version} (this build supports {FORMAT_VERSION})"
            );
        }
        if b[10] != KDF_ARGON2ID {
            bail!("unsupported key derivation function id {}", b[10]);
        }
        let u32_at = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        let kdf = KdfParams {
            m_cost_kib: u32_at(11),
            t_cost: u32_at(15),
            p_cost: u32_at(19),
        };
        let chunk_size = u32_at(74);
        if kdf.m_cost_kib > MAX_M_COST_KIB
            || kdf.t_cost == 0
            || kdf.t_cost > MAX_T_COST
            || kdf.p_cost == 0
            || kdf.p_cost > MAX_P_COST
        {
            bail!("vault header has out-of-range key derivation parameters");
        }
        if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
            bail!("vault header has an out-of-range chunk size");
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&b[23..55]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&b[55..74]);
        Ok(Self {
            kdf,
            salt,
            nonce,
            chunk_size,
        })
    }
}

fn derive_key(password: &[u8], salt: &[u8], kdf: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid KDF parameters: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// A `Write` adapter that encrypts everything written to it. Call
/// [`EncryptWriter::finish`] at the end: the final chunk is only written
/// then, and a vault without its final chunk is rejected as truncated.
pub struct EncryptWriter<W: Write> {
    inner: W,
    enc: Option<EncryptorBE32<XChaCha20Poly1305>>,
    aad: [u8; HEADER_LEN],
    buf: Zeroizing<Vec<u8>>,
    chunk_size: usize,
}

impl<W: Write> EncryptWriter<W> {
    pub fn new(inner: W, password: &[u8], kdf: KdfParams) -> Result<Self> {
        Self::with_chunk_size(inner, password, kdf, DEFAULT_CHUNK_SIZE)
    }

    pub fn with_chunk_size(
        mut inner: W,
        password: &[u8],
        kdf: KdfParams,
        chunk_size: u32,
    ) -> Result<Self> {
        let mut header = Header {
            kdf,
            salt: [0; SALT_LEN],
            nonce: [0; NONCE_LEN],
            chunk_size,
        };
        OsRng.fill_bytes(&mut header.salt);
        OsRng.fill_bytes(&mut header.nonce);
        let key = derive_key(password, &header.salt, kdf)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let enc = EncryptorBE32::from_aead(cipher, header.nonce.as_ref().into());
        let aad = header.to_bytes();
        inner.write_all(&aad).context("writing vault header")?;
        Ok(Self {
            inner,
            enc: Some(enc),
            aad,
            buf: Zeroizing::new(Vec::with_capacity(chunk_size as usize + 1)),
            chunk_size: chunk_size as usize,
        })
    }

    fn flush_full_chunks(&mut self) -> io::Result<()> {
        // Only emit a chunk once we know more data follows. The last chunk
        // must be sealed with `encrypt_last`, which happens in `finish`.
        while self.buf.len() > self.chunk_size {
            let enc = self.enc.as_mut().expect("writer already finished");
            let ct = enc
                .encrypt_next(Payload {
                    msg: &self.buf[..self.chunk_size],
                    aad: &self.aad,
                })
                .map_err(|_| io::Error::other("encryption failed"))?;
            self.inner.write_all(&ct)?;
            self.buf.drain(..self.chunk_size);
        }
        Ok(())
    }

    /// Seal the final chunk and return the inner writer.
    pub fn finish(mut self) -> Result<W> {
        self.flush_full_chunks()?;
        let enc = self.enc.take().expect("writer already finished");
        let ct = enc
            .encrypt_last(Payload {
                msg: &self.buf[..],
                aad: &self.aad,
            })
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        self.inner.write_all(&ct)?;
        self.buf.zeroize();
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for EncryptWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        self.flush_full_chunks()?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------------

/// A `Read` adapter that decrypts and authenticates a vault stream. It only
/// ever releases plaintext that has been authenticated. Reaching EOF (a read
/// returning 0) means the final chunk was present and valid, so the stream
/// was not truncated.
pub struct DecryptReader<R: Read> {
    inner: R,
    dec: Option<DecryptorBE32<XChaCha20Poly1305>>,
    aad: [u8; HEADER_LEN],
    ct_buf: Vec<u8>,
    /// One byte of read-ahead used to detect whether a chunk is the last one.
    lookahead: Option<u8>,
    plain: Zeroizing<Vec<u8>>,
    pos: usize,
}

/// Error message for authentication failures. A wrong password and a
/// tampered file look identical by design.
pub const AUTH_FAILED: &str =
    "wrong password, or the vault file is corrupted or has been tampered with";

impl<R: Read> DecryptReader<R> {
    pub fn new(mut inner: R, password: &[u8]) -> Result<Self> {
        let mut hb = [0u8; HEADER_LEN];
        let n = read_full(&mut inner, &mut hb).context("reading vault header")?;
        if n < HEADER_LEN {
            bail!("not a .vault file (file too short)");
        }
        let header = Header::from_bytes(&hb)?;
        let key = derive_key(password, &header.salt, header.kdf)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let dec = DecryptorBE32::from_aead(cipher, header.nonce.as_ref().into());
        let mut me = Self {
            inner,
            dec: Some(dec),
            aad: hb,
            ct_buf: vec![0u8; header.chunk_size as usize + TAG_LEN],
            lookahead: None,
            plain: Zeroizing::new(Vec::new()),
            pos: 0,
        };
        // Decrypt the first chunk now, so a wrong password fails fast, right
        // where the caller is still asking for the password.
        me.next_chunk()?;
        Ok(me)
    }

    fn next_chunk(&mut self) -> io::Result<()> {
        let Some(dec) = self.dec.as_mut() else {
            return Ok(()); // already past the last chunk
        };
        let mut n = 0;
        if let Some(b) = self.lookahead.take() {
            self.ct_buf[0] = b;
            n = 1;
        }
        n += read_full(&mut self.inner, &mut self.ct_buf[n..])?;
        let is_last = if n < self.ct_buf.len() {
            true
        } else {
            let mut one = [0u8; 1];
            if read_full(&mut self.inner, &mut one)? == 0 {
                true
            } else {
                self.lookahead = Some(one[0]);
                false
            }
        };
        let payload = Payload {
            msg: &self.ct_buf[..n],
            aad: &self.aad,
        };
        let auth_err = || io::Error::new(io::ErrorKind::InvalidData, AUTH_FAILED);
        let pt = if is_last {
            let dec = self.dec.take().unwrap();
            dec.decrypt_last(payload).map_err(|_| auth_err())?
        } else {
            dec.decrypt_next(payload).map_err(|_| auth_err())?
        };
        self.plain.zeroize();
        *self.plain = pt;
        self.pos = 0;
        Ok(())
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos >= self.plain.len() {
            if self.dec.is_none() {
                return Ok(0);
            }
            self.next_chunk()?;
        }
        let n = out.len().min(self.plain.len() - self.pos);
        out[..n].copy_from_slice(&self.plain[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Does this file start with the vault magic bytes? Used to recognise vaults
/// dropped onto the GUI.
pub fn looks_like_vault(path: &std::path::Path) -> bool {
    let mut magic = [0u8; 8];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .map(|_| &magic == MAGIC)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    fn roundtrip(data: &[u8], chunk: u32) -> Vec<u8> {
        let mut w = EncryptWriter::with_chunk_size(Vec::new(), b"pw", FAST, chunk).unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap()
    }

    fn decrypt(ct: &[u8], pw: &[u8]) -> Result<Vec<u8>> {
        let mut r = DecryptReader::new(ct, pw)?;
        let mut out = Vec::new();
        r.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn roundtrips_various_sizes() {
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 100, 1000] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let ct = roundtrip(&data, 16);
            assert_eq!(decrypt(&ct, b"pw").unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn wrong_password_fails() {
        let ct = roundtrip(b"secret", 16);
        assert!(decrypt(&ct, b"nope").is_err());
    }

    #[test]
    fn truncation_detected() {
        let data = vec![42u8; 100];
        let ct = roundtrip(&data, 16);
        // Cut off at chunk boundaries and in the middle of chunks.
        for cut in [
            HEADER_LEN + 32,
            HEADER_LEN + 64,
            ct.len() - 1,
            ct.len() - 20,
        ] {
            assert!(decrypt(&ct[..cut], b"pw").is_err(), "cut {cut}");
        }
    }

    #[test]
    fn appended_data_detected() {
        let mut ct = roundtrip(&[1u8; 40], 16);
        ct.extend_from_slice(&[0u8; 32]);
        assert!(decrypt(&ct, b"pw").is_err());
    }

    #[test]
    fn any_bit_flip_detected() {
        let ct = roundtrip(&[9u8; 50], 16);
        for i in 0..ct.len() {
            // Flipping a bit in the memory-cost field would just make the test
            // allocate gigabytes before failing; skip those four bytes.
            if (11..15).contains(&i) {
                continue;
            }
            let mut bad = ct.clone();
            bad[i] ^= 0x01;
            assert!(
                decrypt(&bad, b"pw").is_err(),
                "flip at byte {i} not detected"
            );
        }
    }

    #[test]
    fn same_input_gives_different_ciphertext() {
        assert_ne!(roundtrip(b"hello", 16), roundtrip(b"hello", 16));
    }
}
