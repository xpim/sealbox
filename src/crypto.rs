//! Encrypted container layer of the `.sbx` format.
//!
//! On-disk layout:
//!
//! ```text
//! offset  size  field
//! 0       32    random salt
//! 32      19    random STREAM nonce prefix
//! 51      ...   ciphertext chunks
//! ```
//!
//! There is deliberately no magic number, version field or parameter block.
//! Every byte of a sealbox is either random (salt, nonce) or ciphertext, so the
//! file looks like uniformly random data and does not identify the program
//! that wrote it. The cost of this is that the parameters of this outer
//! layer ([`SealParams::default`]) are not stored in the file.
//!
//! **Compatibility rule:** keep this outer layer stable. Put format changes
//! inside the encrypted payload, whose version header lets any Sealbox name
//! the version needed (see `archive.rs`). If the outer layer ever must
//! change, new versions must also try the old parameters (trial decryption)
//! so existing sealboxes keep opening.
//!
//! The key is derived from the password with Argon2id. The payload is
//! encrypted with XChaCha20-Poly1305 in the STREAM construction (Hoang,
//! Reyhanitabar, Rogaway, Vizár 2015). Every chunk is authenticated and
//! carries its position, plus a flag for the final chunk, in its nonce. So
//! reordering, dropping, truncating or appending chunks is detected. The
//! header is bound to every chunk as associated data, so tampering with it is
//! detected too.
//!
//! Nothing about the contents is stored in plaintext. File names, sizes,
//! counts and data all live inside the encrypted payload.

use std::io::{self, Read, Write};

use anyhow::{Context, Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::{KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use zeroize::{Zeroize, Zeroizing};

pub const SALT_LEN: usize = 32;
pub const NONCE_LEN: usize = 19; // 24-byte XChaCha nonce minus 5 bytes STREAM counter/flag
pub const HEADER_LEN: usize = SALT_LEN + NONCE_LEN;
const TAG_LEN: usize = 16;

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

/// Parameters needed to read or write a sealbox. They are not stored in the
/// file, so writer and reader must agree on them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealParams {
    pub kdf: KdfParams,
    pub chunk_size: u32,
}

impl Default for SealParams {
    /// Format v1: Argon2id with 256 MiB, 3 passes, 4 lanes (roughly half a
    /// second to a second on a modern machine, which makes guessing passwords
    /// offline very expensive), and 1 MiB chunks.
    ///
    /// Changing any of these makes existing sealboxes unreadable. Only change
    /// them together with a fallback that also tries the old values.
    fn default() -> Self {
        Self {
            kdf: KdfParams {
                m_cost_kib: 256 * 1024,
                t_cost: 3,
                p_cost: 4,
            },
            chunk_size: 1024 * 1024,
        }
    }
}

fn header_bytes(salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> [u8; HEADER_LEN] {
    let mut b = [0u8; HEADER_LEN];
    b[..SALT_LEN].copy_from_slice(salt);
    b[SALT_LEN..].copy_from_slice(nonce);
    b
}

/// Bring a password into Unicode NFC form. The same visible text (e.g. "é")
/// can be typed or pasted as different byte sequences depending on the OS
/// and input method; normalising makes the password work everywhere.
fn normalize_password(password: &[u8]) -> Zeroizing<Vec<u8>> {
    use unicode_normalization::UnicodeNormalization;
    match std::str::from_utf8(password) {
        Ok(s) => Zeroizing::new(
            Zeroizing::new(s.nfc().collect::<String>())
                .as_bytes()
                .to_vec(),
        ),
        Err(_) => Zeroizing::new(password.to_vec()),
    }
}

fn derive_key(password: &[u8], salt: &[u8], kdf: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let password = normalize_password(password);
    let params = Params::new(kdf.m_cost_kib, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid KDF parameters: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(&password, salt, key.as_mut())
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
/// then, and a sealbox without its final chunk is rejected as truncated.
pub struct EncryptWriter<W: Write> {
    inner: W,
    enc: Option<EncryptorBE32<XChaCha20Poly1305>>,
    aad: [u8; HEADER_LEN],
    buf: Zeroizing<Vec<u8>>,
    chunk_size: usize,
    written: u64,
}

impl<W: Write> EncryptWriter<W> {
    pub fn new(inner: W, password: &[u8], params: &SealParams) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        // Straight from the operating system's secure random generator.
        getrandom::fill(&mut salt)
            .and_then(|()| getrandom::fill(&mut nonce))
            .map_err(|e| anyhow::anyhow!("cannot get secure random bytes: {e}"))?;
        Self::with_salt_and_nonce(inner, password, params, salt, nonce)
    }

    /// Like [`EncryptWriter::new`] but with caller-chosen salt and nonce.
    /// Only for known-answer tests: reusing a salt/nonce pair with the same
    /// password would break confidentiality.
    #[doc(hidden)]
    pub fn with_salt_and_nonce(
        mut inner: W,
        password: &[u8],
        params: &SealParams,
        salt: [u8; SALT_LEN],
        nonce: [u8; NONCE_LEN],
    ) -> Result<Self> {
        let key = derive_key(password, &salt, params.kdf)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let enc = EncryptorBE32::from_aead(cipher, nonce.as_ref().into());
        let aad = header_bytes(&salt, &nonce);
        inner.write_all(&aad).context("writing sealbox header")?;
        let chunk_size = params.chunk_size as usize;
        Ok(Self {
            inner,
            enc: Some(enc),
            aad,
            buf: Zeroizing::new(Vec::with_capacity(chunk_size + 1)),
            chunk_size,
            written: 0,
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

    /// Number of plaintext bytes written so far.
    pub fn plaintext_len(&self) -> u64 {
        self.written
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
        self.written += data.len() as u64;
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

/// A `Read` adapter that decrypts and authenticates a sealbox stream. It only
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
///
/// A sealbox written by a future version with different outer-layer
/// parameters also fails here; without a plaintext header (which would
/// identify the file) it cannot be told apart, so the message says so.
pub const AUTH_FAILED: &str = "cannot open the sealbox: wrong password, the file is damaged or \
     was tampered with, or it was made by a newer version of Sealbox";

impl<R: Read> DecryptReader<R> {
    pub fn new(mut inner: R, password: &[u8], params: &SealParams) -> Result<Self> {
        let mut hb = [0u8; HEADER_LEN];
        let n = read_full(&mut inner, &mut hb).context("reading sealbox header")?;
        if n < HEADER_LEN {
            bail!("not a sealbox file (file too short)");
        }
        let (salt, nonce) = hb.split_at(SALT_LEN);
        let key = derive_key(password, salt, params.kdf)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let dec = DecryptorBE32::from_aead(cipher, nonce.into());
        let mut me = Self {
            inner,
            dec: Some(dec),
            aad: hb,
            ct_buf: vec![0u8; params.chunk_size as usize + TAG_LEN],
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap KDF and tiny chunks so tests are fast and cross chunk borders.
    const FAST: SealParams = SealParams {
        kdf: KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        },
        chunk_size: 16,
    };

    fn roundtrip(data: &[u8]) -> Vec<u8> {
        let mut w = EncryptWriter::new(Vec::new(), b"pw", &FAST).unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap()
    }

    fn decrypt(ct: &[u8], pw: &[u8]) -> Result<Vec<u8>> {
        let mut r = DecryptReader::new(ct, pw, &FAST)?;
        let mut out = Vec::new();
        r.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn roundtrips_various_sizes() {
        for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 100, 1000] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let ct = roundtrip(&data);
            assert_eq!(decrypt(&ct, b"pw").unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn wrong_password_fails() {
        let ct = roundtrip(b"secret");
        assert!(decrypt(&ct, b"nope").is_err());
    }

    #[test]
    fn truncation_detected() {
        let data = vec![42u8; 100];
        let ct = roundtrip(&data);
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
        let mut ct = roundtrip(&[1u8; 40]);
        ct.extend_from_slice(&[0u8; 32]);
        assert!(decrypt(&ct, b"pw").is_err());
    }

    #[test]
    fn any_bit_flip_detected() {
        let ct = roundtrip(&[9u8; 50]);
        for i in 0..ct.len() {
            let mut bad = ct.clone();
            bad[i] ^= 0x01;
            assert!(
                decrypt(&bad, b"pw").is_err(),
                "flip at byte {i} not detected"
            );
        }
    }

    #[test]
    fn no_identifying_bytes() {
        // Two sealboxes of the same content share no fixed prefix: there is no
        // magic number, version or parameter block anywhere.
        let (a, b) = (roundtrip(b"hello"), roundtrip(b"hello"));
        let common = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
        assert!(common < 4, "{common} identical leading bytes");
    }

    #[test]
    fn unicode_password_forms_are_equivalent() {
        // "café" with a precomposed é (NFC) vs e + combining accent (NFD).
        let nfc = "caf\u{e9}".as_bytes();
        let nfd = "cafe\u{301}".as_bytes();
        assert_ne!(nfc, nfd);
        let mut w = EncryptWriter::new(Vec::new(), nfd, &FAST).unwrap();
        w.write_all(b"data").unwrap();
        let ct = w.finish().unwrap();
        assert_eq!(decrypt(&ct, nfc).unwrap(), b"data");
    }

    #[test]
    fn same_input_gives_different_ciphertext() {
        assert_ne!(roundtrip(b"hello"), roundtrip(b"hello"));
    }
}
