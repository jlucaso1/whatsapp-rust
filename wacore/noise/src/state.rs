use crate::error::{NoiseError, Result};
use bytes::BytesMut;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use wacore_libsignal::crypto::{aes_256_gcm_decrypt, aes_256_gcm_encrypt};

/// Minimal byte-buffer interface used by `NoiseCipher::decrypt_in_place_with_counter`.
/// Callers can pass either `Vec<u8>` or `bytes::BytesMut` (both read-then-write patterns).
pub trait NoiseBuffer {
    fn as_slice(&self) -> &[u8];
    fn replace_contents(&mut self, data: &[u8]);
}

impl NoiseBuffer for Vec<u8> {
    fn as_slice(&self) -> &[u8] {
        self
    }
    fn replace_contents(&mut self, data: &[u8]) {
        self.clear();
        self.extend_from_slice(data);
    }
}

impl NoiseBuffer for BytesMut {
    fn as_slice(&self) -> &[u8] {
        self
    }
    fn replace_contents(&mut self, data: &[u8]) {
        self.clear();
        self.extend_from_slice(data);
    }
}

/// Generates an IV (nonce) for AES-GCM from a counter value.
/// The counter is placed in the last 4 bytes of a 12-byte IV.
#[inline]
pub fn generate_iv(counter: u32) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[8..].copy_from_slice(&counter.to_be_bytes());
    iv
}

const TAG_LEN: usize = 16;

/// A cipher wrapper that encapsulates AES-256-GCM encryption/decryption
/// with counter-based IV generation.
pub struct NoiseCipher {
    key: [u8; 32],
}

impl NoiseCipher {
    /// Creates a new cipher from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        Ok(Self { key: *key })
    }

    /// Encrypts plaintext using the specified counter for IV generation.
    /// Returns the ciphertext with appended authentication tag (16 bytes).
    pub fn encrypt_with_counter(&self, counter: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        let iv = generate_iv(counter);
        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        aes_256_gcm_encrypt(&self.key, &iv, b"", plaintext, &mut out)
            .map_err(|e| NoiseError::CryptoError(format!("{e}")))?;
        Ok(out)
    }

    /// Encrypts plaintext in-place within the provided buffer: on entry `buffer`
    /// holds the plaintext; on return it holds ciphertext + 16-byte tag.
    pub fn encrypt_in_place_with_counter(&self, counter: u32, buffer: &mut Vec<u8>) -> Result<()> {
        let iv = generate_iv(counter);
        let plaintext = std::mem::take(buffer);
        aes_256_gcm_encrypt(&self.key, &iv, b"", &plaintext, buffer)
            .map_err(|e| NoiseError::CryptoError(format!("{e}")))
    }

    /// Decrypts ciphertext (with 16-byte tag appended) in-place within the
    /// provided buffer. On return, `buffer` holds the plaintext (tag removed).
    /// Accepts any [`NoiseBuffer`] (`Vec<u8>` or `bytes::BytesMut`).
    pub fn decrypt_in_place_with_counter<B: NoiseBuffer>(
        &self,
        counter: u32,
        buffer: &mut B,
    ) -> Result<()> {
        let iv = generate_iv(counter);
        let mut out = Vec::with_capacity(buffer.as_slice().len().saturating_sub(TAG_LEN));
        aes_256_gcm_decrypt(&self.key, &iv, b"", buffer.as_slice(), &mut out)
            .map_err(|e| NoiseError::CryptoError(format!("Decrypt failed: {e}")))?;
        buffer.replace_contents(&out);
        Ok(())
    }
}

fn to_array(slice: &[u8], name: &'static str) -> Result<[u8; 32]> {
    slice.try_into().map_err(|_| NoiseError::InvalidKeyLength {
        name,
        expected: 32,
        got: slice.len(),
    })
}

fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// The final keys extracted from a completed Noise handshake.
pub struct NoiseKeys {
    pub write: NoiseCipher,
    pub read: NoiseCipher,
}

/// A generic Noise Protocol XX state machine.
pub struct NoiseState {
    hash: [u8; 32],
    salt: [u8; 32],
    key: [u8; 32],
    counter: u32,
}

impl NoiseState {
    /// Returns the current hash state.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Returns the current salt/chaining key.
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    /// Creates a new Noise state with the given pattern and prologue.
    pub fn new(pattern: impl AsRef<[u8]>, prologue: &[u8]) -> Result<Self> {
        let pattern = pattern.as_ref();
        let h: [u8; 32] = if pattern.len() == 32 {
            to_array(pattern, "noise pattern prefix")?
        } else {
            sha256_digest(pattern)
        };

        let mut state = Self {
            hash: h,
            salt: h,
            key: h,
            counter: 0,
        };

        state.authenticate(prologue);
        Ok(state)
    }

    /// Mixes data into the hash state (MixHash operation).
    pub fn authenticate(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.hash);
        hasher.update(data);
        self.hash = hasher.finalize().into();
    }

    fn post_increment_counter(&mut self) -> Result<u32> {
        let count = self.counter;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(NoiseError::CounterExhausted)?;
        Ok(count)
    }

    /// Encrypts plaintext, updates the hash state with the ciphertext.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let iv = generate_iv(self.post_increment_counter()?);
        let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        aes_256_gcm_encrypt(&self.key, &iv, &self.hash, plaintext, &mut out)
            .map_err(|e| NoiseError::CryptoError(format!("{e}")))?;
        self.authenticate(&out);
        Ok(out)
    }

    /// Zero-allocation-ish encryption that appends the ciphertext to `out`.
    pub fn encrypt_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let iv = generate_iv(self.post_increment_counter()?);
        let aad = self.hash;
        let start = out.len();
        aes_256_gcm_encrypt(&self.key, &iv, &aad, plaintext, out)
            .map_err(|e| NoiseError::CryptoError(format!("{e}")))?;
        self.authenticate(&out[start..]);
        Ok(())
    }

    /// Decrypts ciphertext, updates the hash state.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let aad = self.hash;
        let iv = generate_iv(self.post_increment_counter()?);
        let mut out = Vec::with_capacity(ciphertext.len().saturating_sub(TAG_LEN));
        aes_256_gcm_decrypt(&self.key, &iv, &aad, ciphertext, &mut out)
            .map_err(|e| NoiseError::CryptoError(format!("Noise decrypt failed: {e}")))?;
        self.authenticate(ciphertext);
        Ok(out)
    }

    /// Zero-allocation decryption that appends the plaintext to the provided buffer.
    pub fn decrypt_into(&mut self, ciphertext: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if ciphertext.len() < TAG_LEN {
            return Err(NoiseError::CryptoError(
                "Ciphertext too short (missing tag)".into(),
            ));
        }
        let aad = self.hash;
        let iv = generate_iv(self.post_increment_counter()?);
        aes_256_gcm_decrypt(&self.key, &iv, &aad, ciphertext, out)
            .map_err(|e| NoiseError::CryptoError(format!("Noise decrypt failed: {e}")))?;
        self.authenticate(ciphertext);
        Ok(())
    }

    /// Mixes key material into the cipher state (MixKey operation).
    pub fn mix_key(&mut self, input_key_material: &[u8]) -> Result<()> {
        self.counter = 0;
        let (new_salt, new_key) = self.extract_and_expand(Some(input_key_material))?;
        self.salt = new_salt;
        self.key = new_key;
        Ok(())
    }

    fn extract_and_expand(&self, ikm: Option<&[u8]>) -> Result<([u8; 32], [u8; 32])> {
        let hk = Hkdf::<Sha256>::new(Some(&self.salt), ikm.unwrap_or(&[]));
        let mut okm = [0u8; 64];
        hk.expand(&[], &mut okm)
            .map_err(|_| NoiseError::HkdfExpandFailed)?;

        let mut write = [0u8; 32];
        let mut read = [0u8; 32];

        write.copy_from_slice(&okm[..32]);
        read.copy_from_slice(&okm[32..]);

        Ok((write, read))
    }

    /// Extracts the final write and read keys from the Noise state.
    pub fn split(self) -> Result<NoiseKeys> {
        let (write_bytes, read_bytes) = self.extract_and_expand(None)?;
        let write = NoiseCipher::new(&write_bytes)?;
        let read = NoiseCipher::new(&read_bytes)?;

        Ok(NoiseKeys { write, read })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_iv() {
        let iv = generate_iv(0);
        assert_eq!(iv, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let iv = generate_iv(1);
        assert_eq!(iv, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let iv = generate_iv(0x01020304);
        assert_eq!(iv, [0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_noise_state_initialization() {
        let prologue = b"test prologue";
        let noise = NoiseState::new(b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0", prologue)
            .expect("initialization should succeed");

        assert_ne!(noise.hash(), noise.salt());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let prologue = b"test";
        let mut noise = NoiseState::new(b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0", prologue)
            .expect("initialization should succeed");

        let plaintext = b"hello world";
        let ciphertext = noise.encrypt(plaintext).expect("encrypt should succeed");

        let mut noise2 = NoiseState::new(b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0", prologue)
            .expect("initialization should succeed");

        let decrypted = noise2.decrypt(&ciphertext).expect("decrypt should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_mix_key() {
        let prologue = b"test";
        let mut noise = NoiseState::new(b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0", prologue)
            .expect("initialization should succeed");

        let old_salt = *noise.salt();
        let shared_secret = [0x42u8; 32];

        noise
            .mix_key(&shared_secret)
            .expect("mix_key should succeed");

        assert_ne!(noise.salt(), &old_salt);
        assert_eq!(noise.counter, 0);
    }

    #[test]
    fn test_encrypt_into_decrypt_into_roundtrip() {
        let prologue = b"test";
        let mut noise1 = NoiseState::new(b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0", prologue)
            .expect("initialization should succeed");

        let plaintext = b"hello world from encrypt_into";
        let mut ciphertext_buf = Vec::new();

        noise1
            .encrypt_into(plaintext, &mut ciphertext_buf)
            .expect("encrypt_into should succeed");

        assert_eq!(ciphertext_buf.len(), plaintext.len() + 16);

        let mut noise2 = NoiseState::new(b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0", prologue)
            .expect("initialization should succeed");

        let mut plaintext_buf = Vec::new();
        noise2
            .decrypt_into(&ciphertext_buf, &mut plaintext_buf)
            .expect("decrypt_into should succeed");

        assert_eq!(plaintext_buf, plaintext);
    }

    #[test]
    fn test_encrypt_into_matches_encrypt() {
        let prologue = b"test";
        let plaintext = b"test message";

        let mut noise1 = NoiseState::new(b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0", prologue)
            .expect("initialization should succeed");
        let ciphertext1 = noise1.encrypt(plaintext).expect("encrypt should succeed");

        let mut noise2 = NoiseState::new(b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0", prologue)
            .expect("initialization should succeed");
        let mut ciphertext2 = Vec::new();
        noise2
            .encrypt_into(plaintext, &mut ciphertext2)
            .expect("encrypt_into should succeed");

        assert_eq!(ciphertext1, ciphertext2);
        assert_eq!(noise1.hash(), noise2.hash());
    }

    #[test]
    fn test_noise_cipher_in_place_roundtrip() {
        let key = [0x42u8; 32];
        let cipher = NoiseCipher::new(&key).expect("cipher creation should succeed");

        let plaintext = b"test in-place encryption";
        let mut buffer = plaintext.to_vec();

        cipher
            .encrypt_in_place_with_counter(0, &mut buffer)
            .expect("encrypt should succeed");

        assert_eq!(buffer.len(), plaintext.len() + 16);

        cipher
            .decrypt_in_place_with_counter(0, &mut buffer)
            .expect("decrypt should succeed");

        assert_eq!(buffer, plaintext);
    }

    #[test]
    fn test_counter_exhaustion() {
        let prologue = b"test";
        let mut noise = NoiseState::new(b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0", prologue)
            .expect("initialization should succeed");

        noise.counter = u32::MAX;

        let result = noise.encrypt(b"test");
        assert!(matches!(result, Err(NoiseError::CounterExhausted)));
    }
}
