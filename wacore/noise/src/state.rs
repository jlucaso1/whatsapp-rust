use crate::error::{NoiseError, Result};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, AeadInPlace, KeyInit, Payload};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Generates an IV (nonce) for AES-GCM from a counter value.
/// The counter is placed in the last 4 bytes of a 12-byte IV.
#[inline]
pub fn generate_iv(counter: u32) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[8..].copy_from_slice(&counter.to_be_bytes());
    iv
}

/// A cipher wrapper that encapsulates AES-256-GCM encryption/decryption
/// with counter-based IV generation.
///
/// This provides a high-level API for post-handshake message encryption
/// without exposing the underlying AES-GCM implementation details.
///
/// # Example
///
/// ```ignore
/// use wacore_noise::NoiseCipher;
///
/// // After handshake, you get read/write ciphers
/// let mut counter = 0u32;
///
/// // Encrypt with counter
/// let ciphertext = cipher.encrypt_with_counter(counter, plaintext)?;
/// counter = counter.wrapping_add(1);
///
/// // Decrypt with counter
/// let plaintext = cipher.decrypt_with_counter(counter, ciphertext)?;
/// ```
pub struct NoiseCipher {
    inner: Aes256Gcm,
}

impl NoiseCipher {
    /// Creates a new cipher from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        let inner = Aes256Gcm::new_from_slice(key)
            .map_err(|_| NoiseError::CryptoError("Invalid key size for AES-256-GCM".into()))?;
        Ok(Self { inner })
    }

    /// Encrypts plaintext using the specified counter for IV generation.
    ///
    /// Returns the ciphertext with appended authentication tag (16 bytes).
    pub fn encrypt_with_counter(&self, counter: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        let iv = generate_iv(counter);
        self.inner
            .encrypt(iv.as_ref().into(), plaintext)
            .map_err(|e| NoiseError::CryptoError(e.to_string()))
    }

    /// Encrypts plaintext in-place within the provided buffer.
    ///
    /// The buffer should contain the plaintext. After encryption, it will
    /// contain the ciphertext with the authentication tag appended.
    pub fn encrypt_in_place_with_counter(&self, counter: u32, buffer: &mut Vec<u8>) -> Result<()> {
        let iv = generate_iv(counter);
        self.inner
            .encrypt_in_place(iv.as_ref().into(), b"", buffer)
            .map_err(|e| NoiseError::CryptoError(e.to_string()))
    }

    /// Decrypts ciphertext using the specified counter for IV generation.
    ///
    /// The ciphertext should include the 16-byte authentication tag.
    pub fn decrypt_with_counter(&self, counter: u32, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let iv = generate_iv(counter);
        self.inner
            .decrypt(iv.as_ref().into(), ciphertext)
            .map_err(|e| NoiseError::CryptoError(format!("Decrypt failed: {e}")))
    }

    /// Decrypts ciphertext in-place within the provided buffer.
    ///
    /// The buffer should contain the ciphertext with the 16-byte authentication tag.
    /// After decryption, it will contain the plaintext (tag is removed).
    pub fn decrypt_in_place_with_counter(&self, counter: u32, buffer: &mut Vec<u8>) -> Result<()> {
        let iv = generate_iv(counter);
        self.inner
            .decrypt_in_place(iv.as_ref().into(), b"", buffer)
            .map_err(|e| NoiseError::CryptoError(format!("Decrypt failed: {e}")))
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
///
/// Contains `NoiseCipher` instances for both write (outgoing) and read (incoming)
/// directions. Use `encrypt_with_counter` and `decrypt_with_counter` methods
/// with your own counter management.
pub struct NoiseKeys {
    pub write: NoiseCipher,
    pub read: NoiseCipher,
}

/// A generic Noise Protocol XX state machine.
///
/// This implements the core Noise protocol operations without any
/// dependency on specific key agreement libraries. The caller is
/// responsible for computing DH shared secrets externally.
///
/// # Example
///
/// ```ignore
/// use wacore_noise::{NoiseState, generate_iv};
///
/// // Initialize with pattern and prologue
/// let mut noise = NoiseState::new(b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0", &prologue)?;
///
/// // Authenticate public keys
/// noise.authenticate(&my_ephemeral_public);
/// noise.authenticate(&their_ephemeral_public);
///
/// // Mix pre-computed shared secret (caller handles DH)
/// noise.mix_key(&shared_secret)?;
///
/// // Encrypt/decrypt messages
/// let ciphertext = noise.encrypt(plaintext)?;
/// let plaintext = noise.decrypt(ciphertext)?;
///
/// // Extract final keys
/// let keys = noise.split()?;
/// ```
pub struct NoiseState {
    hash: [u8; 32],
    salt: [u8; 32],
    cipher: Aes256Gcm,
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
    ///
    /// The pattern should be exactly 32 bytes (used directly as initial hash)
    /// or any other length (will be SHA-256 hashed to derive initial state).
    ///
    /// The prologue is authenticated into the hash state.
    pub fn new(pattern: impl AsRef<[u8]>, prologue: &[u8]) -> Result<Self> {
        let pattern = pattern.as_ref();
        let h: [u8; 32] = if pattern.len() == 32 {
            to_array(pattern, "noise pattern prefix")?
        } else {
            sha256_digest(pattern)
        };

        let cipher = Aes256Gcm::new_from_slice(&h)
            .map_err(|_| NoiseError::CryptoError("Invalid key size for AES-256-GCM".into()))?;

        let mut state = Self {
            hash: h,
            salt: h,
            cipher,
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
        let payload = Payload {
            msg: plaintext,
            aad: &self.hash,
        };
        let ciphertext = self
            .cipher
            .encrypt(iv.as_ref().into(), payload)
            .map_err(|e| NoiseError::CryptoError(e.to_string()))?;
        self.authenticate(&ciphertext);
        Ok(ciphertext)
    }

    /// Zero-allocation encryption that appends the ciphertext to the provided buffer.
    ///
    /// The ciphertext (including the AES-GCM tag) is appended to `out`.
    /// The buffer is NOT cleared before appending.
    pub fn encrypt_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let iv = generate_iv(self.post_increment_counter()?);
        let aad = self.hash;
        let start = out.len();

        // Copy plaintext to output buffer
        out.extend_from_slice(plaintext);

        // Encrypt in-place and get the tag separately
        let tag = self
            .cipher
            .encrypt_in_place_detached(iv.as_ref().into(), &aad, &mut out[start..])
            .map_err(|e| NoiseError::CryptoError(e.to_string()))?;

        // Append the authentication tag
        out.extend_from_slice(&tag);

        // Authenticate with the complete ciphertext (including tag)
        self.authenticate(&out[start..]);
        Ok(())
    }

    /// Decrypts ciphertext, updates the hash state.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let aad = self.hash;
        let iv = generate_iv(self.post_increment_counter()?);
        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };
        let plaintext = self
            .cipher
            .decrypt(iv.as_ref().into(), payload)
            .map_err(|e| NoiseError::CryptoError(format!("Noise decrypt failed: {e}")))?;

        self.authenticate(ciphertext);
        Ok(plaintext)
    }

    /// Zero-allocation decryption that appends the plaintext to the provided buffer.
    ///
    /// The plaintext is appended to `out`. The buffer is NOT cleared before appending.
    /// The ciphertext must include the 16-byte authentication tag.
    pub fn decrypt_into(&mut self, ciphertext: &[u8], out: &mut Vec<u8>) -> Result<()> {
        const TAG_LEN: usize = 16;

        if ciphertext.len() < TAG_LEN {
            return Err(NoiseError::CryptoError(
                "Ciphertext too short (missing tag)".into(),
            ));
        }

        let aad = self.hash;
        let iv = generate_iv(self.post_increment_counter()?);

        // Split ciphertext and tag
        let (ct, tag_slice) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
        let tag: &[u8; TAG_LEN] = tag_slice.try_into().unwrap(); // Safe: we checked length

        let start = out.len();

        // Copy ciphertext (without tag) to output buffer
        out.extend_from_slice(ct);

        // Decrypt in-place
        self.cipher
            .decrypt_in_place_detached(iv.as_ref().into(), &aad, &mut out[start..], tag.into())
            .map_err(|e| NoiseError::CryptoError(format!("Noise decrypt failed: {e}")))?;

        // Authenticate with the original ciphertext (including tag)
        self.authenticate(ciphertext);
        Ok(())
    }

    /// Mixes key material into the cipher state (MixKey operation).
    ///
    /// This is the generic version that accepts pre-computed key material.
    /// The caller is responsible for computing DH shared secrets externally
    /// using their preferred cryptographic library.
    pub fn mix_key(&mut self, input_key_material: &[u8]) -> Result<()> {
        self.counter = 0;
        let (new_salt, new_key) = self.extract_and_expand(Some(input_key_material))?;
        self.salt = new_salt;
        self.cipher = Aes256Gcm::new_from_slice(&new_key)
            .map_err(|_| NoiseError::CryptoError("Invalid key size for AES-256-GCM".into()))?;
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
    ///
    /// This consumes the state and returns `NoiseCipher` instances for
    /// subsequent encrypted communication.
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

        // The hash should have been updated by the prologue
        assert_ne!(noise.hash(), noise.salt());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let prologue = b"test";
        let mut noise = NoiseState::new(b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0", prologue)
            .expect("initialization should succeed");

        let plaintext = b"hello world";
        let ciphertext = noise.encrypt(plaintext).expect("encrypt should succeed");

        // Reset state for decryption (in real use, you'd have two separate states)
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

        // Salt should have changed
        assert_ne!(noise.salt(), &old_salt);
        // Counter should be reset
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

        // Verify ciphertext has expected size (plaintext + 16 byte tag)
        assert_eq!(ciphertext_buf.len(), plaintext.len() + 16);

        // Decrypt with fresh state
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

        // Test with encrypt()
        let mut noise1 = NoiseState::new(b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0", prologue)
            .expect("initialization should succeed");
        let ciphertext1 = noise1.encrypt(plaintext).expect("encrypt should succeed");

        // Test with encrypt_into()
        let mut noise2 = NoiseState::new(b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0", prologue)
            .expect("initialization should succeed");
        let mut ciphertext2 = Vec::new();
        noise2
            .encrypt_into(plaintext, &mut ciphertext2)
            .expect("encrypt_into should succeed");

        // Both should produce identical ciphertext
        assert_eq!(ciphertext1, ciphertext2);

        // Both should have same hash state after
        assert_eq!(noise1.hash(), noise2.hash());
    }

    #[test]
    fn test_noise_cipher_in_place_roundtrip() {
        let key = [0x42u8; 32];
        let cipher = NoiseCipher::new(&key).expect("cipher creation should succeed");

        let plaintext = b"test in-place encryption";
        let mut buffer = plaintext.to_vec();

        // Encrypt in-place
        cipher
            .encrypt_in_place_with_counter(0, &mut buffer)
            .expect("encrypt should succeed");

        // Buffer should now be larger (ciphertext + 16 byte tag)
        assert_eq!(buffer.len(), plaintext.len() + 16);

        // Decrypt in-place
        cipher
            .decrypt_in_place_with_counter(0, &mut buffer)
            .expect("decrypt should succeed");

        // Buffer should be back to original plaintext
        assert_eq!(buffer, plaintext);
    }

    #[test]
    fn test_counter_exhaustion() {
        let prologue = b"test";
        let mut noise = NoiseState::new(b"Noise_XX_25519_AESGCM_SHA256\0\0\0\0", prologue)
            .expect("initialization should succeed");

        // Set counter to max value
        noise.counter = u32::MAX;

        // Next encrypt should fail with CounterExhausted
        let result = noise.encrypt(b"test");
        assert!(matches!(result, Err(NoiseError::CounterExhausted)));
    }
}
