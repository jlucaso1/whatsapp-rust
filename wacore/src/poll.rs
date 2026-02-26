//! Poll encryption and utilities for WhatsApp polls.
//!
//! WhatsApp polls use AES-256-GCM encryption with randomly generated keys.
//! The poll options are encrypted, and votes reference the encrypted option hashes.

use crate::libsignal::crypto::{Aes256GcmDecryption, Aes256GcmEncryption};
use anyhow::{Result, anyhow};
use rand::Rng;
use sha2::{Digest, Sha256};

const POLL_ENC_KEY_SIZE: usize = 32;
const POLL_ENC_IV_SIZE: usize = 12;

/// Generate a random 32-byte encryption key for a poll.
pub fn generate_poll_enc_key() -> [u8; POLL_ENC_KEY_SIZE] {
    let mut key = [0u8; POLL_ENC_KEY_SIZE];
    rand::rng().fill(&mut key);
    key
}

/// Encrypt a poll option name using the poll's encryption key.
///
/// Returns (encrypted_payload, iv) tuple.
pub fn encrypt_poll_option(
    option_name: &str,
    enc_key: &[u8; POLL_ENC_KEY_SIZE],
) -> Result<(Vec<u8>, [u8; POLL_ENC_IV_SIZE])> {
    let mut iv = [0u8; POLL_ENC_IV_SIZE];
    rand::rng().fill(&mut iv);

    let mut payload = option_name.as_bytes().to_vec();
    let mut enc = Aes256GcmEncryption::new(enc_key, &iv, b"")?;
    enc.encrypt(&mut payload);
    let tag = enc.compute_tag();

    // Append tag to payload
    payload.extend_from_slice(&tag);

    Ok((payload, iv))
}

/// Decrypt a poll option from encrypted payload and IV.
pub fn decrypt_poll_option(encrypted_payload: &[u8], iv: &[u8], enc_key: &[u8]) -> Result<String> {
    if encrypted_payload.len() < 16 {
        return Err(anyhow!(
            "encrypted payload too short (need at least 16 bytes for tag)"
        ));
    }

    let (ciphertext, tag) = encrypted_payload.split_at(encrypted_payload.len() - 16);

    let mut plaintext = ciphertext.to_vec();
    let mut dec = Aes256GcmDecryption::new(enc_key, iv, b"")?;
    dec.decrypt(&mut plaintext);
    dec.verify_tag(tag)?;

    String::from_utf8(plaintext).map_err(|e| anyhow!("invalid UTF-8 in poll option: {}", e))
}

/// Compute the SHA-256 hash of an encrypted poll option for identification.
///
/// The hash is computed over the concatenation of IV and encrypted payload.
pub fn compute_poll_option_hash(encrypted_payload: &[u8], iv: &[u8; POLL_ENC_IV_SIZE]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(iv);
    hasher.update(encrypted_payload);
    hasher.finalize().to_vec()
}

/// Encrypt poll vote selections.
///
/// Encrypts the serialized vote message using the poll's encryption key.
/// Returns (encrypted_payload, iv) tuple.
pub fn encrypt_poll_vote(
    selected_option_hashes: &[Vec<u8>],
    enc_key: &[u8; POLL_ENC_KEY_SIZE],
) -> Result<(Vec<u8>, [u8; POLL_ENC_IV_SIZE])> {
    use prost::Message;

    let vote_msg = waproto::whatsapp::message::PollVoteMessage {
        selected_options: selected_option_hashes.to_vec(),
    };

    let mut vote_bytes = Vec::new();
    vote_msg.encode(&mut vote_bytes)?;

    let mut iv = [0u8; POLL_ENC_IV_SIZE];
    rand::rng().fill(&mut iv);

    let mut payload = vote_bytes;
    let mut enc = Aes256GcmEncryption::new(enc_key, &iv, b"")?;
    enc.encrypt(&mut payload);
    let tag = enc.compute_tag();

    // Append tag to payload
    payload.extend_from_slice(&tag);

    Ok((payload, iv))
}

/// Decrypt a poll vote from encrypted payload and IV.
pub fn decrypt_poll_vote(
    encrypted_payload: &[u8],
    iv: &[u8],
    enc_key: &[u8],
) -> Result<Vec<Vec<u8>>> {
    use prost::Message as _;

    if encrypted_payload.len() < 16 {
        return Err(anyhow!(
            "encrypted payload too short (need at least 16 bytes for tag)"
        ));
    }

    let (ciphertext, tag) = encrypted_payload.split_at(encrypted_payload.len() - 16);

    let mut plaintext = ciphertext.to_vec();
    let mut dec = Aes256GcmDecryption::new(enc_key, iv, b"")?;
    dec.decrypt(&mut plaintext);
    dec.verify_tag(tag)?;

    let vote_msg = waproto::whatsapp::message::PollVoteMessage::decode(&plaintext[..])?;
    Ok(vote_msg.selected_options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poll_option_encryption_roundtrip() {
        let enc_key = generate_poll_enc_key();
        let option_name = "Option 1";

        let (encrypted, iv) = encrypt_poll_option(option_name, &enc_key).unwrap();
        let decrypted = decrypt_poll_option(&encrypted, &iv, &enc_key).unwrap();

        assert_eq!(decrypted, option_name);
    }

    #[test]
    fn test_poll_option_hash() {
        let enc_key = generate_poll_enc_key();
        let option_name = "Option 1";

        let (encrypted, iv) = encrypt_poll_option(option_name, &enc_key).unwrap();
        let hash = compute_poll_option_hash(&encrypted, &iv);

        // SHA-256 produces 32 bytes
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_poll_vote_encryption_roundtrip() {
        let enc_key = generate_poll_enc_key();
        let option_hashes = vec![vec![1, 2, 3], vec![4, 5, 6]];

        let (encrypted, iv) = encrypt_poll_vote(&option_hashes, &enc_key).unwrap();
        let decrypted = decrypt_poll_vote(&encrypted, &iv, &enc_key).unwrap();

        assert_eq!(decrypted, option_hashes);
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let key1 = generate_poll_enc_key();
        let key2 = generate_poll_enc_key();
        let option = "Test";

        let (enc1, _) = encrypt_poll_option(option, &key1).unwrap();
        let (enc2, _) = encrypt_poll_option(option, &key2).unwrap();

        assert_ne!(enc1, enc2);
    }
}
