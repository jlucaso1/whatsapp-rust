//! Call encryption via enc_rekey mechanism.
//!
//! This module handles the encryption key exchange for calls using the
//! `enc_rekey` signaling type. The call encryption key is encrypted using
//! the existing Signal Protocol session.
//!
//! # Protocol Overview
//!
//! 1. Caller generates a random 32-byte call master key
//! 2. Key is encrypted using Signal session to recipient
//! 3. Sent via `<call><enc_rekey>` stanza with encrypted payload
//! 4. Recipient decrypts using Signal session
//! 5. Both parties derive SRTP keys from the master key (Phase 2)

use super::error::CallError;
use wacore_binary::jid::Jid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Call encryption key material.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CallEncryptionKey {
    /// 32-byte master key for the call.
    pub master_key: [u8; 32],
    /// Key generation/version number.
    pub generation: u32,
}

impl CallEncryptionKey {
    /// Generate a new random call encryption key.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut master_key = [0u8; 32];
        rand::rng().fill_bytes(&mut master_key);
        Self {
            master_key,
            generation: 1,
        }
    }

    /// Serialize the key for encryption.
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(36);
        data.extend_from_slice(&self.master_key);
        data.extend_from_slice(&self.generation.to_be_bytes());
        data
    }

    /// Deserialize from decrypted data.
    pub fn deserialize(data: &[u8]) -> Result<Self, CallError> {
        if data.len() < 32 {
            return Err(CallError::Encryption("key data too short".into()));
        }

        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&data[..32]);

        let generation = if data.len() >= 36 {
            u32::from_be_bytes([data[32], data[33], data[34], data[35]])
        } else {
            1
        };

        Ok(Self {
            master_key,
            generation,
        })
    }
}

/// Stub for call encryption operations.
///
/// Full implementation will integrate with Signal Protocol sessions.
pub struct CallEncryption;

impl CallEncryption {
    /// Create enc_rekey payload (stub - returns unencrypted for now).
    ///
    /// In full implementation, this will:
    /// 1. Encrypt the call key using Signal session
    /// 2. Return the encrypted payload for the enc_rekey stanza
    pub async fn create_enc_rekey_payload(
        _recipient: &Jid,
        key: &CallEncryptionKey,
    ) -> Result<Vec<u8>, CallError> {
        // TODO: Encrypt using Signal session
        // For now, return serialized key (not secure - placeholder only)
        Ok(key.serialize())
    }

    /// Decrypt enc_rekey payload (stub).
    ///
    /// In full implementation, this will:
    /// 1. Decrypt using Signal session
    /// 2. Return the call encryption key
    pub async fn decrypt_enc_rekey_payload(
        _sender: &Jid,
        payload: &[u8],
    ) -> Result<CallEncryptionKey, CallError> {
        // TODO: Decrypt using Signal session
        // For now, deserialize directly (not secure - placeholder only)
        CallEncryptionKey::deserialize(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_serialize_deserialize() {
        let key = CallEncryptionKey::generate();
        let data = key.serialize();
        let restored = CallEncryptionKey::deserialize(&data).unwrap();

        assert_eq!(key.master_key, restored.master_key);
        assert_eq!(key.generation, restored.generation);
    }

    #[test]
    fn test_key_generation() {
        let key1 = CallEncryptionKey::generate();
        let key2 = CallEncryptionKey::generate();

        // Keys should be different (random)
        assert_ne!(key1.master_key, key2.master_key);
    }
}
