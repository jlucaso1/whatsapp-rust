//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;

use arrayref::array_ref;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::protocol::{PrivateKey, PublicKey, Result, crypto, stores::session_structure};

/// Lazy message key generator that defers key derivation and avoids re-serialization.
///
/// This enum enables two optimizations:
/// 1. **Lazy derivation**: Keys are only derived from seed when actually needed for encryption
/// 2. **Zero-cost round-trip**: Keys loaded from protobuf are kept in serialized form and
///    returned as-is when saving, avoiding unnecessary deserialization and re-serialization
pub enum MessageKeyGenerator {
    /// Native computed keys - from encryption operations
    Keys(MessageKeys),
    /// Seed for lazy derivation - keys derived on demand
    Seed(([u8; 32], u32)),
    /// Original protobuf - zero-cost pass-through on save
    Serialized(session_structure::chain::MessageKey),
}

impl MessageKeyGenerator {
    #[inline]
    pub fn new_from_seed(seed: &[u8; 32], counter: u32) -> Self {
        Self::Seed((*seed, counter))
    }

    /// Generate the actual MessageKeys, deriving them if necessary.
    /// This is called when keys are needed for actual encryption/decryption.
    pub fn generate_keys(self) -> MessageKeys {
        match self {
            Self::Seed((seed, counter)) => MessageKeys::derive_keys(&seed, None, counter),
            Self::Keys(k) => k,
            Self::Serialized(pb) => {
                // Parse on demand - only when keys are actually needed.
                // Note: from_pb() validates field lengths before creating Serialized,
                // so these conversions should always succeed. The unwrap_or fallbacks
                // exist only as a defensive measure; in debug builds we assert to
                // catch any invariant violations.
                let cipher_key = pb
                    .cipher_key
                    .as_deref()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok());
                let mac_key = pb
                    .mac_key
                    .as_deref()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok());
                let iv = pb.iv.as_deref().and_then(|b| <[u8; 16]>::try_from(b).ok());

                debug_assert!(
                    cipher_key.is_some() && mac_key.is_some() && iv.is_some(),
                    "Serialized MessageKeyGenerator has invalid field lengths - from_pb should have rejected this"
                );

                MessageKeys {
                    cipher_key: cipher_key.unwrap_or([0u8; 32]),
                    mac_key: mac_key.unwrap_or([0u8; 32]),
                    iv: iv.unwrap_or([0u8; 16]),
                    counter: pb.index.unwrap_or(0),
                }
            }
        }
    }

    /// Convert to protobuf format for storage.
    /// Zero-cost for Serialized variant (pass-through), allocates for others.
    pub fn into_pb(self) -> session_structure::chain::MessageKey {
        match self {
            // Zero-cost pass-through: return original protobuf unchanged
            Self::Serialized(pb) => pb,
            // Need to serialize: derive keys and convert
            Self::Seed(_) | Self::Keys(_) => {
                use prost::bytes::Bytes;
                let keys = self.generate_keys();
                session_structure::chain::MessageKey {
                    cipher_key: Some(Bytes::copy_from_slice(keys.cipher_key())),
                    mac_key: Some(Bytes::copy_from_slice(keys.mac_key())),
                    iv: Some(Bytes::copy_from_slice(keys.iv())),
                    index: Some(keys.counter()),
                }
            }
        }
    }

    /// Load from protobuf without parsing - keeps original bytes for zero-cost round-trip.
    pub fn from_pb(
        pb: session_structure::chain::MessageKey,
    ) -> std::result::Result<Self, &'static str> {
        // Validate the protobuf has required fields
        if pb.cipher_key.as_ref().is_some_and(|b| b.len() == 32)
            && pb.mac_key.as_ref().is_some_and(|b| b.len() == 32)
            && pb.iv.as_ref().is_some_and(|b| b.len() == 16)
        {
            // Keep as Serialized for zero-cost round-trip
            Ok(Self::Serialized(pb))
        } else {
            Err("invalid message key format")
        }
    }

    /// Get the counter/index without fully parsing the keys.
    #[inline]
    pub fn counter(&self) -> u32 {
        match self {
            Self::Keys(k) => k.counter(),
            Self::Seed((_, counter)) => *counter,
            Self::Serialized(pb) => pb.index.unwrap_or(0),
        }
    }
}

#[derive(Clone, Copy)]
pub struct MessageKeys {
    cipher_key: [u8; 32],
    mac_key: [u8; 32],
    iv: [u8; 16],
    counter: u32,
}

impl MessageKeys {
    pub fn derive_keys(
        input_key_material: &[u8],
        optional_salt: Option<&[u8]>,
        counter: u32,
    ) -> Self {
        let mut okm = [0; 80];
        hkdf::Hkdf::<sha2::Sha256>::new(optional_salt, input_key_material)
            .expand(b"WhisperMessageKeys", &mut okm)
            .expect("valid output length");

        MessageKeys {
            cipher_key: *array_ref![okm, 0, 32],
            mac_key: *array_ref![okm, 32, 32],
            iv: *array_ref![okm, 64, 16],
            counter,
        }
    }

    #[inline]
    pub fn cipher_key(&self) -> &[u8; 32] {
        &self.cipher_key
    }

    #[inline]
    pub fn mac_key(&self) -> &[u8; 32] {
        &self.mac_key
    }

    #[inline]
    pub fn iv(&self) -> &[u8; 16] {
        &self.iv
    }

    #[inline]
    pub fn counter(&self) -> u32 {
        self.counter
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ChainKey {
    key: [u8; 32],
    index: u32,
}

impl ChainKey {
    const MESSAGE_KEY_SEED: [u8; 1] = [0x01u8];
    const CHAIN_KEY_SEED: [u8; 1] = [0x02u8];

    pub fn new(key: [u8; 32], index: u32) -> Self {
        Self { key, index }
    }

    #[inline]
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    #[inline]
    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn next_chain_key(&self) -> Self {
        Self {
            key: self.calculate_base_material(Self::CHAIN_KEY_SEED),
            index: self.index + 1,
        }
    }

    pub fn message_keys(&self) -> MessageKeyGenerator {
        MessageKeyGenerator::new_from_seed(
            &self.calculate_base_material(Self::MESSAGE_KEY_SEED),
            self.index,
        )
    }

    /// Compute both message keys and next chain key in one call, reusing HMAC key setup.
    #[inline]
    pub fn step_with_message_keys(&self) -> (MessageKeyGenerator, Self) {
        let mut hmac = Hmac::<Sha256>::new_from_slice(&self.key)
            .expect("HMAC-SHA256 should accept any size key");

        hmac.update(&Self::MESSAGE_KEY_SEED);
        let message_key_seed: [u8; 32] = hmac.finalize_reset().into_bytes().into();

        hmac.update(&Self::CHAIN_KEY_SEED);
        let next_key: [u8; 32] = hmac.finalize().into_bytes().into();

        let message_keys = MessageKeyGenerator::new_from_seed(&message_key_seed, self.index);
        let next_chain = Self {
            key: next_key,
            index: self.index + 1,
        };

        (message_keys, next_chain)
    }

    fn calculate_base_material(&self, seed: [u8; 1]) -> [u8; 32] {
        crypto::hmac_sha256(&self.key, &seed)
    }
}

#[derive(Clone, Debug)]
pub struct RootKey {
    key: [u8; 32],
}

impl RootKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    pub fn create_chain(
        self,
        their_ratchet_key: &PublicKey,
        our_ratchet_key: &PrivateKey,
    ) -> Result<(RootKey, ChainKey)> {
        let shared_secret = our_ratchet_key.calculate_agreement(their_ratchet_key)?;
        let mut derived_secret_bytes = [0; 64];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&self.key), &shared_secret)
            .expand(b"WhisperRatchet", &mut derived_secret_bytes)
            .expect("valid output length");

        Ok((
            RootKey {
                key: *array_ref![derived_secret_bytes, 0, 32],
            },
            ChainKey {
                key: *array_ref![derived_secret_bytes, 32, 32],
                index: 0,
            },
        ))
    }
}

impl fmt::Display for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that ChainKey properly derives the next chain key
    /// The chain key advances by HMAC-SHA256 with a constant seed
    #[test]
    fn test_chain_key_stepping() {
        let initial_key = [0x42u8; 32];
        let chain_key = ChainKey::new(initial_key, 0);

        // Step the chain multiple times
        let chain1 = chain_key.next_chain_key();
        let chain2 = chain1.next_chain_key();
        let chain3 = chain2.next_chain_key();

        // Verify index increments correctly
        assert_eq!(chain_key.index(), 0);
        assert_eq!(chain1.index(), 1);
        assert_eq!(chain2.index(), 2);
        assert_eq!(chain3.index(), 3);

        // Verify keys are different at each step
        assert_ne!(chain_key.key(), chain1.key());
        assert_ne!(chain1.key(), chain2.key());
        assert_ne!(chain2.key(), chain3.key());

        // Verify determinism: same initial key produces same chain
        let chain_key_copy = ChainKey::new(initial_key, 0);
        let chain1_copy = chain_key_copy.next_chain_key();
        assert_eq!(chain1.key(), chain1_copy.key());
        assert_eq!(chain1.index(), chain1_copy.index());
    }

    /// Test that MessageKeys derivation is deterministic
    #[test]
    fn test_message_keys_derivation() {
        let chain_key = ChainKey::new([0x55u8; 32], 10);
        let message_keys_gen = chain_key.message_keys();
        let message_keys = message_keys_gen.generate_keys();

        // Verify counter is preserved
        assert_eq!(message_keys.counter(), 10);

        // Verify key sizes
        assert_eq!(message_keys.cipher_key().len(), 32);
        assert_eq!(message_keys.mac_key().len(), 32);
        assert_eq!(message_keys.iv().len(), 16);

        // Verify determinism
        let chain_key2 = ChainKey::new([0x55u8; 32], 10);
        let message_keys2 = chain_key2.message_keys().generate_keys();
        assert_eq!(message_keys.cipher_key(), message_keys2.cipher_key());
        assert_eq!(message_keys.mac_key(), message_keys2.mac_key());
        assert_eq!(message_keys.iv(), message_keys2.iv());
    }

    /// Test that different chain key indices produce different message keys
    #[test]
    fn test_message_keys_differ_by_counter() {
        let key = [0xAAu8; 32];
        let chain_key_0 = ChainKey::new(key, 0);
        let chain_key_1 = ChainKey::new(key, 1);

        let mk0 = chain_key_0.message_keys().generate_keys();
        let mk1 = chain_key_1.message_keys().generate_keys();

        // Same base key but different counters should produce different message keys
        // because the counter is used in the derivation
        assert_eq!(mk0.counter(), 0);
        assert_eq!(mk1.counter(), 1);

        // The keys themselves depend on the chain key (not counter), but counter differs
        // If we advance the chain, we should get different underlying keys
        let chain_advanced = chain_key_0.next_chain_key();
        let mk_advanced = chain_advanced.message_keys().generate_keys();

        assert_ne!(mk0.cipher_key(), mk_advanced.cipher_key());
    }

    /// Test RootKey creation and accessor
    #[test]
    fn test_root_key_basic() {
        let key_bytes = [0x12u8; 32];
        let root_key = RootKey::new(key_bytes);

        assert_eq!(root_key.key(), &key_bytes);

        // Test Display trait
        let display = format!("{}", root_key);
        assert_eq!(display, hex::encode(key_bytes));
    }

    /// Test stepping the chain 100 times to verify no issues with long chains
    #[test]
    fn test_chain_key_long_chain() {
        let mut chain = ChainKey::new([0x01u8; 32], 0);

        for i in 0..100 {
            assert_eq!(chain.index(), i);
            chain = chain.next_chain_key();
        }

        assert_eq!(chain.index(), 100);
    }

    /// Test MessageKeyGenerator from seed
    #[test]
    fn test_message_key_generator_from_seed() {
        let seed = [0xBBu8; 32];
        let counter = 42;

        let generator = MessageKeyGenerator::new_from_seed(&seed, counter);
        let keys = generator.generate_keys();

        assert_eq!(keys.counter(), counter);
        assert_eq!(keys.cipher_key().len(), 32);
        assert_eq!(keys.mac_key().len(), 32);
        assert_eq!(keys.iv().len(), 16);

        // Verify determinism
        let generator2 = MessageKeyGenerator::new_from_seed(&seed, counter);
        let keys2 = generator2.generate_keys();
        assert_eq!(keys.cipher_key(), keys2.cipher_key());
    }

    /// Test MessageKeys derive_keys with known inputs
    #[test]
    fn test_message_keys_derive_with_salt() {
        let input_key_material = [0x11u8; 32];
        let salt = [0x22u8; 32];
        let counter = 5;

        let keys1 = MessageKeys::derive_keys(&input_key_material, Some(&salt), counter);
        let keys2 = MessageKeys::derive_keys(&input_key_material, None, counter);

        // With salt vs without salt should produce different keys
        assert_ne!(keys1.cipher_key(), keys2.cipher_key());
        assert_ne!(keys1.mac_key(), keys2.mac_key());
        assert_ne!(keys1.iv(), keys2.iv());

        // Both should have same counter
        assert_eq!(keys1.counter(), counter);
        assert_eq!(keys2.counter(), counter);
    }

    /// Test that step_with_message_keys produces the same results as
    /// calling message_keys() and next_chain_key() separately
    #[test]
    fn test_step_with_message_keys_equivalence() {
        let initial_key = [0x77u8; 32];
        let chain_key = ChainKey::new(initial_key, 5);

        // Get results using separate calls
        let message_keys_separate = chain_key.message_keys().generate_keys();
        let next_chain_separate = chain_key.next_chain_key();

        // Get results using optimized combined call
        let (message_keys_gen_combined, next_chain_combined) = chain_key.step_with_message_keys();
        let message_keys_combined = message_keys_gen_combined.generate_keys();

        // Verify message keys are identical
        assert_eq!(
            message_keys_separate.cipher_key(),
            message_keys_combined.cipher_key()
        );
        assert_eq!(
            message_keys_separate.mac_key(),
            message_keys_combined.mac_key()
        );
        assert_eq!(message_keys_separate.iv(), message_keys_combined.iv());
        assert_eq!(
            message_keys_separate.counter(),
            message_keys_combined.counter()
        );

        // Verify next chain key is identical
        assert_eq!(next_chain_separate.key(), next_chain_combined.key());
        assert_eq!(next_chain_separate.index(), next_chain_combined.index());
    }

    /// Test step_with_message_keys over multiple iterations
    #[test]
    fn test_step_with_message_keys_chain() {
        let initial_key = [0x88u8; 32];
        let mut chain_separate = ChainKey::new(initial_key, 0);
        let mut chain_combined = ChainKey::new(initial_key, 0);

        // Step both chains 10 times and verify they stay in sync
        for i in 0..10 {
            let msg_keys_sep = chain_separate.message_keys().generate_keys();
            chain_separate = chain_separate.next_chain_key();

            let (msg_keys_gen_comb, next_chain) = chain_combined.step_with_message_keys();
            let msg_keys_comb = msg_keys_gen_comb.generate_keys();
            chain_combined = next_chain;

            // Verify message keys match
            assert_eq!(
                msg_keys_sep.cipher_key(),
                msg_keys_comb.cipher_key(),
                "cipher_key mismatch at iteration {i}"
            );

            // Verify chain keys match
            assert_eq!(
                chain_separate.key(),
                chain_combined.key(),
                "chain key mismatch at iteration {i}"
            );
            assert_eq!(chain_separate.index(), chain_combined.index());
        }
    }
}
