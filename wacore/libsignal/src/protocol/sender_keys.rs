//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::VecDeque;

use itertools::Itertools;
use prost::Message;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::protocol::crypto::hmac_sha256;
use crate::protocol::stores::{
    SenderKeyRecordStructure, SenderKeyStateStructure, sender_key_state_structure,
};
use crate::protocol::{PrivateKey, PublicKey, SignalProtocolError, consts};

/// A distinct error type to keep from accidentally propagating deserialization errors.
#[derive(Debug)]
pub struct InvalidSenderKeySessionError(&'static str);

impl std::fmt::Display for InvalidSenderKeySessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone)]
pub struct SenderMessageKey {
    iteration: u32,
    iv: [u8; 16],
    cipher_key: [u8; 32],
    seed: [u8; 32],
}

impl SenderMessageKey {
    pub fn new(iteration: u32, seed: [u8; 32]) -> Self {
        let mut derived = [0u8; 48];
        hkdf::Hkdf::<sha2::Sha256>::new(None, &seed)
            .expand(b"WhisperGroup", &mut derived)
            .expect("valid output length");
        Self {
            iteration,
            seed,
            iv: derived[0..16].try_into().expect("correct iv length"),
            cipher_key: derived[16..48]
                .try_into()
                .expect("correct cipher_key length"),
        }
    }

    pub(crate) fn from_protobuf(smk: sender_key_state_structure::SenderMessageKey) -> Self {
        let seed_bytes = smk.seed.unwrap_or_default();
        let seed: [u8; 32] = seed_bytes
            .as_ref()
            .try_into()
            .expect("SenderMessageKey seed must be exactly 32 bytes");
        Self::new(smk.iteration.unwrap_or_default(), seed)
    }

    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    pub fn cipher_key(&self) -> &[u8] {
        &self.cipher_key
    }

    pub(crate) fn as_protobuf(&self) -> sender_key_state_structure::SenderMessageKey {
        use prost::bytes::Bytes;
        sender_key_state_structure::SenderMessageKey {
            iteration: Some(self.iteration),
            seed: Some(Bytes::copy_from_slice(&self.seed)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SenderChainKey {
    iteration: u32,
    chain_key: [u8; 32],
}

impl SenderChainKey {
    const MESSAGE_KEY_SEED: u8 = 0x01;
    const CHAIN_KEY_SEED: u8 = 0x02;

    pub(crate) fn new(iteration: u32, chain_key: [u8; 32]) -> Self {
        Self {
            iteration,
            chain_key,
        }
    }

    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.chain_key
    }

    pub fn next(&self) -> Result<SenderChainKey, SignalProtocolError> {
        let new_iteration = self.iteration.checked_add(1).ok_or_else(|| {
            SignalProtocolError::InvalidState(
                "sender_chain_key_next",
                "Sender chain is too long".into(),
            )
        })?;

        Ok(SenderChainKey::new(
            new_iteration,
            self.get_derivative(Self::CHAIN_KEY_SEED),
        ))
    }

    pub fn sender_message_key(&self) -> SenderMessageKey {
        SenderMessageKey::new(self.iteration, self.get_derivative(Self::MESSAGE_KEY_SEED))
    }

    /// Compute both sender message key and next chain key in one call, reusing HMAC key setup.
    #[inline]
    pub fn step_with_message_key(&self) -> Result<(SenderMessageKey, Self), SignalProtocolError> {
        let new_iteration = self.iteration.checked_add(1).ok_or_else(|| {
            SignalProtocolError::InvalidState(
                "sender_chain_key_step",
                "Sender chain is too long".into(),
            )
        })?;

        let mut hmac = Hmac::<Sha256>::new_from_slice(&self.chain_key)
            .expect("HMAC-SHA256 should accept any size key");

        hmac.update(&[Self::MESSAGE_KEY_SEED]);
        let message_key_seed: [u8; 32] = hmac.finalize_reset().into_bytes().into();

        hmac.update(&[Self::CHAIN_KEY_SEED]);
        let next_chain_key: [u8; 32] = hmac.finalize().into_bytes().into();

        let message_key = SenderMessageKey::new(self.iteration, message_key_seed);
        let next_chain = Self {
            iteration: new_iteration,
            chain_key: next_chain_key,
        };

        Ok((message_key, next_chain))
    }

    #[inline]
    fn get_derivative(&self, label: u8) -> [u8; 32] {
        let label = [label];
        hmac_sha256(&self.chain_key, &label)
    }

    pub(crate) fn as_protobuf(&self) -> sender_key_state_structure::SenderChainKey {
        use prost::bytes::Bytes;
        sender_key_state_structure::SenderChainKey {
            iteration: Some(self.iteration),
            seed: Some(Bytes::copy_from_slice(&self.chain_key)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SenderKeyState {
    state: SenderKeyStateStructure,
}

impl SenderKeyState {
    pub fn new(
        _message_version: u8,
        chain_id: u32,
        iteration: u32,
        chain_key: &[u8],
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) -> SenderKeyState {
        use prost::bytes::Bytes;
        let chain_key_arr: [u8; 32] = chain_key.try_into().expect("chain_key must be 32 bytes");
        let state = SenderKeyStateStructure {
            sender_key_id: Some(chain_id),
            sender_chain_key: Some(SenderChainKey::new(iteration, chain_key_arr).as_protobuf()),
            sender_signing_key: Some(sender_key_state_structure::SenderSigningKey {
                public: Some(Bytes::copy_from_slice(&signature_key.serialize())),
                private: signature_private_key
                    .map(|k| Bytes::copy_from_slice(k.serialize().as_ref())),
            }),
            sender_message_keys: vec![],
        };

        Self { state }
    }

    pub(crate) fn from_protobuf(state: SenderKeyStateStructure) -> Self {
        Self { state }
    }

    pub fn message_version(&self) -> u32 {
        3
    }

    pub fn chain_id(&self) -> u32 {
        self.state.sender_key_id.unwrap_or_default()
    }

    pub fn sender_chain_key(&self) -> Option<SenderChainKey> {
        let sender_chain = self.state.sender_chain_key.as_ref()?;
        let seed: [u8; 32] = sender_chain
            .seed
            .as_deref()
            .unwrap_or_default()
            .try_into()
            .ok()?;
        Some(SenderChainKey::new(
            sender_chain.iteration.unwrap_or_default(),
            seed,
        ))
    }

    pub fn set_sender_chain_key(&mut self, chain_key: SenderChainKey) {
        self.state.sender_chain_key = Some(chain_key.as_protobuf());
    }

    pub fn signing_key_public(&self) -> Result<PublicKey, InvalidSenderKeySessionError> {
        if let Some(ref signing_key) = self.state.sender_signing_key {
            let public = signing_key
                .public
                .as_ref()
                .ok_or(InvalidSenderKeySessionError("missing public key bytes"))?;
            PublicKey::try_from(&public[..])
                .map_err(|_| InvalidSenderKeySessionError("invalid public signing key"))
        } else {
            Err(InvalidSenderKeySessionError("missing signing key"))
        }
    }

    pub fn signing_key_private(&self) -> Result<PrivateKey, InvalidSenderKeySessionError> {
        if let Some(ref signing_key) = self.state.sender_signing_key {
            let private = signing_key
                .private
                .as_ref()
                .ok_or(InvalidSenderKeySessionError("missing private key bytes"))?;
            PrivateKey::deserialize(private)
                .map_err(|_| InvalidSenderKeySessionError("invalid private signing key"))
        } else {
            Err(InvalidSenderKeySessionError("missing signing key"))
        }
    }

    pub(crate) fn as_protobuf(&self) -> SenderKeyStateStructure {
        self.state.clone()
    }

    pub fn add_sender_message_key(&mut self, sender_message_key: &SenderMessageKey) {
        self.state
            .sender_message_keys
            .push(sender_message_key.as_protobuf());
        // AMORTIZED EVICTION: Only prune when exceeding MAX + threshold.
        // This reduces O(n) drain() calls from every insert to once every PRUNE_THRESHOLD inserts.
        let len = self.state.sender_message_keys.len();
        if len > consts::MAX_MESSAGE_KEYS + consts::MESSAGE_KEY_PRUNE_THRESHOLD {
            let excess = len - consts::MAX_MESSAGE_KEYS;
            self.state.sender_message_keys.drain(..excess);
        }
    }

    pub(crate) fn remove_sender_message_key(&mut self, iteration: u32) -> Option<SenderMessageKey> {
        if let Some(index) = self
            .state
            .sender_message_keys
            .iter()
            .position(|x| x.iteration.unwrap_or_default() == iteration)
        {
            let smk = self.state.sender_message_keys.remove(index);
            Some(SenderMessageKey::from_protobuf(smk))
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct SenderKeyRecord {
    states: VecDeque<SenderKeyState>,
}

impl SenderKeyRecord {
    pub fn set_states_for_testing(&mut self, states: std::collections::VecDeque<SenderKeyState>) {
        self.states = states;
    }

    pub fn new_empty() -> Self {
        Self {
            states: VecDeque::with_capacity(consts::MAX_SENDER_KEY_STATES),
        }
    }

    pub fn deserialize(buf: &[u8]) -> Result<SenderKeyRecord, SignalProtocolError> {
        let skr = SenderKeyRecordStructure::decode(buf)
            .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;

        let mut states = VecDeque::with_capacity(skr.sender_key_states.len());
        for state in skr.sender_key_states {
            states.push_back(SenderKeyState::from_protobuf(state))
        }
        Ok(Self { states })
    }

    pub fn sender_key_state(&self) -> Result<&SenderKeyState, InvalidSenderKeySessionError> {
        if !self.states.is_empty() {
            return Ok(&self.states[0]);
        }
        Err(InvalidSenderKeySessionError("empty sender key state"))
    }

    pub fn sender_key_state_mut(
        &mut self,
    ) -> Result<&mut SenderKeyState, InvalidSenderKeySessionError> {
        if !self.states.is_empty() {
            return Ok(&mut self.states[0]);
        }
        Err(InvalidSenderKeySessionError("empty sender key state"))
    }

    pub(crate) fn sender_key_state_for_chain_id(
        &mut self,
        chain_id: u32,
    ) -> Option<&mut SenderKeyState> {
        for i in 0..self.states.len() {
            if self.states[i].chain_id() == chain_id {
                return Some(&mut self.states[i]);
            }
        }
        None
    }

    pub(crate) fn chain_ids_for_logging(&self) -> impl ExactSizeIterator<Item = u32> + '_ {
        self.states.iter().map(|state| state.chain_id())
    }

    pub fn add_sender_key_state(
        &mut self,
        message_version: u8,
        chain_id: u32,
        iteration: u32,
        chain_key: &[u8],
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) {
        let existing_state = self.remove_state(chain_id, signature_key);

        if self.remove_states_with_chain_id(chain_id) > 0 {
            log::warn!(
                "Removed a matching chain_id ({chain_id}) found with a different public key"
            );
        }

        let state = match existing_state {
            None => SenderKeyState::new(
                message_version,
                chain_id,
                iteration,
                chain_key,
                signature_key,
                signature_private_key,
            ),
            Some(state) => state,
        };

        while self.states.len() >= consts::MAX_SENDER_KEY_STATES {
            self.states.pop_back();
        }

        self.states.push_front(state);
    }

    /// Remove the state with the matching `chain_id` and `signature_key`.
    ///
    /// Skips any bad protobufs.
    fn remove_state(&mut self, chain_id: u32, signature_key: PublicKey) -> Option<SenderKeyState> {
        let (index, _state) = self.states.iter().find_position(|state| {
            state.chain_id() == chain_id && state.signing_key_public().ok() == Some(signature_key)
        })?;

        self.states.remove(index)
    }

    /// Returns the number of removed states.
    ///
    /// Skips any bad protobufs.
    fn remove_states_with_chain_id(&mut self, chain_id: u32) -> usize {
        let initial_length = self.states.len();
        self.states.retain(|state| state.chain_id() != chain_id);
        initial_length - self.states.len()
    }

    pub(crate) fn as_protobuf(&self) -> SenderKeyRecordStructure {
        let mut states = Vec::with_capacity(self.states.len());
        for state in &self.states {
            states.push(state.as_protobuf());
        }

        SenderKeyRecordStructure {
            sender_key_states: states,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, SignalProtocolError> {
        Ok(self.as_protobuf().encode_to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::KeyPair;

    /// Test SenderMessageKey derivation is deterministic
    #[test]
    fn test_sender_message_key_derivation() {
        let seed = [0x42u8; 32];
        let iteration = 10;

        let smk1 = SenderMessageKey::new(iteration, seed);
        let smk2 = SenderMessageKey::new(iteration, seed);

        // Same seed and iteration should produce same keys
        assert_eq!(smk1.iteration(), smk2.iteration());
        assert_eq!(smk1.iv(), smk2.iv());
        assert_eq!(smk1.cipher_key(), smk2.cipher_key());
    }

    /// Test SenderMessageKey produces different keys for different seeds
    #[test]
    fn test_sender_message_key_different_seeds() {
        let seed1 = [0x42u8; 32];
        let seed2 = [0x43u8; 32];

        let smk1 = SenderMessageKey::new(0, seed1);
        let smk2 = SenderMessageKey::new(0, seed2);

        assert_ne!(smk1.iv(), smk2.iv());
        assert_ne!(smk1.cipher_key(), smk2.cipher_key());
    }

    /// Test SenderChainKey iteration and stepping
    #[test]
    fn test_sender_chain_key_stepping() {
        let initial_chain = [0x55u8; 32];
        let sck = SenderChainKey::new(0, initial_chain);

        let sck1 = sck
            .next()
            .expect("sender chain key iteration should succeed");
        let sck2 = sck1
            .next()
            .expect("sender chain key iteration should succeed");
        let sck3 = sck2
            .next()
            .expect("sender chain key iteration should succeed");

        // Verify iteration increments
        assert_eq!(sck.iteration(), 0);
        assert_eq!(sck1.iteration(), 1);
        assert_eq!(sck2.iteration(), 2);
        assert_eq!(sck3.iteration(), 3);

        // Verify seeds change at each step
        assert_ne!(sck.seed(), sck1.seed());
        assert_ne!(sck1.seed(), sck2.seed());
        assert_ne!(sck2.seed(), sck3.seed());
    }

    /// Test SenderChainKey produces correct message keys
    #[test]
    fn test_sender_chain_key_message_key() {
        let chain = [0x55u8; 32];
        let sck = SenderChainKey::new(5, chain);

        let smk = sck.sender_message_key();

        assert_eq!(smk.iteration(), 5);
        assert_eq!(smk.iv().len(), 16);
        assert_eq!(smk.cipher_key().len(), 32);
    }

    /// Test SenderChainKey stepping is deterministic
    #[test]
    fn test_sender_chain_key_determinism() {
        let chain = [0x77u8; 32];

        let sck1 = SenderChainKey::new(0, chain);
        let sck2 = SenderChainKey::new(0, chain);

        let next1 = sck1
            .next()
            .expect("sender chain key iteration should succeed");
        let next2 = sck2
            .next()
            .expect("sender chain key iteration should succeed");

        assert_eq!(next1.seed(), next2.seed());
        assert_eq!(next1.iteration(), next2.iteration());
    }

    /// Test SenderKeyState basic operations
    #[test]
    fn test_sender_key_state_basic() {
        let mut rng = rand::rng();
        let keypair = KeyPair::generate(&mut rng);
        let chain_key = [0x42u8; 32];

        let state = SenderKeyState::new(3, 12345, 0, &chain_key, keypair.public_key, None);

        assert_eq!(state.chain_id(), 12345);
        assert_eq!(state.message_version(), 3);
        assert!(state.sender_chain_key().is_some());
        assert!(state.signing_key_public().is_ok());
        // Private key was not provided
        assert!(state.signing_key_private().is_err());
    }

    /// Test SenderKeyState with private signing key
    #[test]
    fn test_sender_key_state_with_private_key() {
        let mut rng = rand::rng();
        let keypair = KeyPair::generate(&mut rng);
        let chain_key = [0x42u8; 32];

        let state = SenderKeyState::new(
            3,
            12345,
            0,
            &chain_key,
            keypair.public_key,
            Some(keypair.private_key),
        );

        assert!(state.signing_key_public().is_ok());
        assert!(state.signing_key_private().is_ok());
    }

    /// Test SenderKeyState chain key operations
    #[test]
    fn test_sender_key_state_chain_key_update() {
        let mut rng = rand::rng();
        let keypair = KeyPair::generate(&mut rng);
        let chain_key = [0x42u8; 32];

        let mut state = SenderKeyState::new(
            3,
            12345,
            0,
            &chain_key,
            keypair.public_key,
            Some(keypair.private_key),
        );

        let initial_sck = state
            .sender_chain_key()
            .expect("sender chain key should exist");
        let next_sck = initial_sck
            .next()
            .expect("sender chain key iteration should succeed");

        state.set_sender_chain_key(next_sck);

        let updated_sck = state
            .sender_chain_key()
            .expect("sender chain key should exist");
        assert_eq!(updated_sck.iteration(), 1);
    }

    /// Test SenderKeyState message key storage
    #[test]
    fn test_sender_key_state_message_key_storage() {
        let mut rng = rand::rng();
        let keypair = KeyPair::generate(&mut rng);
        let chain_key = [0x42u8; 32];

        let mut state = SenderKeyState::new(
            3,
            12345,
            0,
            &chain_key,
            keypair.public_key,
            Some(keypair.private_key),
        );

        let smk = SenderMessageKey::new(5, [0xAA; 32]);
        state.add_sender_message_key(&smk);

        // Should be able to retrieve it
        let retrieved = state.remove_sender_message_key(5);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.expect("message key should exist").iteration(), 5);

        // Should not find it again
        let not_found = state.remove_sender_message_key(5);
        assert!(not_found.is_none());
    }

    /// Test SenderKeyState message key limit
    #[test]
    fn test_sender_key_state_message_key_limit() {
        let mut rng = rand::rng();
        let keypair = KeyPair::generate(&mut rng);
        let chain_key = [0x42u8; 32];

        let mut state = SenderKeyState::new(
            3,
            12345,
            0,
            &chain_key,
            keypair.public_key,
            Some(keypair.private_key),
        );

        // Amortized eviction uses MESSAGE_KEY_PRUNE_THRESHOLD.
        // Eviction triggers when len > MAX_MESSAGE_KEYS + MESSAGE_KEY_PRUNE_THRESHOLD.
        // Add MAX_MESSAGE_KEYS + 100 keys to ensure eviction happens.
        let total_keys = consts::MAX_MESSAGE_KEYS + 100;
        for i in 0..total_keys {
            let smk = SenderMessageKey::new(i as u32, [0xBB; 32]);
            state.add_sender_message_key(&smk);
        }

        // After adding 2100 keys:
        // - At 2051: prune to 2000 (removes first 51 keys: 0-50)
        // - Continue adding keys 2051-2099 (49 more)
        // - Final len = 2049, no second prune since 2049 <= 2050
        // So keys 0-50 (51 keys) should be evicted.
        let evicted_count = consts::MESSAGE_KEY_PRUNE_THRESHOLD + 1; // 51
        for i in 0..evicted_count {
            let not_found = state.remove_sender_message_key(i as u32);
            assert!(
                not_found.is_none(),
                "Key at iteration {} should have been evicted",
                i
            );
        }
    }

    /// Test SenderKeyRecord basic operations
    #[test]
    fn test_sender_key_record_basic() {
        let record = SenderKeyRecord::new_empty();
        assert!(record.sender_key_state().is_err());
    }

    /// Test SenderKeyRecord add and retrieve state
    #[test]
    fn test_sender_key_record_add_state() {
        let mut rng = rand::rng();
        let keypair = KeyPair::generate(&mut rng);
        let chain_key = [0x42u8; 32];

        let mut record = SenderKeyRecord::new_empty();
        record.add_sender_key_state(
            3,
            12345,
            0,
            &chain_key,
            keypair.public_key,
            Some(keypair.private_key),
        );

        let state = record
            .sender_key_state()
            .expect("sender key state should exist");
        assert_eq!(state.chain_id(), 12345);
    }

    /// Test SenderKeyRecord state limit
    #[test]
    fn test_sender_key_record_state_limit() {
        let mut rng = rand::rng();
        let chain_key = [0x42u8; 32];

        let mut record = SenderKeyRecord::new_empty();

        // Add more than MAX_SENDER_KEY_STATES
        for i in 0..(consts::MAX_SENDER_KEY_STATES + 5) {
            let keypair = KeyPair::generate(&mut rng);
            record.add_sender_key_state(
                3,
                i as u32,
                0,
                &chain_key,
                keypair.public_key,
                Some(keypair.private_key),
            );
        }

        // Should not have more than MAX_SENDER_KEY_STATES
        let chain_ids: Vec<u32> = record.chain_ids_for_logging().collect();
        assert!(chain_ids.len() <= consts::MAX_SENDER_KEY_STATES);
    }

    /// Test SenderKeyRecord chain ID lookup
    #[test]
    fn test_sender_key_record_chain_id_lookup() {
        let mut rng = rand::rng();
        let keypair1 = KeyPair::generate(&mut rng);
        let keypair2 = KeyPair::generate(&mut rng);
        let chain_key = [0x42u8; 32];

        let mut record = SenderKeyRecord::new_empty();
        record.add_sender_key_state(
            3,
            111,
            0,
            &chain_key,
            keypair1.public_key,
            Some(keypair1.private_key),
        );
        record.add_sender_key_state(
            3,
            222,
            0,
            &chain_key,
            keypair2.public_key,
            Some(keypair2.private_key),
        );

        // Should find chain 222 (most recent is at front)
        let state = record.sender_key_state_for_chain_id(222);
        assert!(state.is_some());
        assert_eq!(state.expect("state should exist").chain_id(), 222);

        // Should find chain 111
        let state = record.sender_key_state_for_chain_id(111);
        assert!(state.is_some());
        assert_eq!(state.expect("state should exist").chain_id(), 111);

        // Should not find non-existent chain
        let state = record.sender_key_state_for_chain_id(333);
        assert!(state.is_none());
    }

    /// Test SenderKeyRecord serialization roundtrip
    #[test]
    fn test_sender_key_record_serialization() {
        let mut rng = rand::rng();
        let keypair = KeyPair::generate(&mut rng);
        let chain_key = [0x42u8; 32];

        let mut record = SenderKeyRecord::new_empty();
        record.add_sender_key_state(
            3,
            12345,
            5,
            &chain_key,
            keypair.public_key,
            Some(keypair.private_key),
        );

        let serialized = record.serialize().expect("serialization should succeed");
        let deserialized =
            SenderKeyRecord::deserialize(&serialized).expect("deserialization should succeed");

        let state = deserialized
            .sender_key_state()
            .expect("sender key state should exist");
        assert_eq!(state.chain_id(), 12345);
        assert!(state.sender_chain_key().is_some());
    }

    /// Test that step_with_message_key produces the same results as
    /// calling sender_message_key() and next() separately
    #[test]
    fn test_step_with_message_key_equivalence() {
        let chain = [0x99u8; 32];
        let sck = SenderChainKey::new(5, chain);

        // Get results using separate calls
        let msg_key_separate = sck.sender_message_key();
        let next_chain_separate = sck.next().expect("next should succeed");

        // Get results using optimized combined call
        let (msg_key_combined, next_chain_combined) = sck
            .step_with_message_key()
            .expect("step_with_message_key should succeed");

        // Verify message keys are identical
        assert_eq!(msg_key_separate.iteration(), msg_key_combined.iteration());
        assert_eq!(msg_key_separate.iv(), msg_key_combined.iv());
        assert_eq!(msg_key_separate.cipher_key(), msg_key_combined.cipher_key());

        // Verify next chain key is identical
        assert_eq!(next_chain_separate.seed(), next_chain_combined.seed());
        assert_eq!(
            next_chain_separate.iteration(),
            next_chain_combined.iteration()
        );
    }

    /// Test step_with_message_key over multiple iterations
    #[test]
    fn test_step_with_message_key_chain() {
        let initial_chain = [0xBBu8; 32];
        let mut chain_separate = SenderChainKey::new(0, initial_chain);
        let mut chain_combined = SenderChainKey::new(0, initial_chain);

        // Step both chains 10 times and verify they stay in sync
        for i in 0..10 {
            let msg_key_sep = chain_separate.sender_message_key();
            chain_separate = chain_separate.next().expect("next should succeed");

            let (msg_key_comb, next_chain) = chain_combined
                .step_with_message_key()
                .expect("step_with_message_key should succeed");
            chain_combined = next_chain;

            // Verify message keys match
            assert_eq!(
                msg_key_sep.cipher_key(),
                msg_key_comb.cipher_key(),
                "cipher_key mismatch at iteration {i}"
            );

            // Verify chain keys match
            assert_eq!(
                chain_separate.seed(),
                chain_combined.seed(),
                "chain key mismatch at iteration {i}"
            );
            assert_eq!(chain_separate.iteration(), chain_combined.iteration());
        }
    }
}
