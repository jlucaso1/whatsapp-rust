//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::VecDeque;

use itertools::Itertools;
use prost::Message;

use crate::libsignal::protocol::crypto::hmac_sha256;
use crate::libsignal::protocol::stores::{
    SenderKeyRecordStructure, SenderKeyStateStructure, sender_key_state_structure,
};
use crate::libsignal::protocol::{PrivateKey, PublicKey, SignalProtocolError, consts};

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
    iv: Vec<u8>,
    cipher_key: Vec<u8>,
    seed: Vec<u8>,
}

impl SenderMessageKey {
    pub fn new(iteration: u32, seed: Vec<u8>) -> Self {
        let mut derived = [0; 48];
        hkdf::Hkdf::<sha2::Sha256>::new(None, &seed)
            .expand(b"WhisperGroup", &mut derived)
            .expect("valid output length");
        Self {
            iteration,
            seed,
            iv: derived[0..16].to_vec(),
            cipher_key: derived[16..48].to_vec(),
        }
    }

    pub(crate) fn from_protobuf(smk: sender_key_state_structure::SenderMessageKey) -> Self {
        Self::new(smk.iteration, smk.seed)
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
        sender_key_state_structure::SenderMessageKey {
            iteration: self.iteration,
            seed: self.seed.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SenderChainKey {
    iteration: u32,
    chain_key: Vec<u8>,
}

impl SenderChainKey {
    const MESSAGE_KEY_SEED: u8 = 0x01;
    const CHAIN_KEY_SEED: u8 = 0x02;

    pub(crate) fn new(iteration: u32, chain_key: Vec<u8>) -> Self {
        Self {
            iteration,
            chain_key,
        }
    }

    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    pub fn seed(&self) -> &[u8] {
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

    fn get_derivative(&self, label: u8) -> Vec<u8> {
        let label = [label];
        hmac_sha256(&self.chain_key, &label).to_vec()
    }

    pub(crate) fn as_protobuf(&self) -> sender_key_state_structure::SenderChainKey {
        sender_key_state_structure::SenderChainKey {
            iteration: self.iteration,
            seed: self.chain_key.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SenderKeyState {
    state: SenderKeyStateStructure,
}

impl SenderKeyState {
    pub fn new(
        message_version: u8,
        chain_id: u32,
        iteration: u32,
        chain_key: &[u8],
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) -> SenderKeyState {
        let state = SenderKeyStateStructure {
            message_version: message_version as u32,
            chain_id,
            sender_chain_key: Some(
                SenderChainKey::new(iteration, chain_key.to_vec()).as_protobuf(),
            ),
            sender_signing_key: Some(sender_key_state_structure::SenderSigningKey {
                public: signature_key.serialize().to_vec(),
                private: match signature_private_key {
                    None => vec![],
                    Some(k) => k.serialize().to_vec(),
                },
            }),
            sender_message_keys: vec![],
        };

        Self { state }
    }

    pub(crate) fn from_protobuf(state: SenderKeyStateStructure) -> Self {
        Self { state }
    }

    pub fn message_version(&self) -> u32 {
        match self.state.message_version {
            0 => 3, // the first SenderKey version
            v => v,
        }
    }

    pub fn chain_id(&self) -> u32 {
        self.state.chain_id
    }

    pub fn sender_chain_key(&self) -> Option<SenderChainKey> {
        let sender_chain = self.state.sender_chain_key.as_ref()?;
        Some(SenderChainKey::new(
            sender_chain.iteration,
            sender_chain.seed.clone(),
        ))
    }

    pub fn set_sender_chain_key(&mut self, chain_key: SenderChainKey) {
        self.state.sender_chain_key = Some(chain_key.as_protobuf());
    }

    pub fn signing_key_public(&self) -> Result<PublicKey, InvalidSenderKeySessionError> {
        if let Some(ref signing_key) = self.state.sender_signing_key {
            PublicKey::try_from(&signing_key.public[..])
                .map_err(|_| InvalidSenderKeySessionError("invalid public signing key"))
        } else {
            Err(InvalidSenderKeySessionError("missing signing key"))
        }
    }

    pub fn signing_key_private(&self) -> Result<PrivateKey, InvalidSenderKeySessionError> {
        if let Some(ref signing_key) = self.state.sender_signing_key {
            PrivateKey::deserialize(&signing_key.private)
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
        while self.state.sender_message_keys.len() > consts::MAX_MESSAGE_KEYS {
            self.state.sender_message_keys.remove(0);
        }
    }

    pub(crate) fn remove_sender_message_key(&mut self, iteration: u32) -> Option<SenderMessageKey> {
        if let Some(index) = self
            .state
            .sender_message_keys
            .iter()
            .position(|x| x.iteration == iteration)
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
