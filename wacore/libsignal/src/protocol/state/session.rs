//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::result::Result;

use prost::Message;
use subtle::ConstantTimeEq;

use crate::core::curve::KeyType;
use crate::protocol::ratchet::keys::MessageKeyGenerator;
use crate::protocol::ratchet::{ChainKey, RootKey};
use crate::protocol::state::{PreKeyId, SignedPreKeyId};
use crate::protocol::stores::session_structure::{self};
use crate::protocol::stores::{RecordStructure, SessionStructure};
use crate::protocol::{IdentityKey, KeyPair, PrivateKey, PublicKey, SignalProtocolError, consts};

/// A distinct error type to keep from accidentally propagating deserialization errors.
#[derive(Debug)]
pub struct InvalidSessionError(&'static str);

impl std::fmt::Display for InvalidSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<InvalidSessionError> for SignalProtocolError {
    fn from(e: InvalidSessionError) -> Self {
        Self::InvalidSessionStructure(e.0)
    }
}

#[derive(Debug, Clone)]
pub struct UnacknowledgedPreKeyMessageItems {
    pre_key_id: Option<PreKeyId>,
    signed_pre_key_id: SignedPreKeyId,
    base_key: PublicKey,
}

impl UnacknowledgedPreKeyMessageItems {
    fn new(
        pre_key_id: Option<PreKeyId>,
        signed_pre_key_id: SignedPreKeyId,
        base_key: PublicKey,
    ) -> Self {
        Self {
            pre_key_id,
            signed_pre_key_id,
            base_key,
        }
    }

    pub fn pre_key_id(&self) -> Option<PreKeyId> {
        self.pre_key_id
    }

    pub fn signed_pre_key_id(&self) -> SignedPreKeyId {
        self.signed_pre_key_id
    }

    pub fn base_key(&self) -> &PublicKey {
        &self.base_key
    }
}

#[derive(Clone, Debug)]
pub struct SessionState {
    session: SessionStructure,
}

impl SessionState {
    pub fn from_session_structure(session: SessionStructure) -> Self {
        Self { session }
    }

    pub fn new(
        version: u8,
        our_identity: &IdentityKey,
        their_identity: &IdentityKey,
        root_key: &RootKey,
        alice_base_key: &PublicKey,
    ) -> Self {
        Self {
            session: SessionStructure {
                session_version: Some(version as u32),
                local_identity_public: Some(our_identity.public_key().serialize().to_vec()),
                remote_identity_public: Some(their_identity.serialize().to_vec()),
                root_key: Some(root_key.key().to_vec()),
                previous_counter: Some(0),
                sender_chain: None,
                receiver_chains: vec![],
                pending_pre_key: None,
                remote_registration_id: Some(0),
                local_registration_id: Some(0),
                alice_base_key: Some(alice_base_key.serialize().to_vec()),
                needs_refresh: None,
                pending_key_exchange: None,
            },
        }
    }

    pub fn alice_base_key(&self) -> &[u8] {
        self.session.alice_base_key.as_deref().unwrap_or(&[])
    }

    pub fn session_version(&self) -> Result<u32, InvalidSessionError> {
        match self.session.session_version.unwrap_or(0) {
            0 => Ok(2),
            v => Ok(v),
        }
    }

    pub fn remote_identity_key(&self) -> Result<Option<IdentityKey>, InvalidSessionError> {
        let bytes = self
            .session
            .remote_identity_public
            .as_deref()
            .unwrap_or(&[]);
        match bytes.len() {
            0 => Ok(None),
            _ => Ok(Some(IdentityKey::decode(bytes).map_err(|_| {
                InvalidSessionError("invalid remote identity key")
            })?)),
        }
    }

    pub fn remote_identity_key_bytes(&self) -> Result<Option<Vec<u8>>, InvalidSessionError> {
        Ok(self.remote_identity_key()?.map(|k| k.serialize().to_vec()))
    }

    pub fn local_identity_key(&self) -> Result<IdentityKey, InvalidSessionError> {
        let bytes = self.session.local_identity_public.as_deref().unwrap_or(&[]);
        IdentityKey::decode(bytes).map_err(|_| InvalidSessionError("invalid local identity key"))
    }

    pub fn local_identity_key_bytes(&self) -> Result<Vec<u8>, InvalidSessionError> {
        Ok(self.local_identity_key()?.serialize().to_vec())
    }

    pub fn session_with_self(&self) -> Result<bool, InvalidSessionError> {
        if let Some(remote_id) = self.remote_identity_key_bytes()? {
            let local_id = self.local_identity_key_bytes()?;
            return Ok(remote_id == local_id);
        }

        // If remote ID is not set then we can't be sure but treat as non-self
        Ok(false)
    }

    pub fn previous_counter(&self) -> u32 {
        self.session.previous_counter.unwrap_or(0)
    }

    pub fn set_previous_counter(&mut self, ctr: u32) {
        self.session.previous_counter = Some(ctr);
    }

    pub fn root_key(&self) -> Result<RootKey, InvalidSessionError> {
        let root_key_bytes = self.session.root_key.as_deref().unwrap_or(&[]);
        let root_key_bytes = root_key_bytes
            .try_into()
            .map_err(|_| InvalidSessionError("invalid root key"))?;
        Ok(RootKey::new(root_key_bytes))
    }

    pub fn set_root_key(&mut self, root_key: &RootKey) {
        self.session.root_key = Some(root_key.key().to_vec());
    }

    pub fn sender_ratchet_key(&self) -> Result<PublicKey, InvalidSessionError> {
        match self.session.sender_chain {
            None => Err(InvalidSessionError("missing sender chain")),
            Some(ref c) => {
                let key_bytes = c
                    .sender_ratchet_key
                    .as_ref()
                    .ok_or(InvalidSessionError("missing sender ratchet key"))?;
                PublicKey::deserialize(key_bytes)
                    .map_err(|_| InvalidSessionError("invalid sender chain ratchet key"))
            }
        }
    }

    pub fn sender_ratchet_key_for_logging(&self) -> Result<String, InvalidSessionError> {
        Ok(hex::encode(self.sender_ratchet_key()?.public_key_bytes()))
    }

    pub fn sender_ratchet_private_key(&self) -> Result<PrivateKey, InvalidSessionError> {
        match self.session.sender_chain {
            None => Err(InvalidSessionError("missing sender chain")),
            Some(ref c) => {
                let key_bytes = c
                    .sender_ratchet_key_private
                    .as_ref()
                    .ok_or(InvalidSessionError("missing sender ratchet private key"))?;
                PrivateKey::deserialize(key_bytes)
                    .map_err(|_| InvalidSessionError("invalid sender chain private ratchet key"))
            }
        }
    }

    pub fn has_usable_sender_chain(&self) -> Result<bool, InvalidSessionError> {
        if self.session.sender_chain.is_none() {
            return Ok(false);
        }
        // We removed timestamp from PendingPreKey, so we can't check for expiration here.
        // Assuming it's valid if it exists.
        Ok(true)
    }

    pub fn all_receiver_chain_logging_info(&self) -> Vec<(Vec<u8>, Option<u32>)> {
        let mut results = vec![];
        for chain in self.session.receiver_chains.iter() {
            let sender_ratchet_public = chain.sender_ratchet_key.clone().unwrap_or_default();

            let chain_key_idx = chain
                .chain_key
                .as_ref()
                .and_then(|chain_key| chain_key.index);

            results.push((sender_ratchet_public, chain_key_idx))
        }
        results
    }

    /// Expected serialized public key length: 1 type byte + 32 key bytes
    /// This matches the size of `PublicKey::serialize()` return type.
    const SERIALIZED_PUBLIC_KEY_LEN: usize = 33;

    /// Returns the index of the receiver chain for the given sender, without cloning.
    /// This is more efficient than get_receiver_chain when you only need the index.
    ///
    /// Optimization: Compares serialized bytes directly instead of deserializing
    /// each chain key to PublicKey, avoiding allocation and validation overhead.
    fn get_receiver_chain_index(
        &self,
        sender: &PublicKey,
    ) -> Result<Option<usize>, InvalidSessionError> {
        // Pre-compute the serialized form of the sender key once
        let sender_bytes = sender.serialize();

        for (idx, chain) in self.session.receiver_chains.iter().enumerate() {
            let key_bytes = chain
                .sender_ratchet_key
                .as_ref()
                .ok_or(InvalidSessionError("missing receiver chain ratchet key"))?;

            // Validate the stored key has the expected serialized format
            // before comparing bytes to catch corrupted data early
            if key_bytes.len() != Self::SERIALIZED_PUBLIC_KEY_LEN
                || key_bytes.first() != Some(&KeyType::Djb.value())
            {
                return Err(InvalidSessionError("invalid receiver chain ratchet key"));
            }

            // Compare raw bytes directly instead of deserializing to PublicKey
            // The stored key_bytes are already in serialized format (type byte + key bytes)
            if key_bytes.as_slice() == sender_bytes.as_slice() {
                return Ok(Some(idx));
            }
        }

        Ok(None)
    }

    pub fn get_receiver_chain_key(
        &self,
        sender: &PublicKey,
    ) -> Result<Option<ChainKey>, InvalidSessionError> {
        let Some(idx) = self.get_receiver_chain_index(sender)? else {
            return Ok(None);
        };
        let chain = &self.session.receiver_chains[idx];
        let chain_key = chain
            .chain_key
            .as_ref()
            .ok_or(InvalidSessionError("missing receiver chain key"))?;
        let key_bytes = chain_key
            .key
            .as_ref()
            .ok_or(InvalidSessionError("missing receiver chain key bytes"))?;
        let chain_key_bytes = key_bytes[..]
            .try_into()
            .map_err(|_| InvalidSessionError("invalid receiver chain key"))?;
        let index = chain_key
            .index
            .ok_or(InvalidSessionError("missing receiver chain key index"))?;
        Ok(Some(ChainKey::new(chain_key_bytes, index)))
    }

    pub fn add_receiver_chain(&mut self, sender: &PublicKey, chain_key: &ChainKey) {
        use prost::bytes::Bytes;
        let chain_key = session_structure::chain::ChainKey {
            index: Some(chain_key.index()),
            key: Some(Bytes::copy_from_slice(chain_key.key())),
        };

        let chain = session_structure::Chain {
            sender_ratchet_key: Some(sender.serialize().to_vec()),
            sender_ratchet_key_private: Some(vec![]),
            chain_key: Some(chain_key),
            message_keys: vec![],
        };

        self.session.receiver_chains.push(chain);

        // Remove oldest chains if we exceed capacity (MAX_RECEIVER_CHAINS = 5).
        // Using drain() for consistency, though with only 5 elements the difference is negligible.
        let len = self.session.receiver_chains.len();
        if len > consts::MAX_RECEIVER_CHAINS {
            log::info!(
                "Trimming excessive receiver_chain for session with base key {}, chain count: {}",
                self.sender_ratchet_key_for_logging()
                    .unwrap_or_else(|e| format!("<error: {}>", e.0)),
                len
            );
            let excess = len - consts::MAX_RECEIVER_CHAINS;
            self.session.receiver_chains.drain(..excess);
        }
    }

    pub fn with_receiver_chain(mut self, sender: &PublicKey, chain_key: &ChainKey) -> Self {
        self.add_receiver_chain(sender, chain_key);
        self
    }

    pub fn set_sender_chain(&mut self, sender: &KeyPair, next_chain_key: &ChainKey) {
        use prost::bytes::Bytes;
        let chain_key = session_structure::chain::ChainKey {
            index: Some(next_chain_key.index()),
            key: Some(Bytes::copy_from_slice(next_chain_key.key())),
        };

        let new_chain = session_structure::Chain {
            sender_ratchet_key: Some(sender.public_key.serialize().to_vec()),
            sender_ratchet_key_private: Some(sender.private_key.serialize().to_vec()),
            chain_key: Some(chain_key),
            message_keys: vec![],
        };

        self.session.sender_chain = Some(new_chain);
    }

    pub fn with_sender_chain(mut self, sender: &KeyPair, next_chain_key: &ChainKey) -> Self {
        self.set_sender_chain(sender, next_chain_key);
        self
    }

    pub fn get_sender_chain_key(&self) -> Result<ChainKey, InvalidSessionError> {
        let sender_chain = self
            .session
            .sender_chain
            .as_ref()
            .ok_or(InvalidSessionError("missing sender chain"))?;

        let chain_key = sender_chain
            .chain_key
            .as_ref()
            .ok_or(InvalidSessionError("missing sender chain key"))?;

        let key_bytes = chain_key
            .key
            .as_ref()
            .ok_or(InvalidSessionError("missing sender chain key bytes"))?;
        let chain_key_bytes = key_bytes[..]
            .try_into()
            .map_err(|_| InvalidSessionError("invalid sender chain key"))?;

        let index = chain_key
            .index
            .ok_or(InvalidSessionError("missing sender chain key index"))?;
        Ok(ChainKey::new(chain_key_bytes, index))
    }

    pub fn get_sender_chain_key_bytes(&self) -> Result<Vec<u8>, InvalidSessionError> {
        Ok(self.get_sender_chain_key()?.key().to_vec())
    }

    pub fn set_sender_chain_key(&mut self, next_chain_key: &ChainKey) {
        use prost::bytes::Bytes;
        let chain_key = session_structure::chain::ChainKey {
            index: Some(next_chain_key.index()),
            key: Some(Bytes::copy_from_slice(next_chain_key.key())),
        };

        // Is it actually valid to call this function with sender_chain == None?

        let new_chain = match self.session.sender_chain.take() {
            None => session_structure::Chain {
                sender_ratchet_key: Some(vec![]),
                sender_ratchet_key_private: Some(vec![]),
                chain_key: Some(chain_key),
                message_keys: vec![],
            },
            Some(mut c) => {
                c.chain_key = Some(chain_key);
                c
            }
        };

        self.session.sender_chain = Some(new_chain);
    }

    pub fn get_message_keys(
        &mut self,
        sender: &PublicKey,
        counter: u32,
    ) -> Result<Option<MessageKeyGenerator>, InvalidSessionError> {
        let Some(chain_idx) = self.get_receiver_chain_index(sender)? else {
            return Ok(None);
        };

        // Find the message key index without cloning
        let chain = &self.session.receiver_chains[chain_idx];
        let mut message_key_position = None;
        for (i, m) in chain.message_keys.iter().enumerate() {
            let idx = m
                .index
                .ok_or(InvalidSessionError("missing message key index"))?;
            if idx == counter {
                message_key_position = Some(i);
                break;
            }
        }

        if let Some(position) = message_key_position {
            // Only now do we mutate - remove the message key directly
            let message_key = self.session.receiver_chains[chain_idx]
                .message_keys
                .remove(position);
            let keys = MessageKeyGenerator::from_pb(message_key).map_err(InvalidSessionError)?;
            return Ok(Some(keys));
        }

        Ok(None)
    }

    pub fn set_message_keys(
        &mut self,
        sender: &PublicKey,
        message_keys: MessageKeyGenerator,
    ) -> Result<(), InvalidSessionError> {
        let chain_idx = self
            .get_receiver_chain_index(sender)?
            .expect("called set_message_keys for a non-existent chain");

        let chain = &mut self.session.receiver_chains[chain_idx];

        // AMORTIZED EVICTION: Only prune when exceeding MAX + threshold.
        // This reduces O(n) drain() calls from every insert to once every PRUNE_THRESHOLD inserts.
        // The lookup in get_message_keys() does a linear search by counter value, so order
        // doesn't matter for correctness.
        let len = chain.message_keys.len();
        if len > consts::MAX_MESSAGE_KEYS + consts::MESSAGE_KEY_PRUNE_THRESHOLD {
            let excess = len - consts::MAX_MESSAGE_KEYS;
            chain.message_keys.drain(..excess);
        }
        chain.message_keys.push(message_keys.into_pb());

        Ok(())
    }

    pub fn set_receiver_chain_key(
        &mut self,
        sender: &PublicKey,
        chain_key: &ChainKey,
    ) -> Result<(), InvalidSessionError> {
        let chain_idx = self
            .get_receiver_chain_index(sender)?
            .expect("called set_receiver_chain_key for a non-existent chain");

        use prost::bytes::Bytes;
        self.session.receiver_chains[chain_idx].chain_key =
            Some(session_structure::chain::ChainKey {
                index: Some(chain_key.index()),
                key: Some(Bytes::copy_from_slice(chain_key.key())),
            });

        Ok(())
    }

    pub fn set_unacknowledged_pre_key_message(
        &mut self,
        pre_key_id: Option<PreKeyId>,
        signed_ec_pre_key_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) {
        let signed_ec_pre_key_id: u32 = signed_ec_pre_key_id.into();
        let pending = session_structure::PendingPreKey {
            pre_key_id: pre_key_id.map(PreKeyId::into),
            signed_pre_key_id: Some(signed_ec_pre_key_id as i32),
            base_key: Some(base_key.serialize().to_vec()),
        };
        self.session.pending_pre_key = Some(pending);
    }

    pub fn unacknowledged_pre_key_message_items(
        &self,
    ) -> Result<Option<UnacknowledgedPreKeyMessageItems>, InvalidSessionError> {
        if let Some(ref pending_pre_key) = self.session.pending_pre_key {
            Ok(Some(UnacknowledgedPreKeyMessageItems::new(
                pending_pre_key.pre_key_id.map(Into::into),
                (pending_pre_key.signed_pre_key_id.unwrap_or(0) as u32).into(),
                PublicKey::deserialize(
                    pending_pre_key
                        .base_key
                        .as_ref()
                        .ok_or(InvalidSessionError("missing base key"))?,
                )
                .map_err(|_| InvalidSessionError("invalid pending PreKey message base key"))?,
            )))
        } else {
            Ok(None)
        }
    }

    pub fn clear_unacknowledged_pre_key_message(&mut self) {
        // Explicitly destructuring the SessionStructure in case there are new
        // pending fields that need to be cleared.
        let SessionStructure {
            session_version: _session_version,
            local_identity_public: _local_identity_public,
            remote_identity_public: _remote_identity_public,
            root_key: _root_key,
            previous_counter: _previous_counter,
            sender_chain: _sender_chain,
            receiver_chains: _receiver_chains,
            pending_pre_key: _pending_pre_key,
            remote_registration_id: _remote_registration_id,
            local_registration_id: _local_registration_id,
            alice_base_key: _alice_base_key,
            needs_refresh: _needs_refresh,
            pending_key_exchange: _pending_key_exchange,
        } = &self.session;

        self.session.pending_pre_key = None;
    }

    pub fn set_remote_registration_id(&mut self, registration_id: u32) {
        self.session.remote_registration_id = Some(registration_id);
    }

    pub fn remote_registration_id(&self) -> u32 {
        self.session.remote_registration_id.unwrap_or(0)
    }

    pub fn set_local_registration_id(&mut self, registration_id: u32) {
        self.session.local_registration_id = Some(registration_id);
    }

    pub fn local_registration_id(&self) -> u32 {
        self.session.local_registration_id.unwrap_or(0)
    }
}

impl From<SessionStructure> for SessionState {
    fn from(value: SessionStructure) -> SessionState {
        SessionState::from_session_structure(value)
    }
}

impl From<SessionState> for SessionStructure {
    fn from(value: SessionState) -> SessionStructure {
        value.session
    }
}

impl From<&SessionState> for SessionStructure {
    fn from(value: &SessionState) -> SessionStructure {
        value.session.clone()
    }
}

#[derive(Clone)]
pub struct SessionRecord {
    current_session: Option<SessionState>,
    previous_sessions: Vec<SessionStructure>,
}

impl SessionRecord {
    pub fn new_fresh() -> Self {
        Self {
            current_session: None,
            previous_sessions: Vec::new(),
        }
    }

    pub fn new(state: SessionState) -> Self {
        Self {
            current_session: Some(state),
            previous_sessions: Vec::new(),
        }
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, SignalProtocolError> {
        let mut record = RecordStructure::decode(bytes)
            .map_err(|_| InvalidSessionError("failed to decode session record protobuf"))?;

        // OPTIMIZATION: Aggressively prune previous_sessions on load.
        // This avoids deserializing and keeping in memory more sessions than needed.
        // The constant ARCHIVED_STATES_MAX_LENGTH (40) defines the maximum we ever use,
        // so any sessions beyond that are wasted memory and CPU cycles.
        if record.previous_sessions.len() > consts::ARCHIVED_STATES_MAX_LENGTH {
            // Keep only the most recent sessions (at the front of the vec)
            record
                .previous_sessions
                .truncate(consts::ARCHIVED_STATES_MAX_LENGTH);
        }

        Ok(Self {
            current_session: record.current_session.map(|s| s.into()),
            previous_sessions: record.previous_sessions,
        })
    }

    /// If there's a session with a matching version and `alice_base_key`, ensures that it is the
    /// current session, promoting if necessary.
    ///
    /// Returns `Ok(true)` if such a session was found, `Ok(false)` if not, and
    /// `Err(InvalidSessionError)` if an invalid session was found during the search (whether
    /// current or not).
    pub fn promote_matching_session(
        &mut self,
        version: u32,
        alice_base_key: &[u8],
    ) -> Result<bool, InvalidSessionError> {
        if let Some(current_session) = &self.current_session
            && current_session.session_version()? == version
            && alice_base_key
                .ct_eq(current_session.alice_base_key())
                .into()
        {
            return Ok(true);
        }

        // OPTIMIZATION: Find matching session by index without cloning all sessions.
        // Only take ownership of the matching session when found.
        if let Some(index) = self.find_matching_previous_session_index(version, alice_base_key)? {
            // Take only the session we need to promote
            let state = self
                .take_previous_session(index)
                .expect("index was just validated");
            self.promote_state(state);
            return Ok(true);
        }

        Ok(false)
    }

    pub fn session_state(&self) -> Option<&SessionState> {
        self.current_session.as_ref()
    }

    pub fn session_state_mut(&mut self) -> Option<&mut SessionState> {
        self.current_session.as_mut()
    }

    pub fn set_session_state(&mut self, session: SessionState) {
        self.current_session = Some(session);
    }

    /// Take ownership of the current session state, leaving None.
    /// Use `set_session_state()` to restore it if decryption fails.
    pub fn take_session_state(&mut self) -> Option<SessionState> {
        self.current_session.take()
    }

    /// Get the number of previous sessions.
    pub fn previous_session_count(&self) -> usize {
        self.previous_sessions.len()
    }

    /// Take a previous session by index, removing it from the list.
    /// The session is converted from SessionStructure to SessionState.
    pub fn take_previous_session(&mut self, index: usize) -> Option<SessionState> {
        if index < self.previous_sessions.len() {
            Some(self.previous_sessions.remove(index).into())
        } else {
            None
        }
    }

    /// Restore a previous session at a specific index.
    /// Used to put a session back after a failed decryption attempt.
    ///
    /// # Note
    /// This method is designed for the take-restore pattern where a session is
    /// taken with `take_previous_session` and restored at the same index if
    /// decryption fails. It does not enforce `ARCHIVED_STATES_MAX_LENGTH` since
    /// the caller is expected to restore only what was taken.
    pub fn restore_previous_session(&mut self, index: usize, state: SessionState) {
        let structure: SessionStructure = state.into();
        if index <= self.previous_sessions.len() {
            self.previous_sessions.insert(index, structure);
        } else {
            // If index is out of bounds, just push to end
            self.previous_sessions.push(structure);
        }
    }

    pub fn previous_session_states(
        &self,
    ) -> impl ExactSizeIterator<Item = Result<SessionState, InvalidSessionError>> + '_ {
        self.previous_sessions
            .iter()
            .map(|structure| Ok(structure.clone().into()))
    }

    /// Find the index of a previous session matching the given version and alice_base_key.
    /// This method avoids cloning by checking fields directly on the protobuf structure.
    ///
    /// Returns `Ok(Some(index))` if found, `Ok(None)` if not found, or
    /// `Err(InvalidSessionError)` if an invalid session is encountered.
    fn find_matching_previous_session_index(
        &self,
        version: u32,
        alice_base_key: &[u8],
    ) -> Result<Option<usize>, InvalidSessionError> {
        for (i, session) in self.previous_sessions.iter().enumerate() {
            // Check version directly from protobuf
            let session_version = match session.session_version.unwrap_or(0) {
                0 => 2, // Default version
                v => v,
            };

            if session_version != version {
                continue;
            }

            // Check alice_base_key directly from protobuf
            let session_base_key = session.alice_base_key.as_deref().unwrap_or(&[]);
            if alice_base_key.ct_eq(session_base_key).into() {
                return Ok(Some(i));
            }
        }
        Ok(None)
    }

    pub fn promote_old_session(&mut self, old_session: usize, updated_session: SessionState) {
        self.previous_sessions.remove(old_session);
        self.promote_state(updated_session)
    }

    pub fn promote_state(&mut self, new_state: SessionState) {
        self.archive_current_state_inner();
        self.current_session = Some(new_state);
    }

    // A non-fallible version of archive_current_state.
    //
    // Returns `true` if there was a session to archive, `false` if not.
    fn archive_current_state_inner(&mut self) -> bool {
        if let Some(mut current_session) = self.current_session.take() {
            if self.previous_sessions.len() >= consts::ARCHIVED_STATES_MAX_LENGTH {
                self.previous_sessions.pop();
            }
            current_session.clear_unacknowledged_pre_key_message();
            self.previous_sessions.insert(0, current_session.session);
            true
        } else {
            false
        }
    }

    pub fn archive_current_state(&mut self) -> Result<(), SignalProtocolError> {
        if !self.archive_current_state_inner() {
            log::info!("Skipping archive, current session state is fresh");
        }
        Ok(())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, SignalProtocolError> {
        let record = RecordStructure {
            current_session: self.current_session.as_ref().map(|s| s.into()),
            previous_sessions: self.previous_sessions.clone(),
        };
        Ok(record.encode_to_vec())
    }

    pub fn remote_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "remote_registration_id",
                    "No current session".into(),
                )
            })?
            .remote_registration_id())
    }

    pub fn local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "local_registration_id",
                    "No current session".into(),
                )
            })?
            .local_registration_id())
    }

    pub fn session_version(&self) -> Result<u32, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState("session_version", "No current session".into())
            })?
            .session_version()?)
    }

    pub fn local_identity_key_bytes(&self) -> Result<Vec<u8>, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "local_identity_key_bytes",
                    "No current session".into(),
                )
            })?
            .local_identity_key_bytes()?)
    }

    pub fn remote_identity_key_bytes(&self) -> Result<Option<Vec<u8>>, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "remote_identity_key_bytes",
                    "No current session".into(),
                )
            })?
            .remote_identity_key_bytes()?)
    }

    pub fn has_usable_sender_chain(&self) -> Result<bool, SignalProtocolError> {
        match &self.current_session {
            Some(session) => Ok(session.has_usable_sender_chain()?),
            None => Ok(false),
        }
    }

    pub fn alice_base_key(&self) -> Result<&[u8], SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState("alice_base_key", "No current session".into())
            })?
            .alice_base_key())
    }

    pub fn get_receiver_chain_key_bytes(
        &self,
        sender: &PublicKey,
    ) -> Result<Option<Box<[u8]>>, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "get_receiver_chain_key",
                    "No current session".into(),
                )
            })?
            .get_receiver_chain_key(sender)?
            .map(|chain| chain.key()[..].into()))
    }

    pub fn get_sender_chain_key_bytes(&self) -> Result<Vec<u8>, SignalProtocolError> {
        Ok(self
            .session_state()
            .ok_or_else(|| {
                SignalProtocolError::InvalidState(
                    "get_sender_chain_key_bytes",
                    "No current session".into(),
                )
            })?
            .get_sender_chain_key_bytes()?)
    }

    pub fn current_ratchet_key_matches(
        &self,
        key: &PublicKey,
    ) -> Result<bool, SignalProtocolError> {
        match &self.current_session {
            Some(session) => Ok(&session.sender_ratchet_key()? == key),
            None => Ok(false),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::protocol::ratchet::keys::MessageKeyGenerator;
    use crate::protocol::{IdentityKey, KeyPair};

    fn rng() -> impl rand::CryptoRng + rand::Rng {
        rand::rng()
    }

    /// Creates a minimal valid SessionState for testing.
    fn create_test_session_state(version: u8, base_key: &PublicKey) -> SessionState {
        let mut csprng = rng();
        let identity_keypair = KeyPair::generate(&mut csprng);
        let their_identity = IdentityKey::new(identity_keypair.public_key);
        let our_identity = IdentityKey::new(KeyPair::generate(&mut csprng).public_key);
        let root_key = crate::protocol::ratchet::RootKey::new([0u8; 32]);

        let mut state =
            SessionState::new(version, &our_identity, &their_identity, &root_key, base_key);

        // Add a sender chain to make it usable
        let sender_keypair = KeyPair::generate(&mut csprng);
        let chain_key = crate::protocol::ratchet::ChainKey::new([1u8; 32], 0);
        state.set_sender_chain(&sender_keypair, &chain_key);

        state
    }

    /// Creates a SessionRecord with N previous sessions for testing.
    fn create_record_with_previous_sessions(count: usize) -> SessionRecord {
        let mut csprng = rng();
        let mut record = SessionRecord::new_fresh();

        for _ in 0..count {
            let base_key = KeyPair::generate(&mut csprng).public_key;
            let state = create_test_session_state(3, &base_key);
            record.promote_state(state);
        }

        record
    }

    #[test]
    fn test_take_restore_preserves_order() {
        let mut record = create_record_with_previous_sessions(5);

        // Collect base keys before take
        let original_base_keys: Vec<Vec<u8>> = record
            .previous_session_states()
            .map(|s| s.unwrap().alice_base_key().to_vec())
            .collect();

        // Take and restore each session in order
        for _ in 0..5 {
            let session = record.take_previous_session(0).unwrap();
            record.restore_previous_session(0, session);
        }

        // Verify order is preserved
        let after_base_keys: Vec<Vec<u8>> = record
            .previous_session_states()
            .map(|s| s.unwrap().alice_base_key().to_vec())
            .collect();

        assert_eq!(original_base_keys, after_base_keys);
    }

    #[test]
    fn test_take_restore_at_various_indices() {
        let mut record = create_record_with_previous_sessions(5);
        let original_count = record.previous_session_count();

        // Take from middle
        let session_at_2 = record.take_previous_session(2).unwrap();
        assert_eq!(record.previous_session_count(), original_count - 1);

        // Restore at same index
        record.restore_previous_session(2, session_at_2);
        assert_eq!(record.previous_session_count(), original_count);
    }

    #[test]
    fn test_take_restore_maintains_count() {
        // create_record_with_previous_sessions(N) creates:
        // - 1 current session (the Nth one)
        // - N-1 previous sessions (the first N-1 ones)
        let mut record = create_record_with_previous_sessions(10);
        let original_count = record.previous_session_count();
        assert_eq!(original_count, 9); // 10 promotes = 1 current + 9 previous

        // Simulate the decryption loop pattern
        let mut idx = 0;
        while idx < original_count {
            let session = record.take_previous_session(idx).unwrap();
            // Simulate failed decryption
            record.restore_previous_session(idx, session);
            idx += 1;
        }

        // Count should be unchanged after take/restore loop
        assert_eq!(record.previous_session_count(), original_count);
    }

    #[test]
    fn test_take_then_promote() {
        // create_record_with_previous_sessions(5) creates:
        // - 1 current session
        // - 4 previous sessions
        let mut record = create_record_with_previous_sessions(5);
        assert_eq!(record.previous_session_count(), 4);

        // Take a previous session (removes from list)
        let session = record.take_previous_session(2).unwrap();
        assert_eq!(record.previous_session_count(), 3);

        // Promote it (archives current, sets taken session as new current)
        record.promote_state(session);

        // Verify it's now current
        assert!(record.session_state().is_some());
        // previous = original 4 - 1 taken + 1 archived current = 4
        assert_eq!(record.previous_session_count(), 4);
    }

    #[test]
    fn test_take_out_of_bounds() {
        let mut record = create_record_with_previous_sessions(4);
        // 4 promotes = 1 current + 3 previous
        assert_eq!(record.previous_session_count(), 3);
        assert!(record.take_previous_session(10).is_none());
        assert!(record.take_previous_session(3).is_none());
    }

    #[test]
    fn test_message_keys_lookup_by_counter_not_order() {
        let base_key = KeyPair::generate(&mut rng()).public_key;
        let mut state = create_test_session_state(3, &base_key);

        // Add a receiver chain
        let sender_key = KeyPair::generate(&mut rng()).public_key;
        let chain_key = crate::protocol::ratchet::ChainKey::new([2u8; 32], 0);
        state.add_receiver_chain(&sender_key, &chain_key);

        // Add message keys with counters 0, 1, 2
        for counter in 0..3u32 {
            let keys = create_test_message_key_generator(counter);
            state.set_message_keys(&sender_key, keys).unwrap();
        }

        // Verify we can retrieve by counter value, not insertion order
        let key_2 = state.get_message_keys(&sender_key, 2).unwrap();
        assert!(key_2.is_some());

        let key_0 = state.get_message_keys(&sender_key, 0).unwrap();
        assert!(key_0.is_some());

        // Key 1 should also be retrievable
        let key_1 = state.get_message_keys(&sender_key, 1).unwrap();
        assert!(key_1.is_some());
    }

    #[test]
    fn test_message_keys_eviction_at_max() {
        let base_key = KeyPair::generate(&mut rng()).public_key;
        let mut state = create_test_session_state(3, &base_key);

        let sender_key = KeyPair::generate(&mut rng()).public_key;
        let chain_key = crate::protocol::ratchet::ChainKey::new([2u8; 32], 0);
        state.add_receiver_chain(&sender_key, &chain_key);

        // Amortized eviction uses MESSAGE_KEY_PRUNE_THRESHOLD.
        // Eviction triggers when len > MAX_MESSAGE_KEYS + MESSAGE_KEY_PRUNE_THRESHOLD.
        // Add MAX_MESSAGE_KEYS + 100 keys to ensure eviction happens.
        let total_keys = consts::MAX_MESSAGE_KEYS + 100;
        for counter in 0..total_keys as u32 {
            let keys = create_test_message_key_generator(counter);
            state.set_message_keys(&sender_key, keys).unwrap();
        }

        // After adding 2100 keys:
        // - At 2051: prune to 2000 (removes first 51 keys: 0-50)
        // - Continue adding keys 2051-2099 (49 more)
        // - Final len = 2049, no second prune since 2049 <= 2050
        // So keys 0-50 (51 keys) should be evicted.
        let evicted_count = consts::MESSAGE_KEY_PRUNE_THRESHOLD + 1; // 51
        for counter in 0..evicted_count as u32 {
            let key = state.get_message_keys(&sender_key, counter).unwrap();
            assert!(key.is_none(), "Key {} should have been evicted", counter);
        }

        // Newer keys should still exist
        for counter in evicted_count as u32..total_keys as u32 {
            let key = state.get_message_keys(&sender_key, counter).unwrap();
            assert!(key.is_some(), "Key {} should exist", counter);
        }
    }

    fn create_test_message_key_generator(counter: u32) -> MessageKeyGenerator {
        // Create a MessageKeyGenerator with the given counter using a seed
        let mut seed = [0u8; 32];
        seed[0] = counter as u8;
        seed[1] = (counter >> 8) as u8;
        MessageKeyGenerator::new_from_seed(&seed, counter)
    }

    #[test]
    fn test_receiver_chain_lookup_by_bytes() {
        let base_key = KeyPair::generate(&mut rng()).public_key;
        let mut state = create_test_session_state(3, &base_key);

        // Add a receiver chain
        let sender_keypair = KeyPair::generate(&mut rng());
        let chain_key = crate::protocol::ratchet::ChainKey::new([2u8; 32], 0);
        state.add_receiver_chain(&sender_keypair.public_key, &chain_key);

        // Retrieve chain key using same public key
        let chain = state
            .get_receiver_chain_key(&sender_keypair.public_key)
            .unwrap();
        assert!(chain.is_some());

        // Different key should not find the chain
        let other_key = KeyPair::generate(&mut rng()).public_key;
        let chain = state.get_receiver_chain_key(&other_key).unwrap();
        assert!(chain.is_none());
    }

    #[test]
    fn test_receiver_chain_lookup_with_serialized_key() {
        let base_key = KeyPair::generate(&mut rng()).public_key;
        let mut state = create_test_session_state(3, &base_key);

        let sender_keypair = KeyPair::generate(&mut rng());
        let chain_key = crate::protocol::ratchet::ChainKey::new([2u8; 32], 0);
        state.add_receiver_chain(&sender_keypair.public_key, &chain_key);

        // Deserialize the same key from bytes and look up
        let serialized = sender_keypair.public_key.serialize();
        let deserialized = PublicKey::deserialize(&serialized).unwrap();

        let chain = state.get_receiver_chain_key(&deserialized).unwrap();
        assert!(chain.is_some());
    }

    #[test]
    fn test_promote_matching_session_finds_correct_session() {
        let mut record = SessionRecord::new_fresh();

        // Create sessions with distinct version + base_key combinations
        let keys: Vec<PublicKey> = (0..5)
            .map(|_| KeyPair::generate(&mut rng()).public_key)
            .collect();

        for key in keys.iter() {
            let state = create_test_session_state(3, key);
            record.promote_state(state);
        }

        // The current session should have keys[4]'s base_key
        // Try to promote a session matching keys[2]
        let target_base_key = keys[2].serialize();
        let result = record
            .promote_matching_session(3, &target_base_key)
            .unwrap();

        assert!(result, "Should find matching session");

        // Verify the promoted session has the correct base_key
        let current = record.session_state().unwrap();
        assert_eq!(current.alice_base_key(), target_base_key.as_slice());
    }

    #[test]
    fn test_promote_matching_session_version_mismatch() {
        let mut record = SessionRecord::new_fresh();

        let key = KeyPair::generate(&mut rng()).public_key;
        let state = create_test_session_state(3, &key);
        record.promote_state(state);

        // Archive the current session
        record.archive_current_state().unwrap();

        // Try to find with wrong version
        let base_key = key.serialize();
        let result = record.promote_matching_session(2, &base_key).unwrap();

        assert!(!result, "Should not find session with wrong version");
    }

    #[test]
    fn test_promote_matching_session_already_current() {
        let key = KeyPair::generate(&mut rng()).public_key;
        let state = create_test_session_state(3, &key);
        let mut record = SessionRecord::new(state);

        // The matching session is already current
        let base_key = key.serialize();
        let result = record.promote_matching_session(3, &base_key).unwrap();

        assert!(result, "Should return true for already-current session");
        assert_eq!(record.previous_session_count(), 0);
    }

    #[test]
    fn test_session_record_serialization_preserves_previous_sessions() {
        let record = create_record_with_previous_sessions(10);

        // Collect state before serialization
        let original_count = record.previous_session_count();
        let original_base_keys: Vec<Vec<u8>> = record
            .previous_session_states()
            .map(|s| s.unwrap().alice_base_key().to_vec())
            .collect();

        // Serialize and deserialize
        let bytes = record.serialize().unwrap();
        let restored = SessionRecord::deserialize(&bytes).unwrap();

        // Verify
        assert_eq!(restored.previous_session_count(), original_count);
        let restored_base_keys: Vec<Vec<u8>> = restored
            .previous_session_states()
            .map(|s| s.unwrap().alice_base_key().to_vec())
            .collect();
        assert_eq!(original_base_keys, restored_base_keys);
    }

    #[test]
    fn test_session_record_truncates_on_deserialize() {
        // This tests the ARCHIVED_STATES_MAX_LENGTH enforcement on load
        let mut record = SessionRecord::new_fresh();

        // Manually add more sessions than the limit
        for _ in 0..(consts::ARCHIVED_STATES_MAX_LENGTH + 10) {
            let key = KeyPair::generate(&mut rng()).public_key;
            let state = create_test_session_state(3, &key);
            record.previous_sessions.push(state.session);
        }

        // Serialize
        let bytes = record.serialize().unwrap();

        // Deserialize should truncate
        let restored = SessionRecord::deserialize(&bytes).unwrap();
        assert_eq!(
            restored.previous_session_count(),
            consts::ARCHIVED_STATES_MAX_LENGTH
        );
    }
}
