//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::result::Result;

use prost::Message;
use subtle::ConstantTimeEq;

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
                local_identity_public: Some(our_identity.public_key().serialize().into_vec()),
                remote_identity_public: Some(their_identity.serialize().into_vec()),
                root_key: Some(root_key.key().to_vec()),
                previous_counter: Some(0),
                sender_chain: None,
                receiver_chains: vec![],
                pending_pre_key: None,
                remote_registration_id: Some(0),
                local_registration_id: Some(0),
                alice_base_key: Some(alice_base_key.serialize().into_vec()),
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

    pub fn get_receiver_chain(
        &self,
        sender: &PublicKey,
    ) -> Result<Option<(session_structure::Chain, usize)>, InvalidSessionError> {
        for (idx, chain) in self.session.receiver_chains.iter().enumerate() {
            // If we compared bytes directly it would be faster, but may miss non-canonical points.
            // It's unclear if supporting such points is desirable.
            let key_bytes = chain
                .sender_ratchet_key
                .as_ref()
                .ok_or(InvalidSessionError("missing receiver chain ratchet key"))?;
            let chain_ratchet_key = PublicKey::deserialize(key_bytes)
                .map_err(|_| InvalidSessionError("invalid receiver chain ratchet key"))?;

            if &chain_ratchet_key == sender {
                return Ok(Some((chain.clone(), idx)));
            }
        }

        Ok(None)
    }

    pub fn get_receiver_chain_key(
        &self,
        sender: &PublicKey,
    ) -> Result<Option<ChainKey>, InvalidSessionError> {
        match self.get_receiver_chain(sender)? {
            None => Ok(None),
            Some((chain, _)) => match chain.chain_key {
                None => Err(InvalidSessionError("missing receiver chain key")),
                Some(c) => {
                    let key_bytes = c
                        .key
                        .as_ref()
                        .ok_or(InvalidSessionError("missing receiver chain key bytes"))?;
                    let chain_key_bytes = key_bytes[..]
                        .try_into()
                        .map_err(|_| InvalidSessionError("invalid receiver chain key"))?;
                    let index = c
                        .index
                        .ok_or(InvalidSessionError("missing receiver chain key index"))?;
                    Ok(Some(ChainKey::new(chain_key_bytes, index)))
                }
            },
        }
    }

    pub fn add_receiver_chain(&mut self, sender: &PublicKey, chain_key: &ChainKey) {
        let chain_key = session_structure::chain::ChainKey {
            index: Some(chain_key.index()),
            key: Some(chain_key.key().to_vec()),
        };

        let chain = session_structure::Chain {
            sender_ratchet_key: Some(sender.serialize().to_vec()),
            sender_ratchet_key_private: Some(vec![]),
            chain_key: Some(chain_key),
            message_keys: vec![],
        };

        self.session.receiver_chains.push(chain);

        if self.session.receiver_chains.len() > consts::MAX_RECEIVER_CHAINS {
            log::info!(
                "Trimming excessive receiver_chain for session with base key {}, chain count: {}",
                self.sender_ratchet_key_for_logging()
                    .unwrap_or_else(|e| format!("<error: {}>", e.0)),
                self.session.receiver_chains.len()
            );
            self.session.receiver_chains.remove(0);
        }
    }

    pub fn with_receiver_chain(mut self, sender: &PublicKey, chain_key: &ChainKey) -> Self {
        self.add_receiver_chain(sender, chain_key);
        self
    }

    pub fn set_sender_chain(&mut self, sender: &KeyPair, next_chain_key: &ChainKey) {
        let chain_key = session_structure::chain::ChainKey {
            index: Some(next_chain_key.index()),
            key: Some(next_chain_key.key().to_vec()),
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
        let chain_key = session_structure::chain::ChainKey {
            index: Some(next_chain_key.index()),
            key: Some(next_chain_key.key().to_vec()),
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
        if let Some(mut chain_and_index) = self.get_receiver_chain(sender)? {
            let mut message_key_idx = None;
            for (i, m) in chain_and_index.0.message_keys.iter().enumerate() {
                let idx = m
                    .index
                    .ok_or(InvalidSessionError("missing message key index"))?;
                if idx == counter {
                    message_key_idx = Some(i);
                    break;
                }
            }

            if let Some(position) = message_key_idx {
                let message_key = chain_and_index.0.message_keys.remove(position);
                let keys =
                    MessageKeyGenerator::from_pb(message_key).map_err(InvalidSessionError)?;

                // Update with message key removed
                self.session.receiver_chains[chain_and_index.1] = chain_and_index.0;
                return Ok(Some(keys));
            }
        }

        Ok(None)
    }

    pub fn set_message_keys(
        &mut self,
        sender: &PublicKey,
        message_keys: MessageKeyGenerator,
    ) -> Result<(), InvalidSessionError> {
        let chain_and_index = self
            .get_receiver_chain(sender)?
            .expect("called set_message_keys for a non-existent chain");
        let mut updated_chain = chain_and_index.0;
        updated_chain.message_keys.insert(0, message_keys.into_pb());

        if updated_chain.message_keys.len() > consts::MAX_MESSAGE_KEYS {
            updated_chain.message_keys.pop();
        }

        self.session.receiver_chains[chain_and_index.1] = updated_chain;

        Ok(())
    }

    pub fn set_receiver_chain_key(
        &mut self,
        sender: &PublicKey,
        chain_key: &ChainKey,
    ) -> Result<(), InvalidSessionError> {
        let chain_and_index = self
            .get_receiver_chain(sender)?
            .expect("called set_receiver_chain_key for a non-existent chain");
        let mut updated_chain = chain_and_index.0;
        updated_chain.chain_key = Some(session_structure::chain::ChainKey {
            index: Some(chain_key.index()),
            key: Some(chain_key.key().to_vec()),
        });

        self.session.receiver_chains[chain_and_index.1] = updated_chain;

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

        let mut session_to_promote = None;
        for (i, previous) in self.previous_session_states().enumerate() {
            let previous = previous?;
            if previous.session_version()? == version
                && alice_base_key.ct_eq(previous.alice_base_key()).into()
            {
                session_to_promote = Some((i, previous));
                break;
            }
        }

        if let Some((i, state)) = session_to_promote {
            self.promote_old_session(i, state);
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

    pub fn previous_session_states(
        &self,
    ) -> impl ExactSizeIterator<Item = Result<SessionState, InvalidSessionError>> + '_ {
        self.previous_sessions
            .iter()
            .map(|structure| Ok(structure.clone().into()))
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
