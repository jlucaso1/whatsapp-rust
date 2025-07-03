use crate::signal::chain_key::ChainKey;
use crate::signal::ecc::key_pair::EcKeyPair;
use crate::signal::ecc::keys::{DjbEcPrivateKey, DjbEcPublicKey, EcPublicKey};
use crate::signal::identity::IdentityKey;
use crate::signal::message_key::MessageKeys;
use crate::signal::root_key::RootKey;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

const MAX_MESSAGE_KEYS: usize = 2000;

#[derive(Clone)]
pub struct Chain {
    pub sender_ratchet_key_pair: EcKeyPair,
    pub chain_key: ChainKey,
    pub message_keys: VecDeque<MessageKeys>,
}

impl Chain {
    pub fn new(sender_ratchet_key_pair: EcKeyPair, chain_key: ChainKey) -> Self {
        Self {
            sender_ratchet_key_pair,
            chain_key,
            message_keys: VecDeque::with_capacity(16),
        }
    }

    pub fn add_message_keys(&mut self, keys: MessageKeys) {
        if self.message_keys.len() >= MAX_MESSAGE_KEYS {
            self.message_keys.pop_front();
        }
        self.message_keys.push_back(keys);
    }
}

#[derive(Clone)]
pub struct PendingPreKey {
    pub pre_key_id: Option<u32>,
    pub signed_pre_key_id: u32,
    pub base_key: Arc<dyn EcPublicKey>,
}

pub struct PendingKeyExchange {
    // ...
}

pub struct SessionState {
    session_version: u32,
    local_identity_public: Arc<IdentityKey>,
    remote_identity_public: Arc<IdentityKey>,
    root_key: RootKey,
    previous_counter: u32,
    sender_chain: Option<Chain>,
    receiver_chains: HashMap<Vec<u8>, Chain>,
    pub pending_pre_key: Option<PendingPreKey>,
}

impl SessionState {
    pub fn new() -> Self {
        Self {
            session_version: 3,
            local_identity_public: Arc::new(IdentityKey::new(Arc::new(DjbEcPublicKey::new(
                [0; 32],
            )))),
            remote_identity_public: Arc::new(IdentityKey::new(Arc::new(DjbEcPublicKey::new(
                [0; 32],
            )))),
            root_key: RootKey::new([0; 32]),
            previous_counter: 0,
            sender_chain: None,
            receiver_chains: HashMap::new(),
            pending_pre_key: None,
        }
    }

    pub fn sender_chain(&self) -> &Chain {
        self.sender_chain.as_ref().expect("sender_chain is not set")
    }

    pub fn sender_chain_key(&self) -> ChainKey {
        self.sender_chain().chain_key.clone()
    }

    pub fn set_sender_chain_key(&mut self, next_chain_key: ChainKey) {
        self.sender_chain.as_mut().unwrap().chain_key = next_chain_key;
    }

    pub fn sender_ratchet_key(&self) -> Arc<dyn EcPublicKey> {
        self.sender_chain()
            .sender_ratchet_key_pair
            .public_key
            .clone()
    }

    pub fn previous_counter(&self) -> u32 {
        self.previous_counter
    }

    pub fn local_identity_public(&self) -> Arc<IdentityKey> {
        self.local_identity_public.clone()
    }

    pub fn remote_identity_public(&self) -> Arc<IdentityKey> {
        self.remote_identity_public.clone()
    }

    pub fn set_unacknowledged_prekey_message(
        &mut self,
        pre_key_id: Option<u32>,
        signed_pre_key_id: u32,
        base_key: Arc<dyn EcPublicKey>,
    ) {
        self.pending_pre_key = Some(PendingPreKey {
            pre_key_id,
            signed_pre_key_id,
            base_key,
        });
    }

    pub fn has_unacknowledged_prekey_message(&self) -> bool {
        self.pending_pre_key.is_some()
    }

    pub fn set_session_version(&mut self, version: u32) {
        self.session_version = version;
    }

    pub fn set_remote_identity_key(&mut self, identity_key: Arc<IdentityKey>) {
        self.remote_identity_public = identity_key;
    }

    pub fn set_local_identity_key(&mut self, identity_key: Arc<IdentityKey>) {
        self.local_identity_public = identity_key;
    }

    pub fn set_sender_chain(&mut self, sender_ratchet_key_pair: EcKeyPair, chain_key: ChainKey) {
        self.sender_chain = Some(Chain::new(sender_ratchet_key_pair, chain_key));
    }

    pub fn set_root_key(&mut self, root_key: RootKey) {
        self.root_key = root_key;
    }

    pub fn add_receiver_chain(
        &mut self,
        their_ephemeral: Arc<dyn EcPublicKey>,
        chain_key: ChainKey,
    ) {
        let chain = Chain::new(
            EcKeyPair::new(
                their_ephemeral.clone(),
                Arc::new(DjbEcPrivateKey::new([0; 32])),
            ),
            chain_key,
        );
        self.receiver_chains
            .insert(their_ephemeral.serialize(), chain);
    }
}
