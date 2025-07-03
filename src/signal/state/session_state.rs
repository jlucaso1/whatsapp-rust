use crate::signal::chain_key::ChainKey;
use crate::signal::ecc::key_pair::EcKeyPair;
use crate::signal::ecc::keys::DjbEcPublicKey;
use crate::signal::ecc::keys::EcPublicKey;
use crate::signal::identity::IdentityKey;
use crate::signal::message_key::MessageKeys;
use crate::signal::root_key::RootKey;
use std::collections::HashMap;
use std::sync::Arc;

const MAX_MESSAGE_KEYS: usize = 2000;

// Corresponds to state/record/ChainState.go
#[derive(Clone)]
pub struct Chain {
    sender_ratchet_key_pair: EcKeyPair,
    chain_key: ChainKey,
    message_keys: HashMap<u32, MessageKeys>,
}

impl Chain {
    pub fn new(sender_ratchet_key_pair: EcKeyPair, chain_key: ChainKey) -> Self {
        Self {
            sender_ratchet_key_pair,
            chain_key,
            message_keys: HashMap::new(),
        }
    }
}

// Corresponds to state/record/PendingPreKeyState.go
#[derive(Clone)]
pub struct PendingPreKey {
    pub pre_key_id: Option<u32>,
    pub signed_pre_key_id: u32,
    pub base_key: Arc<dyn EcPublicKey>,
}

// Corresponds to state/record/PendingKeyExchangeState.go
pub struct PendingKeyExchange {
    // We can fill this in when we implement the full X3DH handshake
}

// Corresponds to state/record/SessionState.go
pub struct SessionState {
    session_version: u32,
    local_identity_public: IdentityKey,
    remote_identity_public: IdentityKey,
    root_key: RootKey,
    previous_counter: u32,
    sender_chain: Option<Chain>,
    receiver_chains: HashMap<[u8; 32], Chain>, // Keyed by their public key

    pending_pre_key: Option<PendingPreKey>,
    // Other pending states can be added here
}

impl SessionState {
    pub fn new() -> Self {
        // A proper constructor will be needed later
        Self {
            session_version: 3, // Current version
            // Dummy values for now
            local_identity_public: IdentityKey::new(Arc::new(DjbEcPublicKey::new([0; 32]))),
            remote_identity_public: IdentityKey::new(Arc::new(DjbEcPublicKey::new([0; 32]))),
            root_key: RootKey::new([0; 32]),
            previous_counter: 0,
            sender_chain: None,
            receiver_chains: HashMap::new(),
            pending_pre_key: None,
        }
    }

    // --- Begin port stubs for SessionCipher integration ---

    pub fn sender_chain_key(&self) -> &ChainKey {
        self.sender_chain
            .as_ref()
            .map(|chain| &chain.chain_key)
            .expect("sender_chain not set")
    }

    pub fn set_sender_chain_key(&mut self, new_chain_key: ChainKey) {
        if let Some(chain) = self.sender_chain.as_mut() {
            chain.chain_key = new_chain_key;
        } else {
            panic!("sender_chain not set");
        }
    }

    pub fn sender_ratchet_key(&self) -> Arc<dyn EcPublicKey> {
        self.sender_chain
            .as_ref()
            .map(|chain| chain.sender_ratchet_key_pair.public_key.clone())
            .expect("sender_chain not set")
    }

    pub fn previous_counter(&self) -> u32 {
        self.previous_counter
    }

    pub fn has_unacknowledged_prekey_message(&self) -> bool {
        false // stub: implement logic as needed
    }

    // --- End port stubs ---
}

// We will add many methods here later, like:
// - set_sender_chain
// - add_receiver_chain
// - sender_chain_key, etc.
