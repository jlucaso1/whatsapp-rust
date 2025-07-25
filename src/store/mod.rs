pub mod signal;
use wacore::crypto::key_pair::{KeyPair, PreKey};
use wacore::types::jid::Jid;
use waproto::whatsapp as wa;
pub mod commands; // Device commands for the persistence manager
pub mod error;
pub mod filestore;
pub mod generic;
pub mod memory;
pub mod persistence_manager; // Background persistence manager
pub mod traits;

// Re-export traits from both wacore and local extensions
pub use crate::store::traits::*;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

#[derive(Clone, Serialize, Deserialize)]
pub struct SerializableDevice {
    pub id: Option<Jid>,
    pub lid: Option<Jid>,
    pub registration_id: u32,
    pub noise_key: KeyPair,
    pub identity_key: KeyPair,
    pub signed_pre_key: PreKey,
    pub adv_secret_key: [u8; 32],
    pub account: Option<wa::AdvSignedDeviceIdentity>,
    pub push_name: String,
    #[serde(default)]
    pub processed_messages: VecDeque<wacore::store::device::ProcessedMessageKey>,
}

/// Platform-specific Device wrapper that contains core device data plus backend
#[derive(Clone)]
pub struct Device {
    /// Core device data
    pub core: wacore::store::Device,
    /// Platform-specific backend for storage operations
    pub backend: Arc<dyn Backend>,
}

impl Deref for Device {
    type Target = wacore::store::Device;

    fn deref(&self) -> &Self::Target {
        &self.core
    }
}

impl DerefMut for Device {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.core
    }
}

impl Device {
    /// Creates a new, unregistered device with fresh keys and abstracted stores.
    pub fn new(backend: Arc<dyn Backend>) -> Self {
        let core = wacore::store::Device::new();
        Self { core, backend }
    }

    pub fn to_serializable(&self) -> SerializableDevice {
        SerializableDevice {
            id: self.core.id.clone(),
            lid: self.core.lid.clone(),
            registration_id: self.core.registration_id,
            noise_key: self.core.noise_key.clone(),
            identity_key: self.core.identity_key.clone(),
            signed_pre_key: self.core.signed_pre_key.clone(),
            adv_secret_key: self.core.adv_secret_key,
            account: self.core.account.clone(),
            push_name: self.core.push_name.clone(),
            processed_messages: self.core.processed_messages.clone(),
        }
    }

    pub fn load_from_serializable(&mut self, loaded: SerializableDevice) {
        self.core.id = loaded.id;
        self.core.lid = loaded.lid;
        self.core.registration_id = loaded.registration_id;
        self.core.noise_key = loaded.noise_key;
        self.core.identity_key = loaded.identity_key;
        self.core.signed_pre_key = loaded.signed_pre_key;
        self.core.adv_secret_key = loaded.adv_secret_key;
        self.core.account = loaded.account;
        self.core.push_name = loaded.push_name;
        self.core.processed_messages = loaded.processed_messages;
    }
}
