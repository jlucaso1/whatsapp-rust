pub mod signal;
/// The public key for verifying the server's intermediate certificate.
pub const WA_CERT_PUB_KEY: [u8; 32] = [
    0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71, 0x66, 0xaa, 0xe7, 0x1e, 0xbe, 0x51, 0x64, 0x37,
    0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69, 0x5c, 0x6c, 0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b,
];
use whatsapp_core::crypto::key_pair::{KeyPair, PreKey};
use whatsapp_core::types::jid::Jid;
use whatsapp_proto::whatsapp as wa;
pub mod clientpayload;
pub mod commands; // Device commands for the persistence manager
pub mod error;
pub mod filestore;
pub mod generic;
pub mod memory;
pub mod persistence_manager; // Background persistence manager
pub mod traits;

// Re-export traits from both whatsapp-core and local extensions
pub use crate::store::traits::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::ops::{Deref, DerefMut};

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
}

/// Platform-specific Device wrapper that contains core device data plus backend
#[derive(Clone)]
pub struct Device {
    /// Core device data
    pub core: whatsapp_core::store::Device,
    /// Platform-specific backend for storage operations
    pub backend: Arc<dyn Backend>,
}

impl Deref for Device {
    type Target = whatsapp_core::store::Device;

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
        let core = whatsapp_core::store::Device::new();
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
    }
    
    pub fn get_client_payload(&self) -> wa::ClientPayload {
        match &self.core.id {
            Some(jid) => clientpayload::get_login_payload(jid),
            None => clientpayload::get_registration_payload(
                self.core.registration_id,
                &self.core.identity_key.public_key,
                &self.core.signed_pre_key,
            ),
        }
    }
}
