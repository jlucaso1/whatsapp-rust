mod signal;
/// The public key for verifying the server's intermediate certificate.
pub const WA_CERT_PUB_KEY: [u8; 32] = [
    0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71, 0x66, 0xaa, 0xe7, 0x1e, 0xbe, 0x51, 0x64, 0x37,
    0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69, 0x5c, 0x6c, 0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b,
];
use crate::crypto::key_pair::{KeyPair, PreKey};
use crate::proto::whatsapp as wa;
use crate::types::jid::Jid;
use rand::RngCore;
pub mod clientpayload;
pub mod error;
pub mod generic;
pub mod memory;
pub mod traits;

use crate::store::traits::*;
use std::sync::Arc;

#[derive(Clone)]
pub struct Device {
    pub id: Option<Jid>,
    pub registration_id: u32,
    pub noise_key: KeyPair,
    pub identity_key: KeyPair,
    pub signed_pre_key: PreKey,
    pub adv_secret_key: [u8; 32],

    // Abstracted storage via trait objects
    pub identities: Arc<dyn IdentityStore>,
    pub sessions: Arc<dyn SessionStore>,
    pub app_state_store: Arc<dyn AppStateStore>,
    pub app_state_keys: Arc<dyn AppStateKeyStore>,
    pub pre_keys: Arc<dyn crate::signal::store::PreKeyStore>,
    pub signed_pre_keys: Arc<dyn crate::signal::store::SignedPreKeyStore>,
    pub sender_keys: Arc<dyn crate::signal::store::SenderKeyStore>,
}

impl Device {
    /// Creates a new, unregistered device with fresh keys and abstracted stores.
    pub fn new(
        identities: Arc<dyn IdentityStore>,
        sessions: Arc<dyn SessionStore>,
        app_state_store: Arc<dyn AppStateStore>,
        app_state_keys: Arc<dyn AppStateKeyStore>,
        pre_keys: Arc<dyn crate::signal::store::PreKeyStore>,
        signed_pre_keys: Arc<dyn crate::signal::store::SignedPreKeyStore>,
        sender_keys: Arc<dyn crate::signal::store::SenderKeyStore>,
    ) -> Self {
        let identity_key = KeyPair::new();
        let signed_pre_key = identity_key.create_signed_prekey(1).unwrap();
        let mut adv_secret_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut adv_secret_key); // Generate the key

        Self {
            id: None,
            registration_id: 3718719151,
            noise_key: KeyPair::new(),
            identity_key,
            signed_pre_key,
            adv_secret_key,
            identities,
            sessions,
            app_state_store,
            app_state_keys,
            pre_keys,
            signed_pre_keys,
            sender_keys,
        }
    }

    pub fn get_client_payload(&self) -> wa::ClientPayload {
        match &self.id {
            Some(jid) => clientpayload::get_login_payload(jid),
            None => clientpayload::get_registration_payload(
                self.registration_id,
                &self.identity_key.public_key,
                &self.signed_pre_key,
            ),
        }
    }
}
