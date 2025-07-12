use crate::crypto::key_pair::{KeyPair, PreKey};
use crate::types::jid::Jid;
use serde::{Deserialize, Serialize};
use whatsapp_proto::whatsapp as wa;

/// Core device data structure containing only platform-independent information
#[derive(Clone, Serialize, Deserialize)]
pub struct Device {
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

impl Device {
    /// Creates a new, unregistered device with fresh keys
    pub fn new() -> Self {
        use rand::RngCore;
        
        let identity_key = KeyPair::new();
        let signed_pre_key = identity_key.create_signed_prekey(1).unwrap();
        let mut adv_secret_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut adv_secret_key);

        Self {
            id: None,
            lid: None,
            registration_id: 3718719151,
            noise_key: KeyPair::new(),
            identity_key,
            signed_pre_key,
            adv_secret_key,
            account: None,
            push_name: String::new(),
        }
    }
}