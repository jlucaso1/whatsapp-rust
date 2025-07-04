use crate::signal::ecc::keys::EcPublicKey;
use crate::signal::identity::IdentityKey;
use std::sync::Arc;

pub struct PreKeyBundle {
    pub registration_id: u32,
    pub device_id: u32,
    pub pre_key_id: Option<u32>,
    pub pre_key_public: Option<Arc<dyn EcPublicKey + Send + Sync>>,
    pub signed_pre_key_id: u32,
    pub signed_pre_key_public: Arc<dyn EcPublicKey + Send + Sync>,
    pub signed_pre_key_signature: [u8; 64],
    pub identity_key: IdentityKey,
}
