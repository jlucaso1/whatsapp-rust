use crate::signal::ecc::keys::DjbEcPublicKey;
use crate::signal::identity::IdentityKey;

#[derive(Debug)]
pub struct PreKeyBundle {
    pub registration_id: u32,
    pub device_id: u32,
    pub pre_key_id: Option<u32>,
    pub pre_key_public: Option<DjbEcPublicKey>,
    pub signed_pre_key_id: u32,
    pub signed_pre_key_public: DjbEcPublicKey,
    pub signed_pre_key_signature: [u8; 64],
    pub identity_key: IdentityKey,
}
