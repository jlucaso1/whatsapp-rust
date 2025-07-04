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

impl PreKeyBundle {
    pub fn new(
        registration_id: u32,
        device_id: u32,
        pre_key_id: Option<u32>,
        pre_key_public: Option<DjbEcPublicKey>,
        signed_pre_key_id: u32,
        signed_pre_key_public: DjbEcPublicKey,
        signed_pre_key_signature: [u8; 64],
        identity_key: IdentityKey,
    ) -> Self {
        Self {
            registration_id,
            device_id,
            pre_key_id,
            pre_key_public,
            signed_pre_key_id,
            signed_pre_key_public,
            signed_pre_key_signature,
            identity_key,
        }
    }
}
