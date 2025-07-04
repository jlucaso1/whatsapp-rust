// src/signal/state/unacknowledged_prekey.rs
// Corresponds to libsignal-protocol-go/state/record/UnacknowledgedPreKey.go

use crate::signal::ecc::keys::DjbEcPublicKey;

/// UnackPreKeyMessageItems is a structure for messages that have not been
/// acknowledged.
#[derive(Clone, Debug)]
pub struct UnacknowledgedPreKeyMessageItems {
    pre_key_id: Option<u32>,
    signed_pre_key_id: u32,
    base_key: DjbEcPublicKey,
}

impl UnacknowledgedPreKeyMessageItems {
    /// NewUnackPreKeyMessageItems returns message items that are unacknowledged.
    pub fn new(pre_key_id: Option<u32>, signed_pre_key_id: u32, base_key: DjbEcPublicKey) -> Self {
        Self {
            pre_key_id,
            signed_pre_key_id,
            base_key,
        }
    }

    pub fn pre_key_id(&self) -> Option<u32> {
        self.pre_key_id
    }
    pub fn signed_pre_key_id(&self) -> u32 {
        self.signed_pre_key_id
    }
    pub fn base_key(&self) -> &DjbEcPublicKey {
        &self.base_key
    }
}
