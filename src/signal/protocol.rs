use super::ecc::keys::EcPublicKey;
use super::identity::IdentityKey;
use std::sync::Arc;

// Base trait for all ciphertext messages
pub trait CiphertextMessage {
    fn serialize(&self) -> Vec<u8>;
    fn q_type(&self) -> u32;
}

pub const WHISPER_TYPE: u32 = 2;
pub const PREKEY_TYPE: u32 = 3;

// Corresponds to protocol/SignalMessage.go
pub struct SignalMessage {
    pub sender_ratchet_key: Arc<dyn EcPublicKey>,
    pub counter: u32,
    pub previous_counter: u32,
    pub ciphertext: Vec<u8>,
    pub serialized_form: Vec<u8>,
}

impl SignalMessage {
    pub fn serialize(&self) -> Vec<u8> {
        self.serialized_form.clone()
    }
}

impl CiphertextMessage for SignalMessage {
    fn serialize(&self) -> Vec<u8> {
        self.serialized_form.clone()
    }
    fn q_type(&self) -> u32 {
        WHISPER_TYPE
    }
}

// Corresponds to protocol/PreKeySignalMessage.go
pub struct PreKeySignalMessage {
    pub registration_id: u32,
    pub pre_key_id: Option<u32>,
    pub signed_pre_key_id: u32,
    pub base_key: Arc<dyn EcPublicKey>,
    pub identity_key: IdentityKey,
    pub message: SignalMessage,
    pub serialized_form: Vec<u8>,
}

impl PreKeySignalMessage {
    pub fn serialize(&self) -> Vec<u8> {
        self.serialized_form.clone()
    }
}

impl CiphertextMessage for PreKeySignalMessage {
    fn serialize(&self) -> Vec<u8> {
        self.serialized_form.clone()
    }
    fn q_type(&self) -> u32 {
        PREKEY_TYPE
    }
}
