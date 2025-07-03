use super::ecc::keys::EcPublicKey;
use super::identity::IdentityKey;
use super::protos;
use hmac::{Hmac, Mac};
use prost::Message;
use sha2::Sha256;
use std::sync::Arc;

pub trait CiphertextMessage {
    fn serialize(&self) -> Vec<u8>;
    fn q_type(&self) -> u32;
}

pub const WHISPER_TYPE: u32 = 2;
pub const PREKEY_TYPE: u32 = 3;
const MAC_LENGTH: usize = 8;
const CURRENT_VERSION: u8 = 3;

// --- SignalMessage ---
pub struct SignalMessage {
    pub sender_ratchet_key: Arc<dyn EcPublicKey>,
    pub counter: u32,
    pub previous_counter: u32,
    pub ciphertext: Vec<u8>,
    pub serialized_form: Vec<u8>,
}

impl SignalMessage {
    pub fn new(
        mac_key: &[u8],
        sender_ratchet_key: Arc<dyn EcPublicKey>,
        counter: u32,
        previous_counter: u32,
        ciphertext: Vec<u8>,
        sender_identity_key: &IdentityKey,
        receiver_identity_key: &IdentityKey,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let version_byte = (CURRENT_VERSION << 4) | CURRENT_VERSION;

        let proto = protos::SignalMessage {
            ratchet_key: Some(sender_ratchet_key.serialize()),
            counter: Some(counter),
            previous_counter: Some(previous_counter),
            ciphertext: Some(ciphertext.clone()),
        };

        let mut serialized_proto = Vec::new();
        proto.encode(&mut serialized_proto)?;

        let mac = Self::get_mac(
            sender_identity_key,
            receiver_identity_key,
            mac_key,
            &[version_byte],
            &serialized_proto,
        );

        let mut serialized_form = Vec::with_capacity(1 + serialized_proto.len() + MAC_LENGTH);
        serialized_form.push(version_byte);
        serialized_form.extend_from_slice(&serialized_proto);
        serialized_form.extend_from_slice(&mac);

        Ok(Self {
            sender_ratchet_key,
            counter,
            previous_counter,
            ciphertext,
            serialized_form,
        })
    }

    fn get_mac(
        sender_identity_key: &IdentityKey,
        receiver_identity_key: &IdentityKey,
        mac_key: &[u8],
        version_bytes: &[u8],
        serialized_proto: &[u8],
    ) -> [u8; MAC_LENGTH] {
        let mut mac = Hmac::<Sha256>::new_from_slice(mac_key).unwrap();
        mac.update(sender_identity_key.serialize().as_slice());
        mac.update(receiver_identity_key.serialize().as_slice());
        mac.update(version_bytes);
        mac.update(serialized_proto);

        let full_mac = mac.finalize().into_bytes();
        full_mac[..MAC_LENGTH].try_into().unwrap()
    }

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

// --- PreKeySignalMessage ---
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
    pub fn new(
        registration_id: u32,
        pre_key_id: Option<u32>,
        signed_pre_key_id: u32,
        base_key: Arc<dyn EcPublicKey>,
        identity_key: IdentityKey,
        message: SignalMessage,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let version_byte = (CURRENT_VERSION << 4) | CURRENT_VERSION;

        let proto = protos::PreKeySignalMessage {
            registration_id: Some(registration_id),
            pre_key_id,
            signed_pre_key_id: Some(signed_pre_key_id),
            base_key: Some(base_key.serialize()),
            identity_key: Some(identity_key.serialize()),
            message: Some(message.serialize()),
        };

        let mut serialized_proto = Vec::new();
        proto.encode(&mut serialized_proto)?;

        let mut serialized_form = Vec::with_capacity(1 + serialized_proto.len());
        serialized_form.push(version_byte);
        serialized_form.extend_from_slice(&serialized_proto);

        Ok(Self {
            registration_id,
            pre_key_id,
            signed_pre_key_id,
            base_key,
            identity_key,
            message,
            serialized_form,
        })
    }

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
