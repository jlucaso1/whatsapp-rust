use super::ecc::keys::EcPublicKey;
use super::identity::IdentityKey;
use super::protos;
use hmac::{Hmac, Mac};
use prost::Message;
use sha2::Sha256;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("bad MAC")]
    BadMac,
    #[error("invalid message version: {0}")]
    InvalidVersion(u8),
    #[error("incomplete message")]
    IncompleteMessage,
    #[error("invalid proto message: {0}")]
    Proto(#[from] prost::DecodeError),
    #[error("invalid key: {0}")]
    InvalidKey(#[from] super::ecc::curve::CurveError),
    #[error("untrusted identity")]
    UntrustedIdentity,
    #[error("old counter: current={0}, received={1}")]
    OldCounter(u32, u32),
}

pub trait CiphertextMessage: Send {
    fn serialize(&self) -> Vec<u8>;
    fn q_type(&self) -> u32;
}

pub enum Ciphertext {
    PreKey(PreKeySignalMessage),
    Whisper(SignalMessage),
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
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
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

    pub fn deserialize(serialized: &[u8]) -> Result<Self, ProtocolError> {
        if serialized.len() < 1 + MAC_LENGTH {
            return Err(ProtocolError::IncompleteMessage);
        }
        let version_byte = serialized[0];
        let message_version = version_byte >> 4;
        if message_version != CURRENT_VERSION {
            return Err(ProtocolError::InvalidVersion(message_version));
        }
        let serialized_proto = &serialized[1..serialized.len() - MAC_LENGTH];
        let proto = protos::SignalMessage::decode(serialized_proto)?;
        let ratchet_key_bytes = proto.ratchet_key.ok_or(ProtocolError::IncompleteMessage)?;
        let ratchet_key = super::ecc::curve::decode_point(&ratchet_key_bytes)?;
        Ok(SignalMessage {
            sender_ratchet_key: Arc::new(ratchet_key) as Arc<dyn super::ecc::keys::EcPublicKey>,
            counter: proto.counter.ok_or(ProtocolError::IncompleteMessage)?,
            previous_counter: proto.previous_counter.unwrap_or(0),
            ciphertext: proto.ciphertext.ok_or(ProtocolError::IncompleteMessage)?,
            serialized_form: serialized.to_vec(),
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

    pub fn deserialize_and_verify(
        serialized: &[u8],
        mac_key: &[u8],
        sender_identity: &IdentityKey,
        receiver_identity: &IdentityKey,
    ) -> Result<Self, ProtocolError> {
        if serialized.len() < 1 + MAC_LENGTH {
            return Err(ProtocolError::IncompleteMessage);
        }

        let version_byte = serialized[0];
        let message_version = version_byte >> 4;
        if message_version != CURRENT_VERSION {
            return Err(ProtocolError::InvalidVersion(message_version));
        }

        let serialized_proto = &serialized[1..serialized.len() - MAC_LENGTH];
        let their_mac = &serialized[serialized.len() - MAC_LENGTH..];

        let our_mac = Self::get_mac(
            sender_identity,
            receiver_identity,
            mac_key,
            &[version_byte],
            serialized_proto,
        );

        if our_mac.ct_eq(their_mac).unwrap_u8() != 1 {
            return Err(ProtocolError::BadMac);
        }

        let proto =
            protos::SignalMessage::decode(serialized_proto).map_err(ProtocolError::Proto)?;
        let ratchet_key_bytes = proto.ratchet_key.ok_or(ProtocolError::IncompleteMessage)?;
        let ratchet_key = super::ecc::curve::decode_point(&ratchet_key_bytes)
            .map_err(ProtocolError::InvalidKey)?;

        Ok(Self {
            sender_ratchet_key: Arc::new(ratchet_key) as Arc<dyn super::ecc::keys::EcPublicKey>,
            counter: proto.counter.ok_or(ProtocolError::IncompleteMessage)?,
            previous_counter: proto.previous_counter.unwrap_or(0),
            ciphertext: proto.ciphertext.ok_or(ProtocolError::IncompleteMessage)?,
            serialized_form: serialized.to_vec(),
        })
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
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
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

    // Simple deserialization without MAC verification
    pub fn deserialize(serialized: &[u8]) -> Result<Self, ProtocolError> {
        if serialized.len() < 2 {
            return Err(ProtocolError::IncompleteMessage);
        }
        let version_byte = serialized[0];
        let message_version = version_byte >> 4;
        if message_version != CURRENT_VERSION {
            return Err(ProtocolError::InvalidVersion(message_version));
        }
        let proto =
            protos::PreKeySignalMessage::decode(&serialized[1..]).map_err(ProtocolError::Proto)?;
        let registration_id = proto
            .registration_id
            .ok_or(ProtocolError::IncompleteMessage)?;
        let pre_key_id = proto.pre_key_id;
        let signed_pre_key_id = proto
            .signed_pre_key_id
            .ok_or(ProtocolError::IncompleteMessage)?;
        let base_key = proto.base_key.ok_or(ProtocolError::IncompleteMessage)?;
        let identity_key = proto.identity_key.ok_or(ProtocolError::IncompleteMessage)?;
        let message_bytes = proto.message.ok_or(ProtocolError::IncompleteMessage)?;
        let base_key = super::ecc::curve::decode_point(&base_key)?;
        let identity_key = IdentityKey::deserialize(&identity_key)?;
        let message = SignalMessage::deserialize(&message_bytes)?;
        Ok(Self {
            registration_id,
            pre_key_id,
            signed_pre_key_id,
            base_key: Arc::new(base_key) as Arc<dyn super::ecc::keys::EcPublicKey>,
            identity_key,
            message,
            serialized_form: serialized.to_vec(),
        })
    }
}

// --- Move these impls to module scope ---

impl From<protos::SignalMessage> for SignalMessage {
    fn from(proto: protos::SignalMessage) -> Self {
        Self {
            counter: proto.counter.unwrap_or_default(),
            previous_counter: proto.previous_counter.unwrap_or_default(),
            ciphertext: proto.ciphertext.unwrap_or_default(),
            ..Default::default()
        }
    }
}

impl Default for SignalMessage {
    fn default() -> Self {
        Self {
            sender_ratchet_key: Arc::new(super::ecc::keys::DjbEcPublicKey::new([0; 32])),
            counter: 0,
            previous_counter: 0,
            ciphertext: Vec::new(),
            serialized_form: Vec::new(),
        }
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

impl From<crate::signal::root_key::RootKeyError> for ProtocolError {
    fn from(e: crate::signal::root_key::RootKeyError) -> Self {
        ProtocolError::Proto(prost::DecodeError::new(std::borrow::Cow::Owned(format!(
            "{:?}",
            e
        ))))
    }
}
impl From<super::ratchet::RatchetError> for ProtocolError {
    fn from(e: super::ratchet::RatchetError) -> Self {
        match e {
            super::ratchet::RatchetError::OldCounter { current, received } => {
                Self::OldCounter(current, received)
            }
            super::ratchet::RatchetError::TooFarInFuture => {
                Self::Proto(prost::DecodeError::new("message too far in future"))
            }
        }
    }
}
