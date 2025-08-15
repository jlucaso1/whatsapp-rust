//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use hmac::{Hmac, Mac};
use prost::Message;
use rand::{CryptoRng, Rng};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::libsignal::protocol::state::{PreKeyId, SignedPreKeyId};
use crate::libsignal::protocol::{
    IdentityKey, PrivateKey, PublicKey, Result, SignalProtocolError, Timestamp,
};

pub const CIPHERTEXT_MESSAGE_CURRENT_VERSION: u8 = 4;
pub const SENDERKEY_MESSAGE_CURRENT_VERSION: u8 = 3;

#[derive(Debug)]
pub enum CiphertextMessage {
    SignalMessage(SignalMessage),
    PreKeySignalMessage(PreKeySignalMessage),
    SenderKeyMessage(SenderKeyMessage),
    PlaintextContent(PlaintextContent),
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, derive_more::TryFrom)]
#[repr(u8)]
#[try_from(repr)]
pub enum CiphertextMessageType {
    Whisper = 2,
    PreKey = 3,
    SenderKey = 7,
    Plaintext = 8,
}

impl CiphertextMessage {
    pub fn message_type(&self) -> CiphertextMessageType {
        match self {
            CiphertextMessage::SignalMessage(_) => CiphertextMessageType::Whisper,
            CiphertextMessage::PreKeySignalMessage(_) => CiphertextMessageType::PreKey,
            CiphertextMessage::SenderKeyMessage(_) => CiphertextMessageType::SenderKey,
            CiphertextMessage::PlaintextContent(_) => CiphertextMessageType::Plaintext,
        }
    }

    pub fn serialize(&self) -> &[u8] {
        match self {
            CiphertextMessage::SignalMessage(x) => x.serialized(),
            CiphertextMessage::PreKeySignalMessage(x) => x.serialized(),
            CiphertextMessage::SenderKeyMessage(x) => x.serialized(),
            CiphertextMessage::PlaintextContent(x) => x.serialized(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignalMessage {
    message_version: u8,
    sender_ratchet_key: PublicKey,
    counter: u32,
    #[cfg_attr(not(test), expect(dead_code))]
    previous_counter: u32,
    ciphertext: Box<[u8]>,
    serialized: Box<[u8]>,
}

impl SignalMessage {
    const MAC_LENGTH: usize = 8;

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        message_version: u8,
        mac_key: &[u8],
        sender_ratchet_key: PublicKey,
        counter: u32,
        previous_counter: u32,
        ciphertext: &[u8],
        sender_identity_key: &IdentityKey,
        receiver_identity_key: &IdentityKey,
    ) -> Result<Self> {
        let message = waproto::whatsapp::SignalMessage {
            ratchet_key: Some(sender_ratchet_key.serialize().into_vec()),
            counter: Some(counter),
            previous_counter: Some(previous_counter),
            ciphertext: Some(Vec::<u8>::from(ciphertext)),
        };
        let mut serialized = Vec::with_capacity(1 + message.encoded_len() + Self::MAC_LENGTH);
        serialized.push(((message_version & 0xF) << 4) | CIPHERTEXT_MESSAGE_CURRENT_VERSION);
        message
            .encode(&mut serialized)
            .expect("can always append to a buffer");
        let mac = Self::compute_mac(
            sender_identity_key,
            receiver_identity_key,
            mac_key,
            &serialized,
        )?;
        serialized.extend_from_slice(&mac);
        let serialized = serialized.into_boxed_slice();
        Ok(Self {
            message_version,
            sender_ratchet_key,
            counter,
            previous_counter,
            ciphertext: ciphertext.into(),
            serialized,
        })
    }

    #[inline]
    pub fn message_version(&self) -> u8 {
        self.message_version
    }

    #[inline]
    pub fn sender_ratchet_key(&self) -> &PublicKey {
        &self.sender_ratchet_key
    }

    #[inline]
    pub fn counter(&self) -> u32 {
        self.counter
    }

    #[inline]
    pub fn serialized(&self) -> &[u8] {
        &self.serialized
    }

    #[inline]
    pub fn body(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn verify_mac(
        &self,
        sender_identity_key: &IdentityKey,
        receiver_identity_key: &IdentityKey,
        mac_key: &[u8],
    ) -> Result<bool> {
        let our_mac = &Self::compute_mac(
            sender_identity_key,
            receiver_identity_key,
            mac_key,
            &self.serialized[..self.serialized.len() - Self::MAC_LENGTH],
        )?;
        let their_mac = &self.serialized[self.serialized.len() - Self::MAC_LENGTH..];
        let result: bool = our_mac.ct_eq(their_mac).into();
        if !result {
            // A warning instead of an error because we try multiple sessions.
            log::warn!(
                "Bad Mac! Their Mac: {} Our Mac: {}",
                hex::encode(their_mac),
                hex::encode(our_mac)
            );
        }
        Ok(result)
    }

    fn compute_mac(
        sender_identity_key: &IdentityKey,
        receiver_identity_key: &IdentityKey,
        mac_key: &[u8],
        message: &[u8],
    ) -> Result<[u8; Self::MAC_LENGTH]> {
        if mac_key.len() != 32 {
            return Err(SignalProtocolError::InvalidMacKeyLength(mac_key.len()));
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(mac_key)
            .expect("HMAC-SHA256 should accept any size key");

        mac.update(sender_identity_key.public_key().serialize().as_ref());
        mac.update(receiver_identity_key.public_key().serialize().as_ref());
        mac.update(message);
        let mut result = [0u8; Self::MAC_LENGTH];
        result.copy_from_slice(&mac.finalize().into_bytes()[..Self::MAC_LENGTH]);
        Ok(result)
    }
}

impl AsRef<[u8]> for SignalMessage {
    fn as_ref(&self) -> &[u8] {
        &self.serialized
    }
}

impl TryFrom<&[u8]> for SignalMessage {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() < SignalMessage::MAC_LENGTH + 1 {
            return Err(SignalProtocolError::CiphertextMessageTooShort(value.len()));
        }
        let message_version = value[0] >> 4;

        if message_version > CIPHERTEXT_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::UnrecognizedCiphertextVersion(
                message_version,
            ));
        }

        let proto_structure = waproto::whatsapp::SignalMessage::decode(
            &value[1..value.len() - SignalMessage::MAC_LENGTH],
        )
        .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;

        let sender_ratchet_key = proto_structure
            .ratchet_key
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let sender_ratchet_key = PublicKey::deserialize(&sender_ratchet_key)?;
        let counter = proto_structure
            .counter
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let previous_counter = proto_structure.previous_counter.unwrap_or(0);
        let ciphertext = proto_structure
            .ciphertext
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
            .into_boxed_slice();

        Ok(SignalMessage {
            message_version,
            sender_ratchet_key,
            counter,
            previous_counter,
            ciphertext,
            serialized: Box::from(value),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PreKeySignalMessage {
    message_version: u8,
    registration_id: u32,
    pre_key_id: Option<PreKeyId>,
    signed_pre_key_id: SignedPreKeyId,
    base_key: PublicKey,
    identity_key: IdentityKey,
    message: SignalMessage,
    serialized: Box<[u8]>,
}

impl PreKeySignalMessage {
    pub fn new(
        message_version: u8,
        registration_id: u32,
        pre_key_id: Option<PreKeyId>,
        signed_pre_key_id: SignedPreKeyId,
        base_key: PublicKey,
        identity_key: IdentityKey,
        message: SignalMessage,
    ) -> Result<Self> {
        let proto_message = waproto::whatsapp::PreKeySignalMessage {
            registration_id: Some(registration_id),
            pre_key_id: pre_key_id.map(|id| id.into()),
            signed_pre_key_id: Some(signed_pre_key_id.into()),
            base_key: Some(base_key.serialize().into_vec()),
            identity_key: Some(identity_key.serialize().into_vec()),
            message: Some(Vec::from(message.as_ref())),
        };
        let mut serialized = Vec::with_capacity(1 + proto_message.encoded_len());
        serialized.push(((message_version & 0xF) << 4) | CIPHERTEXT_MESSAGE_CURRENT_VERSION);
        proto_message
            .encode(&mut serialized)
            .expect("can always append to a Vec");
        Ok(Self {
            message_version,
            registration_id,
            pre_key_id,
            signed_pre_key_id,
            base_key,
            identity_key,
            message,
            serialized: serialized.into_boxed_slice(),
        })
    }

    #[inline]
    pub fn message_version(&self) -> u8 {
        self.message_version
    }

    #[inline]
    pub fn registration_id(&self) -> u32 {
        self.registration_id
    }

    #[inline]
    pub fn pre_key_id(&self) -> Option<PreKeyId> {
        self.pre_key_id
    }

    #[inline]
    pub fn signed_pre_key_id(&self) -> SignedPreKeyId {
        self.signed_pre_key_id
    }

    #[inline]
    pub fn base_key(&self) -> &PublicKey {
        &self.base_key
    }

    #[inline]
    pub fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    #[inline]
    pub fn message(&self) -> &SignalMessage {
        &self.message
    }

    #[inline]
    pub fn serialized(&self) -> &[u8] {
        &self.serialized
    }
}

impl AsRef<[u8]> for PreKeySignalMessage {
    fn as_ref(&self) -> &[u8] {
        &self.serialized
    }
}

impl TryFrom<&[u8]> for PreKeySignalMessage {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(SignalProtocolError::CiphertextMessageTooShort(value.len()));
        }

        let message_version = value[0] >> 4;

        if message_version > CIPHERTEXT_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::UnrecognizedCiphertextVersion(
                message_version,
            ));
        }

        let proto_structure = waproto::whatsapp::PreKeySignalMessage::decode(&value[1..])
            .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;

        let base_key = proto_structure
            .base_key
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let identity_key = proto_structure
            .identity_key
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let message = proto_structure
            .message
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let signed_pre_key_id = proto_structure
            .signed_pre_key_id
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;

        let base_key = PublicKey::deserialize(base_key.as_ref())?;

        Ok(PreKeySignalMessage {
            message_version,
            registration_id: proto_structure.registration_id.unwrap_or(0),
            pre_key_id: proto_structure.pre_key_id.map(|id| id.into()),
            signed_pre_key_id: signed_pre_key_id.into(),
            base_key,
            identity_key: IdentityKey::try_from(identity_key.as_ref())?,
            message: SignalMessage::try_from(message.as_ref())?,
            serialized: Box::from(value),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SenderKeyMessage {
    message_version: u8,
    chain_id: u32,
    iteration: u32,
    ciphertext: Box<[u8]>,
    serialized: Box<[u8]>,
}

impl SenderKeyMessage {
    const SIGNATURE_LEN: usize = 64;

    pub fn new<R: CryptoRng + Rng>(
        message_version: u8,
        chain_id: u32,
        iteration: u32,
        ciphertext: Box<[u8]>,
        csprng: &mut R,
        signature_key: &PrivateKey,
    ) -> Result<Self> {
        let proto_message = waproto::whatsapp::SenderKeyMessage {
            id: Some(chain_id),
            iteration: Some(iteration),
            ciphertext: Some(ciphertext.to_vec()),
        };

        let proto_bytes = proto_message.encode_to_vec();

        let signature = signature_key
            .calculate_signature(&proto_bytes, csprng)
            .map_err(|_| SignalProtocolError::SignatureValidationFailed)?;

        let shifted_version = (message_version << 4) | 3u8;

        let mut serialized = vec![shifted_version];

        serialized.extend_from_slice(&proto_bytes);
        serialized.extend_from_slice(&signature);

        Ok(Self {
            message_version,
            chain_id,
            iteration,
            ciphertext,
            serialized: Box::from(serialized),
        })
    }

    pub fn verify_signature(&self, signature_key: &PublicKey) -> Result<bool> {
        let valid = signature_key.verify_signature(
            &self.serialized[..self.serialized.len() - Self::SIGNATURE_LEN],
            &self.serialized[self.serialized.len() - Self::SIGNATURE_LEN..],
        );

        Ok(valid)
    }

    #[inline]
    pub fn message_version(&self) -> u8 {
        self.message_version
    }

    #[inline]
    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }

    #[inline]
    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    #[inline]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    #[inline]
    pub fn serialized(&self) -> &[u8] {
        &self.serialized
    }
}

impl AsRef<[u8]> for SenderKeyMessage {
    fn as_ref(&self) -> &[u8] {
        &self.serialized
    }
}

impl TryFrom<&[u8]> for SenderKeyMessage {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() < 1 + Self::SIGNATURE_LEN {
            return Err(SignalProtocolError::CiphertextMessageTooShort(value.len()));
        }
        let message_version = value[0] >> 4;
        if message_version < SENDERKEY_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::LegacyCiphertextVersion(
                message_version,
            ));
        }
        if message_version > SENDERKEY_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::UnrecognizedCiphertextVersion(
                message_version,
            ));
        }
        let proto_structure = waproto::whatsapp::SenderKeyMessage::decode(
            &value[1..value.len() - Self::SIGNATURE_LEN],
        )
        .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;

        let chain_id = proto_structure
            .id
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let iteration = proto_structure
            .iteration
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let ciphertext = proto_structure
            .ciphertext
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
            .into_boxed_slice();

        Ok(SenderKeyMessage {
            message_version,
            chain_id,
            iteration,
            ciphertext,
            serialized: Box::from(value),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SenderKeyDistributionMessage {
    message_version: u8,
    chain_id: u32,
    iteration: u32,
    chain_key: Vec<u8>,
    signing_key: PublicKey,
    serialized: Box<[u8]>,
}

impl SenderKeyDistributionMessage {
    pub fn new(
        message_version: u8,
        chain_id: u32,
        iteration: u32,
        chain_key: Vec<u8>,
        signing_key: PublicKey,
    ) -> Result<Self> {
        let proto_message = waproto::whatsapp::SenderKeyDistributionMessage {
            id: Some(chain_id),
            iteration: Some(iteration),
            chain_key: Some(chain_key.clone()),
            signing_key: Some(signing_key.serialize().to_vec()),
        };
        let mut serialized = Vec::with_capacity(1 + proto_message.encoded_len());
        serialized.push(((message_version & 0xF) << 4) | SENDERKEY_MESSAGE_CURRENT_VERSION);
        proto_message
            .encode(&mut serialized)
            .expect("can always append to a buffer");

        Ok(Self {
            message_version,
            chain_id,
            iteration,
            chain_key,
            signing_key,
            serialized: serialized.into_boxed_slice(),
        })
    }

    #[inline]
    pub fn message_version(&self) -> u8 {
        self.message_version
    }

    #[inline]
    pub fn chain_id(&self) -> Result<u32> {
        Ok(self.chain_id)
    }

    #[inline]
    pub fn iteration(&self) -> Result<u32> {
        Ok(self.iteration)
    }

    #[inline]
    pub fn chain_key(&self) -> Result<&[u8]> {
        Ok(&self.chain_key)
    }

    #[inline]
    pub fn signing_key(&self) -> Result<&PublicKey> {
        Ok(&self.signing_key)
    }

    #[inline]
    pub fn serialized(&self) -> &[u8] {
        &self.serialized
    }
}

impl AsRef<[u8]> for SenderKeyDistributionMessage {
    fn as_ref(&self) -> &[u8] {
        &self.serialized
    }
}

impl TryFrom<&[u8]> for SenderKeyDistributionMessage {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        // The message contains at least a X25519 key and a chain key
        if value.len() < 1 + 32 + 32 {
            return Err(SignalProtocolError::CiphertextMessageTooShort(value.len()));
        }

        let message_version = value[0] >> 4;

        if message_version < SENDERKEY_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::LegacyCiphertextVersion(
                message_version,
            ));
        }
        if message_version > SENDERKEY_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::UnrecognizedCiphertextVersion(
                message_version,
            ));
        }

        let proto_structure = waproto::whatsapp::SenderKeyDistributionMessage::decode(&value[1..])
            .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;

        let chain_id = proto_structure
            .id
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let iteration = proto_structure
            .iteration
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let chain_key = proto_structure
            .chain_key
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let signing_key = proto_structure
            .signing_key
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;

        if chain_key.len() != 32 || signing_key.len() != 33 {
            return Err(SignalProtocolError::InvalidProtobufEncoding);
        }

        let signing_key = PublicKey::deserialize(&signing_key)?;

        Ok(SenderKeyDistributionMessage {
            message_version,
            chain_id,
            iteration,
            chain_key,
            signing_key,
            serialized: Box::from(value),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PlaintextContent {
    serialized: Box<[u8]>,
}

impl PlaintextContent {
    /// Identifies a serialized PlaintextContent.
    ///
    /// This ensures someone doesn't try to serialize an arbitrary Content message as
    /// PlaintextContent; only messages that are okay to send as plaintext should be allowed.
    const PLAINTEXT_CONTEXT_IDENTIFIER_BYTE: u8 = 0xC0;

    /// Marks the end of a message and the start of any padding.
    ///
    /// Usually messages are padded to avoid exposing patterns,
    /// but PlaintextContent messages are all fixed-length anyway, so there won't be any padding.
    const PADDING_BOUNDARY_BYTE: u8 = 0x80;

    #[inline]
    pub fn body(&self) -> &[u8] {
        &self.serialized[1..]
    }

    #[inline]
    pub fn serialized(&self) -> &[u8] {
        &self.serialized
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Content {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub data_message: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub sync_message: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub call_message: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub null_message: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub receipt_message: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "6")]
    pub typing_message: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "7")]
    pub sender_key_distribution_message: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "8")]
    pub decryption_error_message: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DecryptionErrorMessageProto {
    /// set to the public ratchet key from the SignalMessage if a 1-1 payload fails to decrypt
    #[prost(bytes = "vec", optional, tag = "1")]
    pub ratchet_key: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[prost(uint64, optional, tag = "2")]
    pub timestamp: ::core::option::Option<u64>,
    #[prost(uint32, optional, tag = "3")]
    pub device_id: ::core::option::Option<u32>,
}

impl From<DecryptionErrorMessage> for PlaintextContent {
    fn from(message: DecryptionErrorMessage) -> Self {
        let proto_structure = Content {
            decryption_error_message: Some(message.serialized().to_vec()),
            ..Default::default()
        };
        let mut serialized = vec![Self::PLAINTEXT_CONTEXT_IDENTIFIER_BYTE];
        proto_structure
            .encode(&mut serialized)
            .expect("can always encode to a Vec");
        serialized.push(Self::PADDING_BOUNDARY_BYTE);
        Self {
            serialized: Box::from(serialized),
        }
    }
}

impl TryFrom<&[u8]> for PlaintextContent {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(SignalProtocolError::CiphertextMessageTooShort(0));
        }
        if value[0] != Self::PLAINTEXT_CONTEXT_IDENTIFIER_BYTE {
            return Err(SignalProtocolError::UnrecognizedMessageVersion(
                value[0] as u32,
            ));
        }
        Ok(Self {
            serialized: Box::from(value),
        })
    }
}

#[derive(Debug, Clone)]
pub struct DecryptionErrorMessage {
    ratchet_key: Option<PublicKey>,
    timestamp: Timestamp,
    device_id: u32,
    serialized: Box<[u8]>,
}

impl DecryptionErrorMessage {
    pub fn for_original(
        original_bytes: &[u8],
        original_type: CiphertextMessageType,
        original_timestamp: Timestamp,
        original_sender_device_id: u32,
    ) -> Result<Self> {
        let ratchet_key = match original_type {
            CiphertextMessageType::Whisper => {
                Some(*SignalMessage::try_from(original_bytes)?.sender_ratchet_key())
            }
            CiphertextMessageType::PreKey => Some(
                *PreKeySignalMessage::try_from(original_bytes)?
                    .message()
                    .sender_ratchet_key(),
            ),
            CiphertextMessageType::SenderKey => None,
            CiphertextMessageType::Plaintext => {
                return Err(SignalProtocolError::InvalidArgument(
                    "cannot create a DecryptionErrorMessage for plaintext content; it is not encrypted".to_string()
                ));
            }
        };

        let proto_message = DecryptionErrorMessageProto {
            timestamp: Some(original_timestamp.epoch_millis()),
            ratchet_key: ratchet_key.map(|k| k.serialize().into()),
            device_id: Some(original_sender_device_id),
        };
        let serialized = proto_message.encode_to_vec();

        Ok(Self {
            ratchet_key,
            timestamp: original_timestamp,
            device_id: original_sender_device_id,
            serialized: serialized.into_boxed_slice(),
        })
    }

    #[inline]
    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    #[inline]
    pub fn ratchet_key(&self) -> Option<&PublicKey> {
        self.ratchet_key.as_ref()
    }

    #[inline]
    pub fn device_id(&self) -> u32 {
        self.device_id
    }

    #[inline]
    pub fn serialized(&self) -> &[u8] {
        &self.serialized
    }
}

impl TryFrom<&[u8]> for DecryptionErrorMessage {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let proto_structure = DecryptionErrorMessageProto::decode(value)
            .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;
        let timestamp = proto_structure
            .timestamp
            .map(Timestamp::from_epoch_millis)
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let ratchet_key = proto_structure
            .ratchet_key
            .map(|k| PublicKey::deserialize(&k))
            .transpose()?;
        let device_id = proto_structure.device_id.unwrap_or_default();
        Ok(Self {
            timestamp,
            ratchet_key,
            device_id,
            serialized: Box::from(value),
        })
    }
}

/// For testing
pub fn extract_decryption_error_message_from_serialized_content(
    bytes: &[u8],
) -> Result<DecryptionErrorMessage> {
    if bytes.last() != Some(&PlaintextContent::PADDING_BOUNDARY_BYTE) {
        return Err(SignalProtocolError::InvalidProtobufEncoding);
    }
    let content = Content::decode(bytes.split_last().expect("checked above").1)
        .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;
    content
        .decryption_error_message
        .as_deref()
        .ok_or_else(|| {
            SignalProtocolError::InvalidArgument(
                "Content does not contain DecryptionErrorMessage".to_owned(),
            )
        })
        .and_then(DecryptionErrorMessage::try_from)
}
