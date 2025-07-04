use prost::Message;

use crate::signal::protocol::ProtocolError;

pub const SENDERKEY_TYPE: u32 = 4;

#[derive(Clone)]
pub struct SenderKeyMessage {
    key_id: u32,
    iteration: u32,
    ciphertext: Vec<u8>,
    signature: [u8; 64],
}

impl SenderKeyMessage {
    pub fn deserialize(serialized: &[u8]) -> Result<Self, ProtocolError> {
        let version = serialized[0] >> 4;
        if version < 3 {
            return Err(ProtocolError::InvalidVersion(version));
        }
        let proto_bytes = &serialized[1..serialized.len() - 64];
        let signature: [u8; 64] = serialized[serialized.len() - 64..].try_into().unwrap();

        let proto = crate::proto::whatsapp::SenderKeyMessage::decode(proto_bytes)?;
        Ok(Self {
            key_id: proto.id.unwrap_or(0),
            iteration: proto.iteration.unwrap_or(0),
            ciphertext: proto.ciphertext.unwrap_or_default(),
            signature,
        })
    }

    pub fn serialize_for_signature(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push((3 << 4) | 3); // Hardcoded version 3
        let proto_msg = crate::proto::whatsapp::SenderKeyMessage {
            id: Some(self.key_id),
            iteration: Some(self.iteration),
            ciphertext: Some(self.ciphertext.clone()),
        };
        proto_msg.encode(&mut buf).unwrap();
        buf
    }

    pub fn key_id(&self) -> u32 {
        self.key_id
    }
    pub fn iteration(&self) -> u32 {
        self.iteration
    }
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
    pub fn signature(&self) -> [u8; 64] {
        self.signature
    }
}
