use prost::Message;
use waproto::whatsapp as wa;

/// Represents a SenderKeyMessage, wrapping the protobuf struct and signature.
#[derive(Clone, Debug)]
pub struct SenderKeyMessage {
    pub proto: wa::SenderKeyMessage,
    pub signature: [u8; 64],
}

impl SenderKeyMessage {
    /// Create a new SenderKeyMessage from components.
    pub fn new(key_id: u32, iteration: u32, ciphertext: Vec<u8>, signature: [u8; 64]) -> Self {
        Self {
            proto: wa::SenderKeyMessage {
                id: Some(key_id),
                iteration: Some(iteration),
                ciphertext: Some(ciphertext),
            },
            signature,
        }
    }

    /// Get the key ID.
    pub fn key_id(&self) -> u32 {
        self.proto.id.unwrap_or(0)
    }

    /// Get the iteration.
    pub fn iteration(&self) -> u32 {
        self.proto.iteration.unwrap_or(0)
    }

    /// Get the ciphertext.
    pub fn ciphertext(&self) -> &[u8] {
        self.proto.ciphertext.as_deref().unwrap_or_default()
    }

    /// Get the signature.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Deserialize a SenderKeyMessage from bytes.
    pub fn deserialize(serialized: &[u8]) -> Result<(Self, &[u8]), anyhow::Error> {
        if serialized.is_empty() {
            return Err(anyhow::anyhow!("Empty serialized SenderKeyMessage"));
        }

        let version = serialized[0];
        let message_version = (version & 0xF0) >> 4;

        if message_version < 3 {
            return Err(anyhow::anyhow!(
                "Legacy SenderKeyMessage versions not supported"
            ));
        }
        if message_version > 3 {
            return Err(anyhow::anyhow!(
                "Unknown SenderKeyMessage version: {}",
                message_version
            ));
        }

        if serialized.len() < 1 + 64 {
            return Err(anyhow::anyhow!("Too short SenderKeyMessage for signature"));
        }

        // The signature covers the version byte and the proto bytes.
        let data_to_verify = &serialized[..serialized.len() - 64];
        let proto_bytes = &data_to_verify[1..];
        let signature: [u8; 64] = serialized[serialized.len() - 64..]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;

        let proto = wa::SenderKeyMessage::decode(proto_bytes)?;

        Ok((Self { proto, signature }, data_to_verify))
    }

    /// Serialize the SenderKeyMessage to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut proto_buf = Vec::new();
        self.proto.encode(&mut proto_buf).unwrap(); // Should not fail

        // Assemble the final message: 1 (version) + N (protobuf) + 64 (signature)
        let mut final_buf = Vec::with_capacity(1 + proto_buf.len() + 64);
        final_buf.push((3 << 4) | 3); // Version 3
        final_buf.extend_from_slice(&proto_buf);
        final_buf.extend_from_slice(&self.signature);

        final_buf
    }
}
