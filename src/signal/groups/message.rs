#[derive(Clone, Debug)]
pub struct SenderKeyMessage {
    key_id: u32,
    iteration: u32,
    ciphertext: Vec<u8>,
    signature: [u8; 64],
}

impl SenderKeyMessage {
    pub fn new(key_id: u32, iteration: u32, ciphertext: Vec<u8>, signature: [u8; 64]) -> Self {
        Self {
            key_id,
            iteration,
            ciphertext,
            signature,
        }
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
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn deserialize(serialized: &[u8]) -> Result<Self, anyhow::Error> {
        use prost::Message;

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
        let proto_bytes = &serialized[1..serialized.len() - 64];
        let signature: [u8; 64] = serialized[serialized.len() - 64..]
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;

        let proto = whatsapp_proto::whatsapp::SenderKeyMessage::decode(proto_bytes)?;

        Ok(Self {
            key_id: proto.id.unwrap_or(0),
            iteration: proto.iteration.unwrap_or(0),
            ciphertext: proto.ciphertext.unwrap_or_default(),
            signature,
        })
    }
    pub fn serialize(&self) -> Vec<u8> {
        use prost::Message;

        let proto_msg = whatsapp_proto::whatsapp::SenderKeyMessage {
            id: Some(self.key_id),
            iteration: Some(self.iteration),
            ciphertext: Some(self.ciphertext.clone()),
        };

        // Get the serialized protobuf message
        let mut proto_buf = Vec::new();
        proto_msg.encode(&mut proto_buf).unwrap(); // Should not fail

        // Assemble the final message: 1 (version) + N (protobuf) + 64 (signature)
        let mut final_buf = Vec::with_capacity(1 + proto_buf.len() + 64);
        final_buf.push((3 << 4) | 3); // Version 3
        final_buf.extend_from_slice(&proto_buf);
        final_buf.extend_from_slice(&self.signature);

        final_buf
    }
}
