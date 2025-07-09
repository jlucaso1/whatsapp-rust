#[derive(Clone, Debug)]
pub struct SenderKeyMessage {
    key_id: u32,
    iteration: u32,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
}

impl SenderKeyMessage {
    pub fn new(key_id: u32, iteration: u32, ciphertext: Vec<u8>, signature: Vec<u8>) -> Self {
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
        let signature = serialized[serialized.len() - 64..].to_vec();

        let proto = whatsapp_proto::whatsapp::SenderKeyMessage::decode(proto_bytes)?;

        Ok(Self {
            key_id: proto.id.unwrap_or(0),
            iteration: proto.iteration.unwrap_or(0),
            ciphertext: proto.ciphertext.unwrap_or_default(),
            signature,
        })
    }
}
