use crate::signal::ecc::keys::DjbEcPublicKey;

#[derive(Clone)]
pub struct SenderKeyDistributionMessage {
    id: u32,
    iteration: u32,
    chain_key: Vec<u8>,
    signing_key: DjbEcPublicKey,
}

impl SenderKeyDistributionMessage {
    pub fn new(id: u32, iteration: u32, chain_key: Vec<u8>, signing_key: DjbEcPublicKey) -> Self {
        Self {
            id,
            iteration,
            chain_key,
            signing_key,
        }
    }
    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn iteration(&self) -> u32 {
        self.iteration
    }
    pub fn chain_key(&self) -> &[u8] {
        &self.chain_key
    }
    pub fn signing_key(&self) -> &DjbEcPublicKey {
        &self.signing_key
    }
}

#[derive(Clone)]
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
    pub fn serialize_for_signature(&self) -> Vec<u8> {
        // Implement actual serialization logic as needed
        let mut out = Vec::new();
        out.extend(&self.key_id.to_be_bytes());
        out.extend(&self.iteration.to_be_bytes());
        out.extend(&self.ciphertext);
        out
    }
}
