use chrono::Utc;
use libsignal_protocol::KeyPair;
use waproto::whatsapp as wa;

pub fn new_pre_key_record(id: u32, key_pair: &KeyPair) -> wa::PreKeyRecordStructure {
    wa::PreKeyRecordStructure {
        id: Some(id),
        public_key: Some(key_pair.public_key.public_key_bytes().to_vec()),
        private_key: Some(key_pair.private_key.serialize()),
    }
}

pub fn new_signed_pre_key_record(
    id: u32,
    key_pair: &KeyPair,
    signature: [u8; 64],
    timestamp: chrono::DateTime<Utc>,
) -> wa::SignedPreKeyRecordStructure {
    wa::SignedPreKeyRecordStructure {
        id: Some(id),
        public_key: Some(key_pair.public_key.public_key_bytes().to_vec()),
        private_key: Some(key_pair.private_key.serialize()),
        signature: Some(signature.to_vec()),
        timestamp: Some(timestamp.timestamp().try_into().unwrap()),
    }
}
