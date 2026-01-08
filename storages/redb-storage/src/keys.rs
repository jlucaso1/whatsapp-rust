use wacore::libsignal::protocol::{KeyPair, PrivateKey, PublicKey};
use wacore::store::error::{Result, StoreError};

#[derive(Clone, Copy)]
pub struct KeyBuilder {
    device_id: i32,
}

impl KeyBuilder {
    pub fn new(device_id: i32) -> Self {
        Self { device_id }
    }

    #[inline]
    pub fn key1(&self, field1: &str) -> String {
        format!("{}:{}", self.device_id, field1)
    }

    #[inline]
    pub fn key2(&self, field1: &str, field2: &str) -> String {
        format!("{}:{}:{}", self.device_id, field1, field2)
    }

    #[inline]
    pub fn prefix(&self) -> String {
        format!("{}:", self.device_id)
    }

    #[inline]
    pub fn pack_id(&self, id: u32) -> u64 {
        ((self.device_id as u64) << 32) | (id as u64)
    }

    #[inline]
    pub fn pack_id_range(&self) -> std::ops::RangeInclusive<u64> {
        let min = (self.device_id as u64) << 32;
        let max = min | 0xFFFFFFFF;
        min..=max
    }

    #[inline]
    pub fn app_state_key(&self, key_id: &[u8]) -> Vec<u8> {
        let mut key = Vec::with_capacity(4 + key_id.len());
        key.extend_from_slice(&self.device_id.to_le_bytes());
        key.extend_from_slice(key_id);
        key
    }
}

#[inline]
pub fn serialize_keypair(key_pair: &KeyPair) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&key_pair.private_key.serialize());
    bytes.extend_from_slice(key_pair.public_key.public_key_bytes());
    bytes
}

#[inline]
pub fn deserialize_keypair(bytes: &[u8]) -> Result<KeyPair> {
    if bytes.len() != 64 {
        return Err(StoreError::Serialization(format!(
            "Invalid KeyPair length: expected 64, got {}",
            bytes.len()
        )));
    }

    let private_key = PrivateKey::deserialize(&bytes[0..32])
        .map_err(|e| StoreError::Serialization(e.to_string()))?;
    let public_key = PublicKey::from_djb_public_key_bytes(&bytes[32..64])
        .map_err(|e| StoreError::Serialization(e.to_string()))?;

    Ok(KeyPair::new(public_key, private_key))
}

#[inline]
pub fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serde::encode_to_vec(value, bincode::config::standard())
        .map_err(|e| StoreError::Serialization(e.to_string()))
}

#[inline]
pub fn decode<T: for<'de> serde::Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    let (value, _) = bincode::serde::decode_from_slice(bytes, bincode::config::standard())
        .map_err(|e| StoreError::Serialization(e.to_string()))?;
    Ok(value)
}
