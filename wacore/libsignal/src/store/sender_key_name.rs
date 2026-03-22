use crate::protocol::ProtocolAddress;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct SenderKeyName {
    group_id: String,
    sender_id: String,
    /// Pre-computed `"{group_id}:{sender_id}"` cache key — avoids allocation on every load/store.
    cache_key: String,
}

impl SenderKeyName {
    pub fn new(group_id: String, sender_id: String) -> Self {
        let cache_key = format!("{group_id}:{sender_id}");
        Self {
            group_id,
            sender_id,
            cache_key,
        }
    }

    pub fn group_id(&self) -> &str {
        &self.group_id
    }
    pub fn sender_id(&self) -> &str {
        &self.sender_id
    }

    /// Returns the cached `"group_id:sender_id"` string without allocation.
    #[inline]
    pub fn cache_key(&self) -> &str {
        &self.cache_key
    }

    pub fn to_protocol_address(&self) -> ProtocolAddress {
        ProtocolAddress::new(format!("{}\n{}", self.group_id, self.sender_id), 0.into())
    }
}
