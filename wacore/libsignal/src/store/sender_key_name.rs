use crate::protocol::ProtocolAddress;

/// Identifies a sender key by group + sender address.
///
/// Stores a single `"{group_id}:{sender_id}"` buffer with an offset,
/// avoiding the 3 separate `String` allocations of the naive layout.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SenderKeyName {
    buf: String,
    group_len: usize,
}

impl SenderKeyName {
    pub fn new(group_id: String, sender_id: String) -> Self {
        let group_len = group_id.len();
        let mut buf = group_id;
        buf.reserve(1 + sender_id.len());
        buf.push(':');
        buf.push_str(&sender_id);
        Self { buf, group_len }
    }

    /// Build from pre-formatted string slices (1 allocation).
    pub fn from_parts(group_id: &str, sender_id: &str) -> Self {
        let mut buf = String::with_capacity(group_id.len() + 1 + sender_id.len());
        buf.push_str(group_id);
        buf.push(':');
        buf.push_str(sender_id);
        Self {
            group_len: group_id.len(),
            buf,
        }
    }

    pub fn group_id(&self) -> &str {
        &self.buf[..self.group_len]
    }

    pub fn sender_id(&self) -> &str {
        &self.buf[self.group_len + 1..]
    }

    /// Returns the cached `"group_id:sender_id"` string without allocation.
    #[inline]
    pub fn cache_key(&self) -> &str {
        &self.buf
    }

    /// Construct from a group JID and a protocol address.
    /// Uses `ProtocolAddress::as_str()` to avoid allocating the sender string.
    pub fn from_jid(group_jid: &impl std::fmt::Display, sender: &ProtocolAddress) -> Self {
        let group_id = group_jid.to_string();
        let sender_id = sender.as_str();
        let group_len = group_id.len();
        let mut buf = group_id;
        buf.reserve(1 + sender_id.len());
        buf.push(':');
        buf.push_str(sender_id);
        Self { buf, group_len }
    }

    pub fn to_protocol_address(&self) -> ProtocolAddress {
        ProtocolAddress::new(
            format!("{}\n{}", self.group_id(), self.sender_id()),
            0.into(),
        )
    }
}
