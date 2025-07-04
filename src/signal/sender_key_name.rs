#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SenderKeyName {
    group_id: String,
    sender_id: String,
}

impl SenderKeyName {
    pub fn new(group_id: String, sender_id: String) -> Self {
        Self {
            group_id,
            sender_id,
        }
    }

    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    pub fn sender_id(&self) -> &str {
        &self.sender_id
    }
}
