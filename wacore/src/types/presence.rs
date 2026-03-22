use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Presence {
    Available,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatPresence {
    Composing,
    Paused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ChatPresenceMedia {
    #[serde(rename = "")]
    #[default]
    Text,
    #[serde(rename = "audio")]
    Audio,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String")]
pub enum ReceiptType {
    Delivered,
    Sender,
    Retry,
    /// VoIP call encryption re-keying retry.
    ///
    /// WA Web: `ENC_RETRY_RECEIPT_ATTRS.GROUP_CALL = "enc_rekey_retry"`.
    /// Sent when a peer fails to decrypt VoIP call encryption data and
    /// needs the sender to re-key.  Uses `<enc_rekey>` child (with
    /// `call-creator`, `call-id`, `count`) instead of `<retry>`.
    EncRekeyRetry,
    Read,
    ReadSelf,
    Played,
    PlayedSelf,
    ServerError,
    Inactive,
    PeerMsg,
    HistorySync,
    Other(String),
}

impl ReceiptType {
    pub fn parse(s: &str) -> Self {
        match s {
            "" | "delivery" => Self::Delivered,
            "sender" => Self::Sender,
            "retry" => Self::Retry,
            "enc_rekey_retry" => Self::EncRekeyRetry,
            "read" => Self::Read,
            "read-self" => Self::ReadSelf,
            "played" => Self::Played,
            "played-self" => Self::PlayedSelf,
            "server-error" => Self::ServerError,
            "inactive" => Self::Inactive,
            "peer_msg" => Self::PeerMsg,
            "hist_sync" => Self::HistorySync,
            other => Self::Other(other.to_string()),
        }
    }
}

impl From<String> for ReceiptType {
    fn from(s: String) -> Self {
        Self::parse(&s)
    }
}

#[cfg(test)]
mod tests {
    use super::ReceiptType;

    #[test]
    fn receipt_type_maps_delivery_string_to_delivered() {
        assert_eq!(ReceiptType::from("".to_string()), ReceiptType::Delivered);
        assert_eq!(
            ReceiptType::from("delivery".to_string()),
            ReceiptType::Delivered
        );
    }

    #[test]
    fn receipt_type_maps_retry_variants() {
        assert_eq!(ReceiptType::from("retry".to_string()), ReceiptType::Retry);
        assert_eq!(
            ReceiptType::from("enc_rekey_retry".to_string()),
            ReceiptType::EncRekeyRetry
        );
    }
}
