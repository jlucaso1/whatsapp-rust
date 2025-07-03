use prost::Message;

// Corresponds to WhisperTextProtocol.proto -> SignalMessage
#[derive(Clone, Message)]
pub struct SignalMessage {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub ratchet_key: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "2")]
    pub counter: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub previous_counter: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub ciphertext: Option<Vec<u8>>,
}

// Corresponds to WhisperTextProtocol.proto -> PreKeySignalMessage
#[derive(Clone, Message)]
pub struct PreKeySignalMessage {
    #[prost(uint32, optional, tag = "5")]
    pub registration_id: Option<u32>,
    #[prost(uint32, optional, tag = "1")]
    pub pre_key_id: Option<u32>,
    #[prost(uint32, optional, tag = "6")]
    pub signed_pre_key_id: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub base_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub identity_key: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub message: Option<Vec<u8>>, // This will contain a serialized SignalMessage
}
