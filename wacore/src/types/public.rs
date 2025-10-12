use reflect_macros::Reflect;
use serde::Serialize;

/// A lightweight snapshot representing the state of a WhatsApp account for FFI consumers.
#[derive(Debug, Clone, Serialize, Reflect)]
pub struct PublicDeviceStatus {
    pub jid: String,
    pub display_name: Option<String>,
    pub connected: bool,
    pub unread_chats: u32,
}

/// Simplified representation of core client events for consumption over FFI.
#[derive(Debug, Clone, Serialize, Reflect)]
pub struct PublicEvent {
    pub category: String,
    pub payload_json: String,
}
