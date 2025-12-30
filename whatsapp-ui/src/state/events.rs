//! UI events for communication between client and UI

use super::call::{CallId, IncomingCall};
use super::chat::ChatMessage;

// Re-export ReceiptType from wacore for DRY
pub use wacore::types::presence::ReceiptType;

/// Events from the WhatsApp client to the UI
#[derive(Debug)]
pub enum UiEvent {
    /// Initial loading complete, starting connection
    InitComplete,

    /// QR code received for pairing
    QrCode { code: String, timeout_secs: u64 },

    /// Pair code received
    PairCode { code: String, timeout_secs: u64 },

    /// Successfully connected
    Connected,

    /// Disconnected or logged out
    Disconnected(String),

    /// Message received (boxed to reduce enum size)
    MessageReceived {
        chat_jid: String,
        message: Box<ChatMessage>,
        /// Sender's push name from the notify attribute (if available)
        sender_name: Option<String>,
    },

    /// Receipt received (read/played status update)
    ReceiptReceived {
        /// The chat where the messages are
        chat_jid: String,
        /// Message IDs that were read/played
        message_ids: Vec<String>,
        /// Type of receipt (using wacore's ReceiptType)
        receipt_type: ReceiptType,
    },

    /// Reaction received on a message
    ReactionReceived {
        /// The chat where the message is
        chat_jid: String,
        /// The message ID that was reacted to
        message_id: String,
        /// The sender of the reaction
        sender: String,
        /// The emoji reaction (empty string means reaction removed)
        emoji: String,
    },

    /// Incoming call
    IncomingCall(IncomingCall),

    /// Outgoing call started (with actual call ID from CallManager)
    OutgoingCallStarted {
        /// The actual call ID from CallManager (using wacore's CallId type)
        call_id: CallId,
        /// The recipient JID
        recipient_jid: String,
    },

    /// Outgoing call failed to start
    OutgoingCallFailed {
        /// The recipient JID
        recipient_jid: String,
        /// Error message
        error: String,
    },

    /// Call accepted by remote (using wacore's CallId type)
    #[allow(dead_code)]
    CallAccepted(CallId),

    /// Call ended (using wacore's CallId type)
    CallEnded(CallId),

    /// Error occurred
    Error(String),
}
