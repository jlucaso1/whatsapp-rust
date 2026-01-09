//! UI events for communication between client and UI.

use super::call::{CallId, IncomingCall};
use super::chat::ChatMessage;

pub use wacore::types::presence::ReceiptType;

#[derive(Debug)]
pub enum UiEvent {
    InitComplete,
    QrCode {
        code: String,
        timeout_secs: u64,
    },
    PairCode {
        code: String,
        timeout_secs: u64,
    },
    PairSuccess,
    Connected,
    Disconnected(String),
    MessageReceived {
        chat_jid: String,
        message: Box<ChatMessage>,
        sender_name: Option<String>,
    },
    ReceiptReceived {
        chat_jid: String,
        message_ids: Vec<String>,
        receipt_type: ReceiptType,
    },
    ReactionReceived {
        chat_jid: String,
        message_id: String,
        sender: String,
        emoji: String,
    },
    IncomingCall(IncomingCall),
    OutgoingCallStarted {
        call_id: CallId,
        recipient_jid: String,
    },
    OutgoingCallFailed {
        recipient_jid: String,
        error: String,
    },
    #[allow(dead_code)]
    CallAccepted(CallId),
    CallEnded(CallId),
    Error(String),
}
