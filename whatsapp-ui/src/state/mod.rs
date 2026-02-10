//! Application state management
//!
//! This module contains all state-related structures:
//! - `AppState`: The overall application state machine
//! - `Chat` and `ChatMessage`: Chat data structures
//! - `IncomingCall`, `OutgoingCall`, `OutgoingCallState`: Call state
//! - `UiEvent`: Events for UI updates

mod app_state;
mod call;
mod chat;
mod events;

pub use app_state::{AppState, CachedQrCode};
pub use call::{CallId, IncomingCall, OutgoingCall, OutgoingCallState};
pub use chat::{Chat, ChatMessage, DownloadableMedia, MediaContent, MediaType};
pub use events::{ReceiptType, UiEvent};
