//! Sync action push system for WhatsApp app state mutations.
//!
//! This module provides functionality to push sync actions to WhatsApp servers.
//! Sync actions are used to synchronize app state across devices, including:
//!
//! - Delete message for me
//! - Star/unstar messages
//! - Archive/unarchive chats
//! - Mute/unmute chats
//! - Pin/unpin chats
//! - Mark chat as read/unread
//!
//! # Architecture
//!
//! The sync action system consists of:
//!
//! 1. **`SyncAction` trait** - Defines how to encode an action
//! 2. **Built-in actions** - Pre-defined actions for common operations
//! 3. **Pusher** - Handles encryption and network communication
//!
//! # Built-in Actions
//!
//! The following actions are provided out of the box:
//!
//! - [`DeleteMessageForMeAction`] - Delete a message locally
//! - [`StarMessageAction`] - Star or unstar a message
//! - [`ArchiveChatAction`] - Archive or unarchive a chat
//! - [`MuteChatAction`] - Mute or unmute a chat
//! - [`PinChatAction`] - Pin or unpin a chat
//! - [`MarkChatAsReadAction`] - Mark a chat as read or unread
//!
//! # Custom Actions
//!
//! You can implement the [`SyncAction`] trait to create custom actions:
//!
//! ```rust,ignore
//! use whatsapp_rust::sync_actions::{SyncAction, SyncCollection};
//! use waproto::whatsapp as wa;
//!
//! struct MyCustomAction {
//!     param: String,
//! }
//!
//! impl SyncAction for MyCustomAction {
//!     fn collection(&self) -> SyncCollection {
//!         SyncCollection::Regular
//!     }
//!
//!     fn build_index(&self) -> Vec<String> {
//!         vec!["myAction".to_string(), self.param.clone()]
//!     }
//!
//!     fn build_value(&self) -> wa::SyncActionValue {
//!         wa::SyncActionValue {
//!             timestamp: Some(chrono::Utc::now().timestamp_millis()),
//!             ..Default::default()
//!         }
//!     }
//! }
//! ```
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use whatsapp_rust::sync_actions::actions::*;
//!
//! // Delete a message for yourself
//! let delete = DeleteMessageForMeAction::for_dm_message(
//!     chat_jid.clone(),
//!     message_id.clone(),
//!     false, // not from_me
//! );
//! client.push_sync_action(delete).await?;
//!
//! // Star a message
//! let star = StarMessageAction::for_dm(
//!     chat_jid.clone(),
//!     message_id.clone(),
//!     true, // from_me
//!     true, // starred
//! );
//! client.push_sync_action(star).await?;
//!
//! // Archive a chat
//! let archive = ArchiveChatAction::archive(chat_jid.clone());
//! client.push_sync_action(archive).await?;
//!
//! // Mute a chat for 8 hours
//! let mute = MuteChatAction::mute_for(
//!     chat_jid.clone(),
//!     std::time::Duration::from_secs(8 * 60 * 60),
//! );
//! client.push_sync_action(mute).await?;
//! ```

pub mod actions;
mod pusher;
mod traits;
mod types;

pub use actions::*;
pub use traits::SyncAction;
pub use types::{SyncCollection, SyncError, SyncdOperation};
