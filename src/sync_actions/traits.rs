//! Trait definition for sync actions.
//!
//! This module defines the `SyncAction` trait that allows users to create
//! custom sync actions without depending on this library to add new action types.

use super::types::{SyncCollection, SyncdOperation};
use waproto::whatsapp as wa;

/// Trait for defining sync actions that can be pushed to WhatsApp.
///
/// Users can implement this trait to create custom actions. The library
/// provides built-in implementations for common actions like:
/// - `DeleteMessageForMeAction`
/// - `StarMessageAction`
/// - `ArchiveChatAction`
/// - `MuteChatAction`
/// - `PinChatAction`
/// - `MarkChatAsReadAction`
///
/// # Example
///
/// ```rust,ignore
/// use whatsapp_rust::sync_actions::{SyncAction, SyncCollection, SyncdOperation};
/// use waproto::whatsapp as wa;
///
/// struct MyCustomAction {
///     param: String,
/// }
///
/// impl SyncAction for MyCustomAction {
///     fn collection(&self) -> SyncCollection {
///         SyncCollection::Regular
///     }
///
///     fn build_index(&self) -> Vec<String> {
///         vec!["myCustomAction".to_string(), self.param.clone()]
///     }
///
///     fn build_value(&self) -> wa::SyncActionValue {
///         wa::SyncActionValue {
///             timestamp: Some(chrono::Utc::now().timestamp_millis()),
///             ..Default::default()
///         }
///     }
/// }
/// ```
pub trait SyncAction: Send + Sync {
    /// The collection this action belongs to.
    fn collection(&self) -> SyncCollection;

    /// Build the index array for this action.
    ///
    /// The index identifies what entity this action applies to. For example:
    /// - `["deleteMessageForMe", chatJid, msgId, fromMe, participant]`
    /// - `["star", chatJid, msgId, fromMe, participant]`
    /// - `["archive", chatJid]`
    fn build_index(&self) -> Vec<String>;

    /// Build the SyncActionValue protobuf for this action.
    ///
    /// This should set the appropriate action field on the SyncActionValue.
    fn build_value(&self) -> wa::SyncActionValue;

    /// The operation type (SET to add/update, REMOVE to delete).
    ///
    /// Defaults to SET. Override this for actions that remove entries.
    fn operation(&self) -> SyncdOperation {
        SyncdOperation::Set
    }

    /// The version number for this action type.
    ///
    /// Different actions have different version numbers based on their schema.
    /// This must match what WhatsApp servers expect.
    fn version(&self) -> i32;
}
