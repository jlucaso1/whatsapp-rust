//! Built-in sync actions.

mod archive;
mod delete_for_me;
mod mark_read;
mod mute;
mod pin;
mod star;

pub use archive::ArchiveChatAction;
pub use delete_for_me::DeleteMessageForMeAction;
pub use mark_read::MarkChatAsReadAction;
pub use mute::MuteChatAction;
pub use pin::PinChatAction;
pub use star::StarMessageAction;
