use crate::types::message::MessageInfo;
use std::sync::Arc;
use tokio::sync::broadcast;
pub use wacore::types::events::*;
use wacore_binary::{jid::Jid, node::Node};
use waproto::whatsapp::{self as wa, HistorySync};

// The size of the broadcast channel buffer.
const CHANNEL_CAPACITY: usize = 100;

// Macro to generate EventBus fields and constructor
macro_rules! define_event_bus {
    ($(($field:ident, $type:ty)),* $(,)?) => {
        /// Typed event bus that provides separate broadcast channels for each event type.
        /// This replaces the generic event handler system with type-safe, efficient channels.
        #[derive(Debug)]
        pub struct EventBus {
            $(
                pub $field: broadcast::Sender<$type>,
            )*
        }

        impl EventBus {
            pub fn new() -> Self {
                Self {
                    $(
                        $field: broadcast::channel(CHANNEL_CAPACITY).0,
                    )*
                }
            }
        }
    };
}

// Define the EventBus structure and implementation using the macro
define_event_bus! {
    // Connection events
    (connected, Arc<Connected>),
    (disconnected, Arc<Disconnected>),
    (pair_success, Arc<PairSuccess>),
    (pair_error, Arc<PairError>),
    (logged_out, Arc<LoggedOut>),
    (qr, Arc<Qr>),
    (qr_scanned_without_multidevice, Arc<QrScannedWithoutMultidevice>),
    (client_outdated, Arc<ClientOutdated>),

    // Message events
    (message, Arc<(Box<wa::Message>, MessageInfo)>),
    (receipt, Arc<Receipt>),
    (undecryptable_message, Arc<UndecryptableMessage>),
    (notification, Arc<Node>),

    // Presence events
    (chat_presence, Arc<ChatPresenceUpdate>),
    (presence, Arc<PresenceUpdate>),
    (picture_update, Arc<PictureUpdate>),
    (user_about_update, Arc<UserAboutUpdate>),

    // Group and contact events
    (joined_group, Arc<Box<wa::Conversation>>),
    (group_info_update, Arc<(Jid, Box<wa::SyncActionValue>)>),
    (contact_update, Arc<ContactUpdate>),

    // Chat state events
    (push_name_update, Arc<PushNameUpdate>),
    (self_push_name_updated, Arc<SelfPushNameUpdated>),
    (pin_update, Arc<PinUpdate>),
    (mute_update, Arc<MuteUpdate>),
    (archive_update, Arc<ArchiveUpdate>),
    (history_sync, Arc<HistorySync>),

    (offline_sync_preview, Arc<OfflineSyncPreview>),
    (offline_sync_completed, Arc<OfflineSyncCompleted>),

    // Error and stream events
    (stream_replaced, Arc<StreamReplaced>),
    (temporary_ban, Arc<TemporaryBan>),
    (connect_failure, Arc<ConnectFailure>),
    (stream_error, Arc<StreamError>),
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
