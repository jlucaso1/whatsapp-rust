//! Handler for incoming `<chatstate>` stanzas (typing indicators).

use super::traits::StanzaHandler;
use crate::client::Client;
use async_trait::async_trait;
use log::debug;
use std::sync::Arc;
use wacore::iq::chatstate::{
    ChatstateParseError, ChatstateSource, ChatstateStanza, ReceivedChatState,
};
use wacore_binary::jid::Jid;
use wacore_binary::node::Node;

/// Event for incoming chatstate (`<chatstate/>`) stanzas.
///
/// Contains the chat JID, optional participant (for groups), and the parsed state.
/// State values align with WhatsApp Web's `WAChatState` constants.
#[derive(Debug, Clone)]
pub struct ChatStateEvent {
    /// The chat where the event occurred (user JID for 1:1, group JID for groups)
    pub chat: Jid,
    /// For group chats, the participant who triggered the event
    pub participant: Option<Jid>,
    /// The chat state (typing, recording_audio, or idle)
    pub state: ReceivedChatState,
}

impl ChatStateEvent {
    /// Create a `ChatStateEvent` from a parsed `ChatstateStanza`.
    pub fn from_stanza(stanza: ChatstateStanza) -> Self {
        let (chat, participant) = match stanza.source {
            ChatstateSource::User { from } => (from, None),
            ChatstateSource::Group { from, participant } => (from, Some(participant)),
        };
        Self {
            chat,
            participant,
            state: stanza.state,
        }
    }
}

/// Handler for `<chatstate>` stanzas.
///
/// Parses incoming chatstate stanzas using the `ProtocolNode` pattern
/// and dispatches events to registered handlers.
#[derive(Default)]
pub struct ChatstateHandler;

#[async_trait]
impl StanzaHandler for ChatstateHandler {
    fn tag(&self) -> &'static str {
        "chatstate"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        match ChatstateStanza::parse(&node) {
            Ok(stanza) => {
                debug!(
                    target: "ChatstateHandler",
                    "Received chatstate: {:?} from {:?}",
                    stanza.state,
                    stanza.source
                );
                client.dispatch_chatstate_event(stanza).await;
            }
            Err(ChatstateParseError::SelfEcho) => {
                debug!(
                    target: "ChatstateHandler",
                    "Ignoring self-echo chatstate"
                );
            }
            Err(e) => {
                log::warn!(
                    target: "ChatstateHandler",
                    "Failed to parse chatstate stanza: {e}"
                );
            }
        }
        true
    }
}
