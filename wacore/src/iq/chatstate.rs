//! Chatstate protocol types following the ProtocolNode pattern.
//!
//! This module provides type-safe structures for parsing incoming `<chatstate>` stanzas
//! (typing indicators) following the patterns defined in `wacore/src/protocol.rs`.
//!
//! ## Wire Format
//!
//! Incoming chatstates (from other users) have a `from` attribute:
//! ```xml
//! <chatstate from="user@s.whatsapp.net">
//!   <composing/>
//! </chatstate>
//! ```
//!
//! Self-echo chatstates (our own typing echoed for multi-device sync) have a `to` attribute:
//! ```xml
//! <chatstate to="user@s.whatsapp.net">
//!   <composing/>
//! </chatstate>
//! ```

use crate::StringEnum;
use crate::iq::node::optional_jid;
use crate::protocol::ProtocolNode;
use anyhow::Result;
use thiserror::Error;
use wacore_binary::jid::Jid;
use wacore_binary::node::Node;

/// Error type for chatstate parsing failures.
#[derive(Debug, Error)]
pub enum ChatstateParseError {
    /// Stanza has wrong tag (not `<chatstate>`)
    #[error("expected <chatstate>, got <{0}>")]
    WrongTag(String),

    /// Self-echo chatstate (has `to` attribute instead of `from`).
    /// This is our own typing indicator echoed back for multi-device sync.
    #[error("self-echo chatstate (has 'to' but no 'from')")]
    SelfEcho,

    /// Missing required `from` attribute
    #[error("missing required attribute 'from'")]
    MissingFrom,

    /// Invalid JID in attribute
    #[error("invalid JID: {0}")]
    InvalidJid(#[from] anyhow::Error),
}

/// Chat state type as received from incoming stanzas.
///
/// Aligned with WhatsApp Web's `WAChatState` constants:
/// - `typing` = ACTIVE_CHAT_STATE_TYPE.TYPING
/// - `recording_audio` = ACTIVE_CHAT_STATE_TYPE.RECORDING_AUDIO
/// - `idle` = IDLE_CHAT_STATE_TYPE.IDLE
#[derive(Debug, Clone, Copy, PartialEq, Eq, StringEnum)]
pub enum ReceivedChatState {
    /// User is typing text
    #[str = "typing"]
    Typing,
    /// User is recording a voice message
    #[str = "recording_audio"]
    RecordingAudio,
    /// User stopped typing/recording
    #[str = "idle"]
    #[string_default]
    Idle,
}

impl ReceivedChatState {
    /// Parse chat state from a chatstate stanza's child node.
    ///
    /// Wire format (from WhatsApp Web's `WAHandleChatStateProtocol.parseChatStatus`):
    /// - `<composing/>` → Typing
    /// - `<composing media="audio"/>` → RecordingAudio
    /// - `<paused/>` → Idle
    pub fn from_child_node(child: &Node) -> Self {
        match child.tag.as_str() {
            "composing" => {
                // Check for media="audio" to distinguish recording from typing
                if child.attrs().optional_string("media") == Some("audio") {
                    Self::RecordingAudio
                } else {
                    Self::Typing
                }
            }
            "paused" => Self::Idle,
            _ => Self::Idle, // Default to idle for unknown states
        }
    }
}

/// Source of a chatstate event.
///
/// WhatsApp Web distinguishes between user (1:1) and group chatstates
/// via `WASmaxInChatstateFromUserMixin` and `WASmaxInChatstateFromGroupMixin`.
#[derive(Debug, Clone)]
pub enum ChatstateSource {
    /// From a 1:1 chat (user JID in `from`)
    User { from: Jid },
    /// From a group chat (group JID in `from`, sender in `participant`)
    Group { from: Jid, participant: Jid },
}

/// Parsed chatstate stanza.
///
/// Wire format:
/// ```xml
/// <!-- 1:1 chat -->
/// <chatstate from="user@s.whatsapp.net">
///   <composing/>
/// </chatstate>
///
/// <!-- Group chat -->
/// <chatstate from="group@g.us" participant="user@s.whatsapp.net">
///   <composing media="audio"/>
/// </chatstate>
/// ```
#[derive(Debug, Clone)]
pub struct ChatstateStanza {
    pub source: ChatstateSource,
    pub state: ReceivedChatState,
}

impl ChatstateStanza {
    /// Parse a chatstate stanza, returning a typed error.
    ///
    /// Use this method when you need to distinguish between different failure modes
    /// (e.g., to ignore self-echo chatstates without logging warnings).
    pub fn parse(node: &Node) -> Result<Self, ChatstateParseError> {
        if node.tag != "chatstate" {
            return Err(ChatstateParseError::WrongTag(node.tag.clone()));
        }

        let from = match optional_jid(node, "from")? {
            Some(jid) => jid,
            None => {
                if optional_jid(node, "to")?.is_some() {
                    return Err(ChatstateParseError::SelfEcho);
                }
                return Err(ChatstateParseError::MissingFrom);
            }
        };

        // Parse 'participant' attribute (optional, present in groups)
        let source = match optional_jid(node, "participant")? {
            Some(participant) => ChatstateSource::Group { from, participant },
            None => ChatstateSource::User { from },
        };

        // Parse state from first child node
        let state = node
            .children()
            .and_then(|children| children.first())
            .map(ReceivedChatState::from_child_node)
            .unwrap_or(ReceivedChatState::Idle);

        Ok(Self { source, state })
    }
}

impl ProtocolNode for ChatstateStanza {
    fn tag(&self) -> &'static str {
        "chatstate"
    }

    fn into_node(self) -> Node {
        // Chatstate stanzas are incoming-only; outgoing uses features/chatstate.rs
        unimplemented!("ChatstateStanza is incoming-only")
    }

    fn try_from_node(node: &Node) -> Result<Self> {
        Self::parse(node).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore_binary::builder::NodeBuilder;

    #[test]
    fn test_received_chat_state_string_enum() {
        assert_eq!(ReceivedChatState::Typing.as_str(), "typing");
        assert_eq!(
            ReceivedChatState::RecordingAudio.as_str(),
            "recording_audio"
        );
        assert_eq!(ReceivedChatState::Idle.as_str(), "idle");
        assert_eq!(ReceivedChatState::default(), ReceivedChatState::Idle);
    }

    #[test]
    fn test_parse_user_typing() {
        let node = NodeBuilder::new("chatstate")
            .attr("from", "1234567890@s.whatsapp.net")
            .children([NodeBuilder::new("composing").build()])
            .build();

        let stanza = ChatstateStanza::try_from_node(&node).unwrap();
        assert!(matches!(stanza.source, ChatstateSource::User { .. }));
        assert_eq!(stanza.state, ReceivedChatState::Typing);

        if let ChatstateSource::User { from } = stanza.source {
            assert_eq!(from.user, "1234567890");
        }
    }

    #[test]
    fn test_parse_user_recording() {
        let node = NodeBuilder::new("chatstate")
            .attr("from", "1234567890@s.whatsapp.net")
            .children([NodeBuilder::new("composing").attr("media", "audio").build()])
            .build();

        let stanza = ChatstateStanza::try_from_node(&node).unwrap();
        assert_eq!(stanza.state, ReceivedChatState::RecordingAudio);
    }

    #[test]
    fn test_parse_user_paused() {
        let node = NodeBuilder::new("chatstate")
            .attr("from", "1234567890@s.whatsapp.net")
            .children([NodeBuilder::new("paused").build()])
            .build();

        let stanza = ChatstateStanza::try_from_node(&node).unwrap();
        assert_eq!(stanza.state, ReceivedChatState::Idle);
    }

    #[test]
    fn test_parse_group_typing() {
        let node = NodeBuilder::new("chatstate")
            .attr("from", "123456789-1234567890@g.us")
            .attr("participant", "1234567890@s.whatsapp.net")
            .children([NodeBuilder::new("composing").build()])
            .build();

        let stanza = ChatstateStanza::try_from_node(&node).unwrap();
        assert!(matches!(stanza.source, ChatstateSource::Group { .. }));
        assert_eq!(stanza.state, ReceivedChatState::Typing);

        if let ChatstateSource::Group { from, participant } = stanza.source {
            assert_eq!(from.user, "123456789-1234567890");
            assert_eq!(participant.user, "1234567890");
        }
    }

    #[test]
    fn test_parse_group_recording() {
        let node = NodeBuilder::new("chatstate")
            .attr("from", "123456789-1234567890@g.us")
            .attr("participant", "5678@s.whatsapp.net")
            .children([NodeBuilder::new("composing").attr("media", "audio").build()])
            .build();

        let stanza = ChatstateStanza::try_from_node(&node).unwrap();
        assert!(matches!(stanza.source, ChatstateSource::Group { .. }));
        assert_eq!(stanza.state, ReceivedChatState::RecordingAudio);
    }

    #[test]
    fn test_parse_missing_from_error() {
        // Chatstate with neither 'from' nor 'to' should error with MissingFrom
        let node = NodeBuilder::new("chatstate")
            .children([NodeBuilder::new("composing").build()])
            .build();

        let result = ChatstateStanza::parse(&node);
        assert!(matches!(result, Err(ChatstateParseError::MissingFrom)));
    }

    #[test]
    fn test_parse_self_echo_chatstate() {
        // Self-echo chatstates have 'to' instead of 'from' (our own typing echoed for multi-device sync)
        let node = NodeBuilder::new("chatstate")
            .attr("to", "1234567890@s.whatsapp.net")
            .children([NodeBuilder::new("composing").build()])
            .build();

        let result = ChatstateStanza::parse(&node);
        assert!(matches!(result, Err(ChatstateParseError::SelfEcho)));
    }

    #[test]
    fn test_parse_wrong_tag_error() {
        let node = NodeBuilder::new("message")
            .attr("from", "1234567890@s.whatsapp.net")
            .build();

        let result = ChatstateStanza::parse(&node);
        assert!(matches!(result, Err(ChatstateParseError::WrongTag(_))));
    }

    #[test]
    fn test_parse_no_children_defaults_to_idle() {
        let node = NodeBuilder::new("chatstate")
            .attr("from", "1234567890@s.whatsapp.net")
            .build();

        let stanza = ChatstateStanza::try_from_node(&node).unwrap();
        assert_eq!(stanza.state, ReceivedChatState::Idle);
    }

    #[test]
    fn test_parse_unknown_child_defaults_to_idle() {
        let node = NodeBuilder::new("chatstate")
            .attr("from", "1234567890@s.whatsapp.net")
            .children([NodeBuilder::new("unknown_state").build()])
            .build();

        let stanza = ChatstateStanza::try_from_node(&node).unwrap();
        assert_eq!(stanza.state, ReceivedChatState::Idle);
    }

    #[test]
    fn test_parse_lid_jid_chatstate() {
        // LID JIDs (Linked IDs) should parse correctly when stored as strings
        let node = NodeBuilder::new("chatstate")
            .attr("from", "236395184570386@lid")
            .children([NodeBuilder::new("composing").build()])
            .build();

        let stanza = ChatstateStanza::parse(&node).unwrap();
        assert!(matches!(stanza.source, ChatstateSource::User { .. }));
        assert_eq!(stanza.state, ReceivedChatState::Typing);

        if let ChatstateSource::User { from } = stanza.source {
            assert_eq!(from.user, "236395184570386");
            assert_eq!(from.server, "lid");
        }
    }

    #[test]
    fn test_parse_jid_attribute_as_jid_type() {
        // In the binary protocol, JID attributes are stored as actual JID types,
        // not strings. This test simulates that behavior using jid_attr().
        use wacore_binary::jid::Jid;

        let jid: Jid = "236395184570386@lid".parse().unwrap();
        let node = NodeBuilder::new("chatstate")
            .jid_attr("from", jid)
            .children([NodeBuilder::new("composing").build()])
            .build();

        let stanza = ChatstateStanza::parse(&node).unwrap();
        assert!(matches!(stanza.source, ChatstateSource::User { .. }));
        assert_eq!(stanza.state, ReceivedChatState::Typing);

        if let ChatstateSource::User { from } = stanza.source {
            assert_eq!(from.user, "236395184570386");
            assert_eq!(from.server, "lid");
        }
    }

    #[test]
    fn test_parse_group_chatstate_with_jid_types() {
        // Test group chatstate with JID-typed attributes (as binary protocol stores them)
        use wacore_binary::jid::Jid;

        let group_jid: Jid = "123456789-1234567890@g.us".parse().unwrap();
        let participant_jid: Jid = "236395184570386@lid".parse().unwrap();

        let node = NodeBuilder::new("chatstate")
            .jid_attr("from", group_jid)
            .jid_attr("participant", participant_jid)
            .children([NodeBuilder::new("composing").build()])
            .build();

        let stanza = ChatstateStanza::parse(&node).unwrap();
        assert!(matches!(stanza.source, ChatstateSource::Group { .. }));
        assert_eq!(stanza.state, ReceivedChatState::Typing);

        if let ChatstateSource::Group { from, participant } = stanza.source {
            assert_eq!(from.server, "g.us");
            assert_eq!(participant.user, "236395184570386");
            assert_eq!(participant.server, "lid");
        }
    }
}
