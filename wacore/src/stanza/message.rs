//! Message stanza types with ProtocolNode derive macro.
//!
//! Provides type-safe message stanzas with JID-aware attributes.

use crate::ProtocolNode;
use wacore_binary::jid::Jid;

/// Typed 1-to-1 or generic message stanza with JID-safe attributes.
///
/// Wire format:
/// ```xml
/// <message from="jid" to="jid" id="..." t="..." type="..."/>
/// ```
#[derive(Debug, Clone, ProtocolNode)]
#[protocol(tag = "message")]
pub struct MessageStanza {
    /// Sender JID (required)
    #[attr(name = "from", jid)]
    pub from: Jid,

    /// Recipient JID (optional; not always present)
    #[attr(name = "to", jid, optional)]
    pub to: Option<Jid>,

    /// Message ID (required)
    #[attr(name = "id")]
    pub id: String,

    /// Timestamp (required, seconds since epoch)
    #[attr(name = "t")]
    pub timestamp: String,

    /// Message type (default: "text")
    #[attr(name = "type", default = "text")]
    pub msg_type: String,

    /// Optional sender LID (JID)
    #[attr(name = "sender_lid", jid, optional)]
    pub sender_lid: Option<Jid>,

    /// Optional participant JID (group sender)
    #[attr(name = "participant", jid, optional)]
    pub participant: Option<Jid>,

    /// Optional participant phone JID
    #[attr(name = "participant_pn", jid, optional)]
    pub participant_pn: Option<Jid>,

    /// Optional addressing mode (e.g., "lid")
    #[attr(name = "addressing_mode", optional)]
    pub addressing_mode: Option<String>,
}
