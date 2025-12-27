//! Message parsing logic for extracting MessageInfo from incoming nodes.
//!
//! This module handles parsing of WhatsApp message stanzas to extract
//! the sender, recipient, timestamps, and other metadata needed for
//! message processing and event dispatching.

use crate::client::Client;
use crate::types::message::MessageInfo;
use chrono::DateTime;
use wacore_binary::jid::JidExt;
use wacore_binary::node::Node;

impl Client {
    /// Parse a message node into a MessageInfo structure.
    ///
    /// This extracts all the relevant metadata from an incoming message stanza including:
    /// - Chat/conversation JID
    /// - Sender JID (with alternate JID for LID/PN mapping)
    /// - Whether the message is from the current user
    /// - Group/broadcast handling
    /// - Addressing mode (LID vs PN)
    /// - Timestamps and push name
    pub(crate) async fn parse_message_info(
        &self,
        node: &Node,
    ) -> Result<MessageInfo, anyhow::Error> {
        let mut attrs = node.attrs();
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let own_jid = device_snapshot.pn.clone().unwrap_or_default();
        let own_lid = device_snapshot.lid.clone();
        let from = attrs.jid("from");

        let mut source = if from.server == wacore_binary::jid::BROADCAST_SERVER {
            // This is the new logic block for handling all broadcast messages, including status.
            let participant = attrs.jid("participant");
            let is_from_me = participant.matches_user_or_lid(&own_jid, own_lid.as_ref());

            crate::types::message::MessageSource {
                chat: from.clone(),
                sender: participant.clone(),
                is_from_me,
                is_group: true, // Treat as group-like for session handling
                broadcast_list_owner: if from.user != wacore_binary::jid::STATUS_BROADCAST_USER {
                    Some(participant.clone())
                } else {
                    None
                },
                ..Default::default()
            }
        } else if from.is_group() {
            let sender = attrs.jid("participant");
            let sender_alt = if let Some(addressing_mode) = attrs
                .optional_string("addressing_mode")
                .map(|s| s.to_ascii_lowercase())
            {
                match addressing_mode.as_str() {
                    "lid" => attrs.optional_jid("participant_pn"),
                    _ => attrs.optional_jid("participant_lid"),
                }
            } else {
                None
            };

            let is_from_me = sender.matches_user_or_lid(&own_jid, own_lid.as_ref());

            crate::types::message::MessageSource {
                chat: from.clone(),
                sender: sender.clone(),
                is_from_me,
                is_group: true,
                sender_alt,
                ..Default::default()
            }
        } else if from.matches_user_or_lid(&own_jid, own_lid.as_ref()) {
            // DM from self (either via PN or LID)
            // Note: peer_recipient_pn contains the RECIPIENT's PN, not sender's.
            // For self-sent messages, we don't set sender_alt here - the decryption
            // logic will use our own PN via the is_from_me fallback path.
            // We store the original `recipient` attribute for retry receipts - this is needed
            // because device sync messages may have a different recipient than our device,
            // and the sender needs this to look up the original message.
            let recipient = attrs.optional_jid("recipient");
            // chat uses non-AD format for session routing, recipient keeps original for retry receipts
            let chat = recipient
                .as_ref()
                .map(|r| r.to_non_ad())
                .unwrap_or_else(|| from.to_non_ad());
            crate::types::message::MessageSource {
                chat,
                sender: from.clone(),
                is_from_me: true,
                recipient,
                // sender_alt stays None - decryption uses own PN for self-sent messages
                ..Default::default()
            }
        } else {
            // DM from someone else
            // Look for alternate JID attribute based on sender type:
            // - For LID senders: look for sender_pn to get their phone number
            // - For PN senders: look for sender_lid to get their LID
            // This is needed because sessions may be stored under either format
            // depending on how the session was originally established.
            let sender_alt = if from.server == wacore_binary::jid::HIDDEN_USER_SERVER {
                // Sender is LID, look for their phone number
                attrs.optional_jid("sender_pn")
            } else {
                // Sender is phone number, look for their LID
                attrs.optional_jid("sender_lid")
            };

            crate::types::message::MessageSource {
                chat: from.to_non_ad(),
                sender: from.clone(),
                is_from_me: false,
                sender_alt,
                ..Default::default()
            }
        };

        source.addressing_mode = attrs
            .optional_string("addressing_mode")
            .map(|s| s.to_ascii_lowercase())
            .and_then(|s| match s.as_str() {
                "pn" => Some(crate::types::message::AddressingMode::Pn),
                "lid" => Some(crate::types::message::AddressingMode::Lid),
                _ => None,
            });

        // Parse the category attribute - this is used for peer device messages ("peer")
        // and is critical for proper retry receipt handling.
        let category = attrs
            .optional_string("category")
            .map(|s| s.to_string())
            .unwrap_or_default();

        Ok(MessageInfo {
            source,
            id: attrs.string("id"),
            push_name: attrs
                .optional_string("notify")
                .map(|s| s.to_string())
                .unwrap_or_default(),
            timestamp: DateTime::from_timestamp(attrs.unix_time("t"), 0)
                .unwrap_or_else(chrono::Utc::now),
            category,
            ..Default::default()
        })
    }
}
