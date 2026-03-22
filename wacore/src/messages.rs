use crate::libsignal::crypto::CryptographicHash;
use anyhow::{Result, anyhow};
use base64::Engine as _;
use prost::Message as ProtoMessage;
use waproto::whatsapp as wa;

pub struct MessageUtils;

impl MessageUtils {
    pub fn pad_message_v2(mut plaintext: Vec<u8>) -> Vec<u8> {
        use rand::RngExt;
        let mut rng = rand::make_rng::<rand::rngs::StdRng>();

        let mut pad_val = rng.random::<u8>() & 0x0F;
        if pad_val == 0 {
            pad_val = 0x0F;
        }

        let padding = vec![pad_val; pad_val as usize];
        plaintext.extend_from_slice(&padding);
        plaintext
    }

    pub fn participant_list_hash(devices: &[wacore_binary::jid::Jid]) -> Result<String> {
        let mut jids: Vec<String> = devices.iter().map(|j| j.to_ad_string()).collect();
        jids.sort();

        let concatenated_jids = jids.join("");

        // Use finalize_sha256_array() for zero-allocation hash finalization
        let full_hash = {
            let mut h = CryptographicHash::new("SHA-256")
                .map_err(|e| anyhow!("failed to initialize SHA-256 hasher: {:?}", e))?;
            h.update(concatenated_jids.as_bytes());
            h.finalize_sha256_array()
                .map_err(|e| anyhow!("failed to finalize hash: {:?}", e))?
        };

        let truncated_hash = &full_hash[..6];

        Ok(format!(
            "2:{hash}",
            hash = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(truncated_hash)
        ))
    }

    pub fn unpad_message_ref(plaintext: &[u8], version: u8) -> Result<&[u8]> {
        if version == 3 {
            return Ok(plaintext);
        }
        if plaintext.is_empty() {
            return Err(anyhow::anyhow!("plaintext is empty, cannot unpad"));
        }
        let pad_len = plaintext[plaintext.len() - 1] as usize;
        if pad_len == 0 || pad_len > plaintext.len() {
            return Err(anyhow::anyhow!("invalid padding length: {}", pad_len));
        }
        let (data, padding) = plaintext.split_at(plaintext.len() - pad_len);
        for &byte in padding {
            if byte != pad_len as u8 {
                return Err(anyhow::anyhow!("invalid padding bytes"));
            }
        }
        Ok(data)
    }
}

/// Decode padded ciphertext into a `wa::Message`.
///
/// Unpads the plaintext (using the given padding version) and decodes the
/// protobuf bytes into a WhatsApp Message. This is the pure,
/// runtime-independent portion of `handle_decrypted_plaintext`.
pub fn decode_plaintext(padded_plaintext: &[u8], padding_version: u8) -> Result<wa::Message> {
    let plaintext_slice = MessageUtils::unpad_message_ref(padded_plaintext, padding_version)?;
    wa::Message::decode(plaintext_slice)
        .map_err(|e| anyhow::anyhow!("Failed to decode decrypted plaintext: {e}"))
}

/// Unwrap a DeviceSentMessage wrapper, returning the inner message.
///
/// When a message is sent from our own device, the actual content is nested
/// inside `device_sent_message.message`.  This function extracts that inner
/// message (preserving `message_context_info`), or returns the original
/// message unchanged when there is no wrapper or the wrapper has no inner
/// message.
pub fn unwrap_device_sent(mut msg: wa::Message) -> wa::Message {
    if let Some(mut dsm) = msg.device_sent_message.take() {
        if let Some(mut inner) = dsm.message.take() {
            inner.message_context_info = crate::proto_helpers::merge_dsm_context(
                inner.message_context_info.take(),
                msg.message_context_info.as_ref(),
            );
            return *inner;
        }
        msg.device_sent_message = Some(dsm);
    }
    msg
}

/// Returns `true` if the message contains only a SenderKey distribution
/// (internal key-exchange for group encryption) and no user-visible content.
///
/// When sending a group message, WhatsApp includes the SKDM in a separate
/// `pkmsg` enc node.  We must process it (store the sender key) but should
/// not surface it as a user event.
pub fn is_sender_key_distribution_only(msg: &wa::Message) -> bool {
    if msg.sender_key_distribution_message.is_none()
        && msg
            .fast_ratchet_key_sender_key_distribution_message
            .is_none()
    {
        return false;
    }

    // Fast path: most common user-visible fields (avoids clone for the typical case).
    if msg.conversation.is_some()
        || msg.extended_text_message.is_some()
        || msg.image_message.is_some()
        || msg.video_message.is_some()
        || msg.audio_message.is_some()
        || msg.document_message.is_some()
        || msg.reaction_message.is_some()
        || msg.protocol_message.is_some()
    {
        return false;
    }

    // Slow path: clone and compare to default to catch all current and future fields.
    let mut stripped = msg.clone();
    stripped.sender_key_distribution_message = None;
    stripped.fast_ratchet_key_sender_key_distribution_message = None;
    stripped.message_context_info = None;
    stripped == wa::Message::default()
}

/// Parse a message stanza into a `MessageInfo` struct.
///
/// This is a pure function that extracts message metadata from a node's
/// attributes. It requires the own JID and optional LID to determine
/// `is_from_me`.
pub fn parse_message_info(
    node: &wacore_binary::node::Node,
    own_jid: &wacore_binary::jid::Jid,
    own_lid: Option<&wacore_binary::jid::Jid>,
) -> Result<crate::types::message::MessageInfo> {
    use crate::types::message::{AddressingMode, EditAttribute, MessageInfo, MessageSource};
    use wacore_binary::jid::{self, JidExt as _};

    let mut attrs = node.attrs();
    let from = attrs.jid("from");
    let addressing_mode = attrs
        .optional_string("addressing_mode")
        .and_then(|s| AddressingMode::try_from(s.as_ref()).ok());

    let mut source = if from.server == jid::BROADCAST_SERVER {
        let participant = attrs.jid("participant");
        let is_from_me = participant.matches_user_or_lid(own_jid, own_lid);

        MessageSource {
            chat: from.clone(),
            sender: participant.clone(),
            is_from_me,
            is_group: true,
            broadcast_list_owner: if from.user != jid::STATUS_BROADCAST_USER {
                Some(participant.clone())
            } else {
                None
            },
            ..Default::default()
        }
    } else if from.is_group() {
        let sender = attrs.jid("participant");
        let sender_alt = match addressing_mode {
            Some(AddressingMode::Lid) => attrs.optional_jid("participant_pn"),
            Some(AddressingMode::Pn) => attrs.optional_jid("participant_lid"),
            None => None,
        };

        let is_from_me = sender.matches_user_or_lid(own_jid, own_lid);

        MessageSource {
            chat: from.clone(),
            sender: sender.clone(),
            is_from_me,
            is_group: true,
            sender_alt,
            ..Default::default()
        }
    } else if from.matches_user_or_lid(own_jid, own_lid) {
        let recipient = attrs.optional_jid("recipient");
        let chat = recipient
            .as_ref()
            .map(|r| r.to_non_ad())
            .unwrap_or_else(|| from.to_non_ad());
        MessageSource {
            chat,
            sender: from.clone(),
            is_from_me: true,
            recipient,
            ..Default::default()
        }
    } else {
        let sender_alt = if from.server == jid::HIDDEN_USER_SERVER {
            attrs.optional_jid("sender_pn")
        } else {
            attrs.optional_jid("sender_lid")
        };

        MessageSource {
            chat: from.to_non_ad(),
            sender: from.clone(),
            is_from_me: false,
            sender_alt,
            ..Default::default()
        }
    };

    source.addressing_mode = addressing_mode;

    let category = attrs
        .optional_string("category")
        .map(|s| s.to_string())
        .unwrap_or_default();

    let id = attrs.required_string("id")?.to_string();
    let server_id = attrs
        .optional_u64("server_id")
        .filter(|&v| (99..=2_147_476_647).contains(&v))
        .unwrap_or(0) as i32;

    if source.chat.is_newsletter() {
        source.chat.device = 0;
        source.chat.agent = 0;
    }

    Ok(MessageInfo {
        source,
        id,
        server_id,
        push_name: attrs
            .optional_string("notify")
            .map(|s| s.to_string())
            .unwrap_or_default(),
        timestamp: chrono::DateTime::from_timestamp(attrs.unix_time("t"), 0)
            .unwrap_or_else(chrono::Utc::now),
        category,
        edit: attrs
            .optional_string("edit")
            .map(|s| EditAttribute::from(s.to_string()))
            .unwrap_or_default(),
        ..Default::default()
    })
}
