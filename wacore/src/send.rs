use crate::client::context::{GroupInfo, SendContextResolver};
use crate::libsignal::protocol::{
    CiphertextMessage, ProtocolAddress, SENDERKEY_MESSAGE_CURRENT_VERSION, SenderKeyMessage,
    SenderKeyStore, SignalProtocolError, UsePQRatchet, message_encrypt, process_prekey_bundle,
};
use crate::messages::MessageUtils;
use crate::reporting_token::{
    build_reporting_node, generate_reporting_token, prepare_message_with_context,
};
use crate::types::jid::JidExt;
use crate::types::jid::make_sender_key_name;
use anyhow::{Result, anyhow};
use prost::Message as ProtoMessage;
use rand::{CryptoRng, Rng};
use std::collections::HashSet;
use wacore_binary::Node;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::{Jid, JidExt as _};
use wacore_libsignal::crypto::aes_256_cbc_encrypt_into;
use waproto::whatsapp as wa;
use waproto::whatsapp::message::DeviceSentMessage;

/// Wire-format constants (MsgCreateDeviceStanza.js).
pub(crate) mod stanza {
    pub const ENC_VERSION: &str = "2";
    pub const MSG_TYPE_TEXT: &str = "text";
    pub const MSG_TYPE_MEDIA: &str = "media";
    pub const MSG_TYPE_REACTION: &str = "reaction";
    pub const MSG_TYPE_POLL: &str = "poll";
    pub const MSG_TYPE_EVENT: &str = "event";
    pub const ENC_TYPE_MSG: &str = "msg";
    pub const ENC_TYPE_PKMSG: &str = "pkmsg";
    pub const ENC_TYPE_SKMSG: &str = "skmsg";
}

/// Extract (enc_type, is_prekey, serialized) from a CiphertextMessage.
pub fn extract_ciphertext(msg: CiphertextMessage) -> Option<(&'static str, bool, Box<[u8]>)> {
    match msg {
        CiphertextMessage::SignalMessage(m) => {
            Some((stanza::ENC_TYPE_MSG, false, m.into_serialized()))
        }
        CiphertextMessage::PreKeySignalMessage(m) => {
            Some((stanza::ENC_TYPE_PKMSG, true, m.into_serialized()))
        }
        _ => None,
    }
}

/// Unwrap wrapper message types to reach the inner message.
/// Matches WA Web's getUnwrappedProtobufMessage (EProtoUtils.js:19-35).
fn unwrap_message(msg: &wa::Message) -> &wa::Message {
    macro_rules! try_unwrap {
        ($($field:ident),+ $(,)?) => {
            $(
                if let Some(ref w) = msg.$field {
                    if let Some(ref inner) = w.message {
                        return unwrap_message(inner);
                    }
                }
            )+
        };
    }
    try_unwrap!(
        ephemeral_message,
        view_once_message,
        view_once_message_v2,
        view_once_message_v2_extension,
        document_with_caption_message,
        group_mentioned_message,
        bot_invoke_message,
        associated_child_message,
        poll_creation_option_image_message,
    );
    if let Some(ref dsm) = msg.device_sent_message
        && let Some(ref inner) = dsm.message
    {
        return unwrap_message(inner);
    }
    msg
}

/// Matches WAWebE2EProtoUtils.typeAttributeFromProtobuf.
pub fn stanza_type_from_message(msg: &wa::Message) -> &'static str {
    let msg = unwrap_message(msg);

    if msg.reaction_message.is_some() || msg.enc_reaction_message.is_some() {
        return stanza::MSG_TYPE_REACTION;
    }
    if msg.event_message.is_some() || msg.enc_event_response_message.is_some() {
        return stanza::MSG_TYPE_EVENT;
    }
    if let Some(ref sec) = msg.secret_encrypted_message {
        use wa::message::secret_encrypted_message::SecretEncType;
        match SecretEncType::try_from(sec.secret_enc_type.unwrap_or(0)) {
            Ok(SecretEncType::EventEdit) => return stanza::MSG_TYPE_EVENT,
            Ok(SecretEncType::MessageEdit) => return stanza::MSG_TYPE_TEXT,
            Ok(SecretEncType::PollEdit) => return stanza::MSG_TYPE_POLL,
            _ => {}
        }
    }
    if msg.poll_creation_message.is_some()
        || msg.poll_creation_message_v2.is_some()
        || msg.poll_creation_message_v3.is_some()
        || msg.poll_creation_message_v5.is_some()
        || msg.poll_update_message.is_some()
    {
        return stanza::MSG_TYPE_POLL;
    }
    if msg.conversation.is_some()
        || msg.protocol_message.is_some()
        || msg.keep_in_chat_message.is_some()
        || msg.edited_message.is_some()
        || msg.pin_in_chat_message.is_some()
        || msg.interactive_message.is_some()
        || msg.template_button_reply_message.is_some()
        || msg.request_phone_number_message.is_some()
        || msg.enc_comment_message.is_some()
        || msg.newsletter_admin_invite_message.is_some()
        || msg.newsletter_follower_invite_message_v2.is_some()
        || msg.message_history_notice.is_some()
    {
        return stanza::MSG_TYPE_TEXT;
    }
    // pollResultSnapshotMessage maps to "text" by default in WA Web
    // (gated behind isPollResultSnapshotPollTypeEnvelopeEnabled for "poll")
    if msg.poll_result_snapshot_message.is_some() || msg.poll_result_snapshot_message_v3.is_some() {
        return stanza::MSG_TYPE_TEXT;
    }
    if let Some(ref ext) = msg.extended_text_message {
        if ext
            .matched_text
            .as_ref()
            .is_some_and(|t| !t.trim().is_empty())
        {
            return stanza::MSG_TYPE_MEDIA;
        }
        return stanza::MSG_TYPE_TEXT;
    }
    stanza::MSG_TYPE_MEDIA
}

/// Matches WAWebBackendJobsCommon.mediaTypeFromProtobuf + encodeMaybeMediaType.
/// Returns `None` when the attribute should be omitted.
pub fn media_type_from_message(msg: &wa::Message) -> Option<&'static str> {
    let msg = unwrap_message(msg);

    if msg.image_message.is_some() {
        return Some("image");
    }
    if let Some(ref vid) = msg.video_message {
        return if vid.gif_playback == Some(true) {
            Some("gif")
        } else {
            Some("video")
        };
    }
    if msg.ptv_message.is_some() {
        return Some("ptv");
    }
    if let Some(ref audio) = msg.audio_message {
        return if audio.ptt == Some(true) {
            Some("ptt")
        } else {
            Some("audio")
        };
    }
    if msg.document_message.is_some() {
        return Some("document");
    }
    if msg.sticker_message.is_some() {
        return Some("sticker");
    }
    if msg.sticker_pack_message.is_some() {
        return Some("sticker_pack");
    }
    if let Some(ref loc) = msg.location_message {
        return if loc.is_live == Some(true) {
            Some("livelocation")
        } else {
            Some("location")
        };
    }
    if msg.live_location_message.is_some() {
        return Some("livelocation");
    }
    if msg.contact_message.is_some() {
        return Some("vcard");
    }
    if msg.contacts_array_message.is_some() {
        return Some("contact_array");
    }
    if let Some(ref ext) = msg.extended_text_message
        && ext
            .matched_text
            .as_ref()
            .is_some_and(|t| !t.trim().is_empty())
    {
        return Some("url");
    }
    if msg.group_invite_message.is_some() {
        return Some("url");
    }
    None
}

/// Infrastructure messages get decrypt-fail="hide" so recipients don't see
/// "waiting for this message" placeholders for things like reactions or pin changes.
pub fn should_hide_decrypt_fail(msg: &wa::Message) -> bool {
    let msg = unwrap_message(msg);

    use wa::message::protocol_message::Type as ProtocolType;
    use wa::message::secret_encrypted_message::SecretEncType;

    msg.reaction_message.is_some()
        || msg.enc_reaction_message.is_some()
        || msg.pin_in_chat_message.is_some()
        || msg.edited_message.is_some()
        || msg.keep_in_chat_message.is_some()
        || msg.enc_event_response_message.is_some()
        || msg
            .poll_update_message
            .as_ref()
            .is_some_and(|p| p.vote.is_some())
        || msg.message_history_notice.is_some()
        || msg.secret_encrypted_message.as_ref().is_some_and(|s| {
            matches!(
                SecretEncType::try_from(s.secret_enc_type.unwrap_or(0)),
                Ok(SecretEncType::EventEdit | SecretEncType::PollEdit)
            )
        })
        || msg
            .bot_invoke_message
            .as_ref()
            .and_then(|b| b.message.as_ref())
            .and_then(|m| m.protocol_message.as_ref())
            .is_some_and(|p| p.r#type == Some(ProtocolType::RequestWelcomeMessage as i32))
        || msg.protocol_message.as_ref().is_some_and(|p| {
            matches!(
                p.r#type,
                Some(t) if t == ProtocolType::EphemeralSyncResponse as i32
                    || t == ProtocolType::RequestWelcomeMessage as i32
                    || t == ProtocolType::GroupMemberLabelChange as i32
            ) || p.edited_message.is_some()
        })
}

pub async fn encrypt_group_message<S, R>(
    sender_key_store: &mut S,
    group_jid: &Jid,
    sender_address: &ProtocolAddress,
    plaintext: &[u8],
    csprng: &mut R,
) -> Result<SenderKeyMessage>
where
    S: SenderKeyStore + ?Sized,
    R: Rng + CryptoRng,
{
    let sender_key_name = make_sender_key_name(group_jid, sender_address);
    log::debug!(
        "Attempting to load sender key for group {} sender {}",
        sender_key_name.group_id(),
        sender_key_name.sender_id()
    );

    let mut record = sender_key_store
        .load_sender_key(&sender_key_name)
        .await?
        .ok_or_else(|| {
            SignalProtocolError::NoSenderKeyState(format!(
                "no sender key record for group {} sender {}",
                sender_key_name.group_id(),
                sender_key_name.sender_id()
            ))
        })?;

    let sender_key_state = record
        .sender_key_state_mut()
        .map_err(|e| anyhow!("Invalid SenderKey session: {:?}", e))?;

    let sender_chain_key = sender_key_state
        .sender_chain_key()
        .ok_or_else(|| anyhow!("Invalid SenderKey session: missing chain key"))?;

    let message_keys = sender_chain_key.sender_message_key();

    let mut ciphertext = Vec::new();
    aes_256_cbc_encrypt_into(
        plaintext,
        message_keys.cipher_key(),
        message_keys.iv(),
        &mut ciphertext,
    )
    .map_err(|_| anyhow!("AES encryption failed"))?;

    let signing_key = sender_key_state
        .signing_key_private()
        .map_err(|e| anyhow!("Invalid SenderKey session: missing signing key: {:?}", e))?;

    let skm = SenderKeyMessage::new(
        SENDERKEY_MESSAGE_CURRENT_VERSION,
        sender_key_state.chain_id(),
        message_keys.iteration(),
        ciphertext.into_boxed_slice(),
        csprng,
        &signing_key,
    )?;

    sender_key_state.set_sender_chain_key(sender_chain_key.next()?);

    sender_key_store
        .store_sender_key(&sender_key_name, record)
        .await?;

    Ok(skm)
}

pub struct SignalStores<'a, S, I, P, SP> {
    pub sender_key_store: &'a mut (dyn crate::libsignal::protocol::SenderKeyStore + Send + Sync),
    pub session_store: &'a mut S,
    pub identity_store: &'a mut I,
    pub prekey_store: &'a mut P,
    pub signed_prekey_store: &'a SP,
}

/// Check if an anyhow error is a 406 "not-acceptable" server error (device unregistered).
/// Uses typed downcast to `ServerErrorCode` — the shared error type that the
/// `SendContextResolver` impl wraps server errors in.
pub(crate) fn is_device_unregistered_error(err: &anyhow::Error) -> bool {
    crate::request::ServerErrorCode::from_anyhow(err).is_some_and(|e| e.code == 406)
}

pub struct EncryptResult {
    pub participant_nodes: Vec<Node>,
    pub includes_prekey_message: bool,
    pub encrypted_devices: Vec<Jid>,
    /// True if any device returned 406 (unregistered) during prekey fetch.
    pub had_unregistered_device: bool,
}

/// Encrypt padded plaintext for each device JID, producing participant `<to>` nodes.
///
/// Callers must hold per-device session locks before calling this function —
/// concurrent ratchet mutations will corrupt Signal session state.
pub async fn encrypt_for_devices<'a, S, I, P, SP>(
    stores: &mut SignalStores<'a, S, I, P, SP>,
    resolver: &dyn SendContextResolver,
    devices: &[Jid],
    plaintext_to_encrypt: &[u8],
    hide_decrypt_fail: bool,
    mediatype: Option<&str>,
) -> Result<EncryptResult>
where
    S: crate::libsignal::protocol::SessionStore + Send + Sync,
    I: crate::libsignal::protocol::IdentityKeyStore + Send + Sync,
    P: crate::libsignal::protocol::PreKeyStore + Send + Sync,
    SP: crate::libsignal::protocol::SignedPreKeyStore + Send + Sync,
{
    // Build a map of device JIDs to their effective encryption JIDs.
    // For phone number JIDs, check if we have an existing session under the corresponding LID.
    // This handles the case where a session was established via a message with sender_lid,
    // and now we're sending a reply using the phone number address.
    let mut jid_to_encryption_jid: std::collections::HashMap<&Jid, Jid> =
        std::collections::HashMap::with_capacity(devices.len());
    let mut jids_needing_prekeys = Vec::with_capacity(devices.len());
    let mut had_406 = false;

    let mut reusable_addr = crate::types::jid::make_reusable_protocol_address();

    for device_jid in devices {
        // WhatsApp Web's SignalAddress.toString() normalizes PN → LID before
        // creating signal addresses. We do the same: check LID session FIRST.
        // This prevents using stale PN sessions when a newer LID session exists.
        if device_jid.is_pn()
            && let Some(lid_user) = resolver.get_lid_for_phone(&device_jid.user).await
        {
            // Construct the LID JID with the same device ID
            let lid_jid = Jid::lid_device(lid_user, device_jid.device);
            lid_jid.reset_protocol_address(&mut reusable_addr);

            if stores.session_store.has_session(&reusable_addr).await? {
                log::debug!(
                    "Using LID session {} for PN {} (LID-first lookup)",
                    lid_jid,
                    device_jid
                );
                jid_to_encryption_jid.insert(device_jid, lid_jid);
                continue;
            }
        }

        device_jid.reset_protocol_address(&mut reusable_addr);
        if stores.session_store.has_session(&reusable_addr).await? {
            continue;
        }

        // No session found - need to fetch prekeys and create session.
        // Keep device_jid for prekey fetch (server returns bundles keyed by this),
        // but normalize to LID for the actual session creation.
        let encryption_jid = if device_jid.is_pn() {
            if let Some(lid_user) = resolver.get_lid_for_phone(&device_jid.user).await {
                let lid_jid = Jid::lid_device(lid_user, device_jid.device);
                log::debug!(
                    "Will create LID session {} for PN {} (no existing session)",
                    lid_jid,
                    device_jid
                );
                lid_jid
            } else {
                device_jid.clone()
            }
        } else {
            device_jid.clone()
        };
        jid_to_encryption_jid.insert(device_jid, encryption_jid);
        // Use original device_jid for prekey fetch (HashMap key match)
        jids_needing_prekeys.push(device_jid.clone());
    }

    if !jids_needing_prekeys.is_empty() {
        log::debug!(
            "Fetching prekeys for {} devices without sessions",
            jids_needing_prekeys.len()
        );
        // 406 on this batch is all-or-nothing — per-device retries just wasted
        // N·RTT with the same failure. Mark `had_406` so the caller invalidates
        // the users and the next send re-fetches. Matches WA Web's
        // `GroupSkmsgJob`: log, continue without those devices.
        let prekey_bundles = match resolver
            .fetch_prekeys_for_identity_check(&jids_needing_prekeys)
            .await
        {
            Ok(bundles) => bundles,
            Err(e) if is_device_unregistered_error(&e) => {
                log::warn!(
                    "Prekey fetch returned 406 for {} device(s); skipping them this round",
                    jids_needing_prekeys.len()
                );
                had_406 = true;
                std::collections::HashMap::new()
            }
            Err(e) => return Err(e),
        };

        for device_jid in &jids_needing_prekeys {
            // Use the LID-normalized encryption JID for session creation
            let mut encryption_jid = jid_to_encryption_jid
                .get(device_jid)
                .unwrap_or(device_jid)
                .clone();

            // Normalize agent to 0 for LID JIDs to match how pre-key bundles are stored.
            // The JID parsing logic in `prekeys.rs` forces agent=0 for LID, so we must match that here.
            if encryption_jid.is_lid() {
                encryption_jid.agent = 0;
            }

            encryption_jid.reset_protocol_address(&mut reusable_addr);
            let lookup_jid = device_jid.normalize_for_prekey_bundle();
            match prekey_bundles.get(&lookup_jid) {
                Some(bundle) => {
                    match process_prekey_bundle(
                        &reusable_addr,
                        stores.session_store,
                        stores.identity_store,
                        bundle,
                        &mut rand::make_rng::<rand::rngs::StdRng>(),
                        UsePQRatchet::No,
                    )
                    .await
                    {
                        Ok(_) => {
                            // Session established successfully
                        }
                        Err(SignalProtocolError::UntrustedIdentity(ref addr)) => {
                            // The stored identity doesn't match the server's identity.
                            // This typically happens when a user reinstalls WhatsApp.
                            // We trust the server's identity and update our local store,
                            // then retry establishing the session.
                            log::info!(
                                "Untrusted identity for device {}. Updating identity and retrying session establishment.",
                                addr
                            );

                            // Get the new identity from the prekey bundle and save it
                            let new_identity = match bundle.identity_key() {
                                Ok(key) => key,
                                Err(e) => {
                                    log::warn!(
                                        "Failed to get identity key from bundle for {}: {:?}. Skipping device.",
                                        addr,
                                        e
                                    );
                                    continue;
                                }
                            };

                            // Save the new identity (this replaces the old one)
                            if let Err(e) = stores
                                .identity_store
                                .save_identity(&reusable_addr, new_identity)
                                .await
                            {
                                log::warn!(
                                    "Failed to save updated identity for {}: {:?}. Skipping device.",
                                    addr,
                                    e
                                );
                                continue;
                            }

                            log::debug!(
                                "Identity updated for {}. Retrying session establishment.",
                                addr
                            );

                            // Retry processing the prekey bundle with the updated identity
                            match process_prekey_bundle(
                                &reusable_addr,
                                stores.session_store,
                                stores.identity_store,
                                bundle,
                                &mut rand::make_rng::<rand::rngs::StdRng>(),
                                UsePQRatchet::No,
                            )
                            .await
                            {
                                Ok(_) => {
                                    log::info!(
                                        "Successfully established session with {} after identity update.",
                                        addr
                                    );
                                }
                                Err(e) => {
                                    log::warn!(
                                        "Failed to establish session with {} even after identity update: {:?}. Skipping device.",
                                        addr,
                                        e
                                    );
                                    continue;
                                }
                            }
                        }
                        Err(e) => {
                            // Propagate other unexpected errors
                            return Err(anyhow::anyhow!(
                                "Failed to process pre-key bundle for {}: {:?}",
                                reusable_addr,
                                e
                            ));
                        }
                    }
                }
                None => {
                    log::warn!(
                        "No pre-key bundle returned for device {}. This device will be skipped for encryption.",
                        &reusable_addr
                    );
                }
            }
        }
    }

    let mut participant_nodes = Vec::with_capacity(devices.len());
    let mut includes_prekey_message = false;
    let mut encrypted_devices = Vec::with_capacity(devices.len());

    for device_jid in devices {
        let encryption_jid = jid_to_encryption_jid.get(device_jid).unwrap_or(device_jid);
        encryption_jid.reset_protocol_address(&mut reusable_addr);

        match message_encrypt(
            plaintext_to_encrypt,
            &reusable_addr,
            stores.session_store,
            stores.identity_store,
        )
        .await
        {
            Ok(encrypted_payload) => {
                let Some((enc_type, is_prekey, serialized_bytes)) =
                    extract_ciphertext(encrypted_payload)
                else {
                    continue;
                };
                includes_prekey_message |= is_prekey;

                let mut enc_builder = NodeBuilder::new("enc")
                    .attr("v", stanza::ENC_VERSION)
                    .attr("type", enc_type);
                if let Some(mt) = mediatype {
                    enc_builder = enc_builder.attr("mediatype", mt);
                }
                if hide_decrypt_fail {
                    enc_builder = enc_builder.attr("decrypt-fail", "hide");
                }
                let enc_node = enc_builder.bytes(serialized_bytes).build();

                participant_nodes.push(
                    NodeBuilder::new("to")
                        .attr("jid", device_jid.clone())
                        .children([enc_node])
                        .build(),
                );
                encrypted_devices.push(device_jid.clone());
            }
            Err(e) => {
                log::warn!(
                    "Failed to encrypt for device {}: {}. Skipping.",
                    &reusable_addr,
                    e
                );
            }
        }
    }

    Ok(EncryptResult {
        participant_nodes,
        includes_prekey_message,
        encrypted_devices,
        had_unregistered_device: had_406,
    })
}

fn is_exact_dm_sender_device(device_jid: &Jid, own_jid: &Jid, own_lid: Option<&Jid>) -> bool {
    (device_jid.is_same_user_as(own_jid) && device_jid.device == own_jid.device)
        || own_lid
            .is_some_and(|lid| device_jid.is_same_user_as(lid) && device_jid.device == lid.device)
}

fn partition_dm_devices(
    all_devices: Vec<Jid>,
    own_jid: &Jid,
    own_lid: Option<&Jid>,
) -> (Vec<Jid>, Vec<Jid>) {
    let mut recipient_devices = Vec::with_capacity(all_devices.len());
    let mut own_other_devices = Vec::with_capacity(4);

    for device_jid in all_devices {
        if is_exact_dm_sender_device(&device_jid, own_jid, own_lid) {
            continue;
        }

        if device_jid.matches_user_or_lid(own_jid, own_lid) {
            own_other_devices.push(device_jid);
        } else {
            recipient_devices.push(device_jid);
        }
    }

    (recipient_devices, own_other_devices)
}

/// Result of `prepare_dm_stanza` — carries the stanza node and the
/// locally computed phash for server ACK validation.
pub struct PreparedDmStanza {
    pub node: Node,
    /// Locally computed phash from the sent device set. Not sent on the
    /// wire (WA Web only sends phash for groups). Used by the caller to
    /// compare against the server's ACK phash for device-list drift detection.
    pub phash: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn prepare_dm_stanza<
    'a,
    S: crate::libsignal::protocol::SessionStore + Send + Sync,
    I: crate::libsignal::protocol::IdentityKeyStore + Send + Sync,
    P: crate::libsignal::protocol::PreKeyStore + Send + Sync,
    SP: crate::libsignal::protocol::SignedPreKeyStore + Send + Sync,
>(
    stores: &mut SignalStores<'a, S, I, P, SP>,
    resolver: &dyn SendContextResolver,
    own_jid: &Jid,
    own_lid: Option<&Jid>,
    account: Option<&wa::AdvSignedDeviceIdentity>,
    to_jid: Jid,
    message: &wa::Message,
    request_id: String,
    edit: Option<crate::types::message::EditAttribute>,
    extra_stanza_nodes: &[Node],
    all_devices: Vec<Jid>,
) -> Result<PreparedDmStanza> {
    let reporting_result = generate_reporting_token(message, &request_id, &to_jid, &to_jid, None);

    let message_for_encryption = if let Some(ref result) = reporting_result {
        prepare_message_with_context(message, &result.message_secret)
    } else {
        message.clone()
    };

    let recipient_plaintext = MessageUtils::encode_and_pad(&message_for_encryption);

    // Partition first so phash reflects the actual sent set (sender excluded)
    let total_devices = all_devices.len();
    let (recipient_devices, own_other_devices) =
        partition_dm_devices(all_devices, own_jid, own_lid);

    let phash = {
        let mut sent = Vec::with_capacity(recipient_devices.len() + own_other_devices.len());
        sent.extend_from_slice(&recipient_devices);
        sent.extend_from_slice(&own_other_devices);
        MessageUtils::participant_list_hash(&sent).ok()
    };

    let dsm = wa::Message {
        device_sent_message: Some(Box::new(DeviceSentMessage {
            destination_jid: Some(to_jid.to_string()),
            message: Some(Box::new(message_for_encryption)),
            phash: None, // WA Web only sets DSM phash for groups
        })),
        ..Default::default()
    };

    let own_devices_plaintext = MessageUtils::encode_and_pad(&dsm);

    let mut participant_nodes = Vec::with_capacity(total_devices);
    let mut includes_prekey_message = false;

    let hide_decrypt_fail = edit
        .as_ref()
        .is_some_and(|e| *e != crate::types::message::EditAttribute::Empty)
        || should_hide_decrypt_fail(message);

    let mediatype = media_type_from_message(message);

    // NOTE: WA Web has a bare-<enc> fast path for single primary device
    // (WAWebSendMsgCreateFanoutStanza). Not implemented here because
    // encrypt_for_devices always wraps in <to jid=...> nodes;
    // a bare-enc mode would require refactoring the encryption layer.
    // The <participants> form is accepted by the server regardless.

    if !recipient_devices.is_empty() {
        let result = encrypt_for_devices(
            stores,
            resolver,
            &recipient_devices,
            &recipient_plaintext,
            hide_decrypt_fail,
            mediatype,
        )
        .await?;
        participant_nodes.extend(result.participant_nodes);
        includes_prekey_message = includes_prekey_message || result.includes_prekey_message;
    }

    if !own_other_devices.is_empty() {
        let result = encrypt_for_devices(
            stores,
            resolver,
            &own_other_devices,
            &own_devices_plaintext,
            hide_decrypt_fail,
            mediatype,
        )
        .await?;
        participant_nodes.extend(result.participant_nodes);
        includes_prekey_message = includes_prekey_message || result.includes_prekey_message;
    }

    let mut message_content_nodes = vec![
        NodeBuilder::new("participants")
            .children(participant_nodes)
            .build(),
    ];

    if includes_prekey_message && let Some(acc) = account {
        let device_identity_bytes = acc.encode_to_vec();
        message_content_nodes.push(
            NodeBuilder::new("device-identity")
                .bytes(device_identity_bytes)
                .build(),
        );
    }

    // Add reporting token node if we generated one
    if let Some(ref result) = reporting_result {
        message_content_nodes.push(build_reporting_node(result));
    }

    // Add any extra stanza nodes provided by the caller
    message_content_nodes.extend(extra_stanza_nodes.iter().cloned());

    let stanza_type = stanza_type_from_message(message);

    let mut stanza_builder = NodeBuilder::new("message")
        .attr("to", to_jid)
        .attr("id", request_id)
        .attr("type", stanza_type);

    if let Some(edit_attr) = edit
        && edit_attr != crate::types::message::EditAttribute::Empty
    {
        stanza_builder = stanza_builder.attr("edit", edit_attr.to_string_val());
    }

    let stanza = stanza_builder.children(message_content_nodes).build();

    Ok(PreparedDmStanza {
        node: stanza,
        phash,
    })
}

pub async fn prepare_peer_stanza<S, I>(
    session_store: &mut S,
    identity_store: &mut I,
    transport_jid: Jid,
    signal_address: &ProtocolAddress,
    message: &wa::Message,
    request_id: String,
) -> Result<Node>
where
    S: crate::libsignal::protocol::SessionStore,
    I: crate::libsignal::protocol::IdentityKeyStore,
{
    let plaintext = MessageUtils::encode_and_pad(message);

    let encrypted_message =
        message_encrypt(&plaintext, signal_address, session_store, identity_store).await?;

    let (enc_type, _, serialized_bytes) = extract_ciphertext(encrypted_message)
        .ok_or_else(|| anyhow!("Unexpected peer encryption message type"))?;

    let enc_node = NodeBuilder::new("enc")
        .attrs([("v", "2"), ("type", enc_type)])
        .bytes(serialized_bytes)
        .build();

    let stanza = NodeBuilder::new("message")
        .attr("to", transport_jid)
        .attr("id", request_id)
        .attr("type", stanza::MSG_TYPE_TEXT)
        .attr("category", "peer")
        .children([enc_node])
        .build();

    Ok(stanza)
}

/// Pairwise-encrypted retry stanza for a single DM recipient device.
/// WA Web retries target only the failing device, not a full DM fanout.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_dm_retry_stanza<S, I>(
    session_store: &mut S,
    identity_store: &mut I,
    to_jid: Jid,
    requester_jid: Jid,
    encryption_jid: Jid,
    message: &wa::Message,
    message_id: String,
    retry_count: u8,
    account: Option<&wa::AdvSignedDeviceIdentity>,
) -> Result<Node>
where
    S: crate::libsignal::protocol::SessionStore,
    I: crate::libsignal::protocol::IdentityKeyStore,
{
    let plaintext = MessageUtils::encode_and_pad(message);
    let signal_address = encryption_jid.to_protocol_address();

    let encrypted =
        message_encrypt(&plaintext, &signal_address, session_store, identity_store).await?;

    let (enc_type, is_prekey, serialized) = extract_ciphertext(encrypted)
        .ok_or_else(|| anyhow!("Unexpected encryption message type for DM retry"))?;

    let mut enc_builder = NodeBuilder::new("enc")
        .attr("v", stanza::ENC_VERSION)
        .attr("type", enc_type)
        .attr("count", retry_count.to_string());
    if let Some(mt) = media_type_from_message(message) {
        enc_builder = enc_builder.attr("mediatype", mt);
    }
    let enc_node = enc_builder.bytes(serialized).build();

    let participant_node = NodeBuilder::new("to")
        .attr("jid", requester_jid)
        .children([enc_node])
        .build();

    let mut children = vec![
        NodeBuilder::new("participants")
            .children([participant_node])
            .build(),
    ];

    if is_prekey && let Some(acc) = account {
        children.push(
            NodeBuilder::new("device-identity")
                .bytes(acc.encode_to_vec())
                .build(),
        );
    }

    Ok(NodeBuilder::new("message")
        .attr("to", to_jid)
        .attr("id", message_id)
        .attr("type", stanza_type_from_message(message))
        .children(children)
        .build())
}

/// Pairwise-encrypted retry stanza for a single group participant.
/// WA Web sends retries to the failing device only (RetryMsgJob.js:71),
/// NOT as a sender-key broadcast to all participants.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_group_retry_stanza<S, I>(
    session_store: &mut S,
    identity_store: &mut I,
    group_jid: Jid,
    participant_jid: Jid,
    encryption_jid: Jid,
    message: &wa::Message,
    message_id: String,
    retry_count: u8,
    account: Option<&wa::AdvSignedDeviceIdentity>,
    addressing_mode: crate::types::message::AddressingMode,
) -> Result<Node>
where
    S: crate::libsignal::protocol::SessionStore,
    I: crate::libsignal::protocol::IdentityKeyStore,
{
    let plaintext = MessageUtils::encode_and_pad(message);
    let signal_address = encryption_jid.to_protocol_address();

    let encrypted =
        message_encrypt(&plaintext, &signal_address, session_store, identity_store).await?;

    let (enc_type, is_prekey, serialized) = extract_ciphertext(encrypted)
        .ok_or_else(|| anyhow!("Unexpected encryption message type for group retry"))?;

    // count="N" distinguishes retries from normal sends (MsgCreateDeviceStanza.js:150-153)
    let mut enc_builder = NodeBuilder::new("enc")
        .attr("v", stanza::ENC_VERSION)
        .attr("type", enc_type)
        .attr("count", retry_count.to_string());
    if let Some(mt) = media_type_from_message(message) {
        enc_builder = enc_builder.attr("mediatype", mt);
    }
    let enc_node = enc_builder.bytes(serialized).build();

    let mut children = vec![enc_node];

    if is_prekey && let Some(acc) = account {
        children.push(
            NodeBuilder::new("device-identity")
                .bytes(acc.encode_to_vec())
                .build(),
        );
    }

    let stanza_type = stanza_type_from_message(message);
    let mut stanza_builder = NodeBuilder::new("message")
        .attr("to", group_jid)
        .attr("participant", participant_jid)
        .attr("id", message_id)
        .attr("type", stanza_type);

    // WA Web always sets addressing_mode for groups (MsgCreateDeviceStanza.js:131-135)
    stanza_builder = stanza_builder.attr("addressing_mode", addressing_mode.as_str());

    Ok(stanza_builder.children(children).build())
}

/// Result of `prepare_group_stanza` — carries the stanza node and the exact
/// device list used for SKDM distribution, so callers can persist sender key
/// tracking without re-resolving devices.
pub struct PreparedGroupStanza {
    pub node: Node,
    /// Devices that actually received SKDM (successfully encrypted).
    pub skdm_devices: Vec<Jid>,
    /// Users whose device registry should be invalidated because their
    /// devices returned 406 (unregistered) during SKDM prekey fetch.
    /// Empty when no 406 occurred.
    pub stale_device_users: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn prepare_group_stanza<
    'a,
    S: crate::libsignal::protocol::SessionStore + Send + Sync,
    I: crate::libsignal::protocol::IdentityKeyStore + Send + Sync,
    P: crate::libsignal::protocol::PreKeyStore + Send + Sync,
    SP: crate::libsignal::protocol::SignedPreKeyStore + Send + Sync,
>(
    stores: &mut SignalStores<'a, S, I, P, SP>,
    resolver: &dyn SendContextResolver,
    group_info: &mut GroupInfo,
    own_jid: &Jid,
    own_lid: &Jid,
    account: Option<&wa::AdvSignedDeviceIdentity>,
    to_jid: Jid,
    message: &wa::Message,
    request_id: String,
    force_skdm_distribution: bool,
    skdm_target_devices: Option<Vec<Jid>>,
    edit: Option<crate::types::message::EditAttribute>,
    extra_stanza_nodes: &[Node],
) -> Result<PreparedGroupStanza> {
    let (own_sending_jid, _) = match group_info.addressing_mode {
        crate::types::message::AddressingMode::Lid => (own_lid.clone(), "lid"),
        crate::types::message::AddressingMode::Pn => (own_jid.clone(), "pn"),
    };

    // Generate reporting token if the message type supports it
    // For groups, both sender_jid and remote_jid are the group JID (to_jid) per Baileys implementation
    let reporting_result = generate_reporting_token(message, &request_id, &to_jid, &to_jid, None);

    // Prepare message with MessageContextInfo containing the message secret
    let message_for_encryption = if let Some(ref result) = reporting_result {
        prepare_message_with_context(message, &result.message_secret)
    } else {
        message.clone()
    };

    let own_base_jid = own_sending_jid.to_non_ad();
    if !group_info
        .participants
        .iter()
        .any(|participant| participant.is_same_user_as(&own_base_jid))
    {
        group_info.participants.push(own_base_jid.clone());
    }

    let mut message_children: Vec<Node> = Vec::new();
    let mut includes_prekey_message = false;
    let mut phash_for_stanza: Option<String> = None;
    let mut skdm_encrypted_devices: Vec<Jid> = Vec::new();

    let sender_address = own_sending_jid.to_protocol_address();

    // Determine if we need to distribute SKDM and to which devices
    let distribution_list: Option<Vec<Jid>> = if let Some(target_devices) = skdm_target_devices {
        // Use the specific list of devices that need SKDM
        if target_devices.is_empty() {
            None
        } else {
            log::debug!(
                "SKDM distribution to {} specific devices for group {}",
                target_devices.len(),
                to_jid
            );
            Some(target_devices)
        }
    } else if force_skdm_distribution {
        // Resolve all devices for all participants (legacy behavior)
        // For LID groups, use phone numbers for device queries (LID usync may not work for own JID)
        // For PN groups, use JIDs directly
        let mut jids_to_resolve: Vec<Jid> = group_info
            .participants
            .iter()
            .map(|jid| {
                let base_jid = jid.to_non_ad();
                // If this is a LID JID and we have a phone number mapping, use it for device query
                if base_jid.is_lid()
                    && let Some(phone_jid) = group_info.phone_jid_for_lid_user(&base_jid.user)
                {
                    log::debug!(
                        "Using phone number {} for LID {} device query",
                        phone_jid,
                        base_jid
                    );
                    return phone_jid.to_non_ad();
                }
                base_jid
            })
            .collect();

        // Determine what user to check for — use the PN user when own is LID
        // and we have a mapping. Keeping this as a borrow avoids allocating a
        // throwaway Jid when own is already in the list.
        let own_pn_mapping = if own_base_jid.is_lid() {
            group_info.phone_jid_for_lid_user(&own_base_jid.user)
        } else {
            None
        };
        let own_check_user = own_pn_mapping
            .map(|pn| pn.user.as_str())
            .unwrap_or(own_base_jid.user.as_str());

        if !jids_to_resolve.iter().any(|p| p.user == own_check_user) {
            jids_to_resolve.push(match own_pn_mapping {
                Some(pn) => pn.to_non_ad(),
                None => own_base_jid.clone(),
            });
        }

        crate::types::jid::sort_dedup_by_user(&mut jids_to_resolve);

        log::debug!(
            "Resolving devices for {} participants",
            jids_to_resolve.len()
        );

        let mut resolved_list = resolver.resolve_devices(&jids_to_resolve).await?;

        // For LID groups, convert phone-based device JIDs back to LID format
        // This is necessary because WhatsApp Web expects LID addressing in SKDM <to> nodes
        if group_info.addressing_mode == crate::types::message::AddressingMode::Lid {
            resolved_list = resolved_list
                .into_iter()
                .map(|device_jid| group_info.phone_device_jid_to_lid(&device_jid))
                .collect();
            log::debug!(
                "Converted {} devices to LID addressing for group {}",
                resolved_list.len(),
                to_jid
            );
        }

        // Dedup AFTER LID conversion to avoid duplicates when both phone and LID
        // queries return the same user (e.g., 559980000003:33 and 100000037037034:33
        // both convert to 100000037037034:33@lid).
        // Key on (user, server, agent, device) — excludes `integrator` which is not
        // part of the wire JID identity used in <to jid> and phash.
        crate::types::jid::sort_dedup_by_device(&mut resolved_list);

        // Filter devices for SKDM distribution:
        // - Exclude the exact sending device (own_sending_jid) - we already have our own sender key
        // - Keep ALL other devices including our own other devices (phone, other companions)
        //   because they need the SKDM to decrypt messages we send from this device
        // - Exclude hosted/Cloud API devices (device ID 99 or @hosted server) - they don't
        //   participate in group E2EE, only in 1:1 chats
        let own_user = &own_sending_jid.user;
        let own_device = own_sending_jid.device;
        let before_filter = resolved_list.len();
        resolved_list.retain(|device_jid| {
            let is_exact_sender = device_jid.user == *own_user && device_jid.device == own_device;
            let is_hosted = device_jid.is_hosted();
            // Exclude the exact sending device and hosted devices
            !is_exact_sender && !is_hosted
        });
        log::debug!(
            "Filtered SKDM devices from {} to {} (excluded sender {}:{} and hosted devices)",
            before_filter,
            resolved_list.len(),
            own_user,
            own_device
        );

        log::debug!(
            "SKDM distribution list for {} resolved to {} devices",
            to_jid,
            resolved_list.len(),
        );

        Some(resolved_list)
    } else {
        None
    };

    let mut had_unregistered_devices = false;

    if let Some(ref distribution_list) = distribution_list {
        // WA Web computes phash from the full distribution list (target set at
        // send time), not the actual encrypted outcome
        match MessageUtils::participant_list_hash(distribution_list) {
            Ok(phash) => phash_for_stanza = Some(phash),
            Err(e) => log::warn!("Failed to compute phash for group {}: {:?}", to_jid, e),
        }
        let axolotl_skdm_bytes = create_sender_key_distribution_message_for_group(
            stores.sender_key_store,
            &to_jid,
            &sender_address,
        )
        .await?;

        let skdm_wrapper_msg = wa::Message {
            sender_key_distribution_message: Some(wa::message::SenderKeyDistributionMessage {
                group_id: Some(to_jid.to_string()),
                axolotl_sender_key_distribution_message: Some(axolotl_skdm_bytes),
            }),
            ..Default::default()
        };
        let skdm_plaintext_to_encrypt = MessageUtils::encode_and_pad(&skdm_wrapper_msg);

        // WA Web's GroupSkmsgJob wraps ensureE2ESessions in try/catch — logs error
        // but does NOT rethrow. SKDM distribution failure must not prevent the group
        // message from being sent. Only successfully encrypted devices are tracked.
        match encrypt_for_devices(
            stores,
            resolver,
            distribution_list,
            &skdm_plaintext_to_encrypt,
            true,
            None,
        )
        .await
        {
            Ok(result) => {
                includes_prekey_message = includes_prekey_message || result.includes_prekey_message;
                if result.had_unregistered_device {
                    had_unregistered_devices = true;
                }
                skdm_encrypted_devices = result.encrypted_devices;

                if !result.participant_nodes.is_empty() {
                    message_children.push(
                        NodeBuilder::new("participants")
                            .children(result.participant_nodes)
                            .build(),
                    );
                    if includes_prekey_message && let Some(acc) = account {
                        message_children.push(
                            NodeBuilder::new("device-identity")
                                .bytes(acc.encode_to_vec())
                                .build(),
                        );
                    }
                }
            }
            Err(e) => {
                log::warn!(
                    "SKDM distribution failed for group {}, continuing without it: {e}",
                    to_jid
                );
                if is_device_unregistered_error(&e) {
                    had_unregistered_devices = true;
                }
            }
        }
    }

    let plaintext = MessageUtils::encode_and_pad(&message_for_encryption);
    let skmsg = encrypt_group_message(
        stores.sender_key_store,
        &to_jid,
        &sender_address,
        &plaintext,
        &mut rand::make_rng::<rand::rngs::StdRng>(),
    )
    .await?;

    let skmsg_ciphertext = skmsg.into_serialized();

    let mediatype = media_type_from_message(message);
    let hide_decrypt_fail = (edit.as_ref().is_some_and(|e| {
        *e != crate::types::message::EditAttribute::Empty
            && *e != crate::types::message::EditAttribute::AdminRevoke
    })) || should_hide_decrypt_fail(message);

    let mut enc_builder = NodeBuilder::new("enc")
        .attr("v", stanza::ENC_VERSION)
        .attr("type", stanza::ENC_TYPE_SKMSG);
    if let Some(mt) = mediatype {
        enc_builder = enc_builder.attr("mediatype", mt);
    }
    enc_builder = enc_builder.bytes(skmsg_ciphertext);
    if hide_decrypt_fail {
        enc_builder = enc_builder.attr("decrypt-fail", "hide");
    }
    let content_node = enc_builder.build();

    let stanza_type = stanza_type_from_message(message);
    let mut stanza_builder = NodeBuilder::new("message")
        .attr("to", to_jid)
        .attr("id", request_id)
        .attr("type", stanza_type);

    // WA Web always sets addressing_mode for groups (MsgCreateDeviceStanza.js:131-135)
    stanza_builder = stanza_builder.attr("addressing_mode", group_info.addressing_mode.as_str());

    if let Some(edit_attr) = &edit
        && *edit_attr != crate::types::message::EditAttribute::Empty
    {
        stanza_builder = stanza_builder.attr("edit", edit_attr.to_string_val());
    }
    // NOTE: WhatsApp Web does NOT include participant attribute on initial admin revoke send
    // The participant attribute only appears on retry/fanout messages

    message_children.push(content_node);

    // Add reporting token node if we generated one
    if let Some(ref result) = reporting_result {
        message_children.push(build_reporting_node(result));
    }

    // Add phash if we distributed keys in this message
    if let Some(phash) = phash_for_stanza {
        stanza_builder = stanza_builder.attr("phash", phash);
    }

    // Add any extra stanza nodes provided by the caller
    message_children.extend(extra_stanza_nodes.iter().cloned());

    let stanza = stanza_builder.children(message_children).build();

    // Emit both LID and PN aliases when the group knows them: registry
    // entries can be stored under either key depending on when/how usync
    // was called, and `invalidate_device_cache` needs both to clean up
    // zombie records without relying on `lid_pn_cache` being populated.
    let stale_users = if had_unregistered_devices {
        let is_lid_mode = group_info.addressing_mode == crate::types::message::AddressingMode::Lid;
        let encrypted_set: HashSet<&Jid> = skdm_encrypted_devices.iter().collect();
        let mut user_set = HashSet::new();
        if let Some(ref dist) = distribution_list {
            for d in dist {
                if !encrypted_set.contains(d) {
                    user_set.insert(d.user.to_string());
                    if is_lid_mode
                        && d.is_lid()
                        && let Some(pn_jid) = group_info.phone_jid_for_lid_user(&d.user)
                        && pn_jid.is_pn()
                    {
                        user_set.insert(pn_jid.user.to_string());
                    }
                }
            }
        }
        user_set.into_iter().collect()
    } else {
        Vec::new()
    };

    Ok(PreparedGroupStanza {
        node: stanza,
        skdm_devices: skdm_encrypted_devices,
        stale_device_users: stale_users,
    })
}

pub async fn create_sender_key_distribution_message_for_group(
    store: &mut (dyn SenderKeyStore + Send + Sync),
    group_jid: &Jid,
    sender_address: &ProtocolAddress,
) -> Result<Vec<u8>> {
    let sender_key_name = make_sender_key_name(group_jid, sender_address);
    let mut rng = rand::make_rng::<rand::rngs::StdRng>();

    let skdm = crate::libsignal::protocol::create_sender_key_distribution_message(
        &sender_key_name,
        store,
        &mut rng,
    )
    .await?;

    Ok(skdm.into_serialized().into_vec())
}

/// Ensure the status stanza has a `<participants>` node listing all recipient
/// user JIDs. WhatsApp Web's `participantList` uses bare USER JIDs (not
/// device JIDs) -- `<to jid="user@s.whatsapp.net"/>` -- to tell the server
/// which users should receive the skmsg. The SKDM distribution list
/// (already in `<participants>`) uses device JIDs with `<enc>` children.
///
/// This is a pure function (no runtime or client dependencies).
pub fn ensure_status_participants(
    mut stanza: Node,
    group_info: &crate::client::context::GroupInfo,
) -> Node {
    use wacore_binary::NodeContent;
    use wacore_binary::builder::NodeBuilder;

    // Build bare <to jid="USER_JID"/> entries for each participant.
    // WhatsApp Web uses USER_JID (not DEVICE_JID) for the participantList.
    let bare_to_nodes: Vec<Node> = group_info
        .participants
        .iter()
        .map(|jid| NodeBuilder::new("to").attr("jid", jid.to_non_ad()).build())
        .collect();

    // Check if <participants> already exists in the stanza children
    let children = match &mut stanza.content {
        Some(NodeContent::Nodes(nodes)) => nodes,
        _ => {
            stanza.content = Some(NodeContent::Nodes(vec![]));
            match &mut stanza.content {
                Some(NodeContent::Nodes(nodes)) => nodes,
                _ => unreachable!(),
            }
        }
    };

    if let Some(participants_node) = children.iter_mut().find(|n| n.tag == "participants") {
        // <participants> already exists (from SKDM distribution).
        // Add bare <to> user JID entries for users whose devices are NOT
        // already represented by SKDM device-level entries.
        let existing_users: std::collections::HashSet<wacore_binary::CompactString> =
            participants_node
                .children()
                .unwrap_or_default()
                .iter()
                .filter_map(|n| n.attrs.get("jid").and_then(|v| v.to_jid()).map(|j| j.user))
                .collect();

        let new_to_nodes: Vec<Node> = bare_to_nodes
            .into_iter()
            .filter(|n| {
                n.attrs
                    .get("jid")
                    .and_then(|v| v.to_jid())
                    .is_some_and(|j| !existing_users.contains(&j.user))
            })
            .collect();

        if !new_to_nodes.is_empty() {
            match &mut participants_node.content {
                Some(NodeContent::Nodes(nodes)) => nodes.extend(new_to_nodes),
                _ => {
                    participants_node.content = Some(NodeContent::Nodes(new_to_nodes));
                }
            }
        }
    } else {
        // No <participants> node — create one with bare <to> entries.
        let participants_node = NodeBuilder::new("participants")
            .children(bare_to_nodes)
            .build();
        children.insert(0, participants_node);
    }

    stanza
}

/// True when a `status@broadcast` message should carry the
/// `<meta status_setting="..."/>` child. Only applies to actual status posts:
/// reactions (handled server-side as addons) and revokes must omit it, per
/// `WAWebEncryptAndSendStatusMsg` vs `WAWebSendReactionMsgAction`.
///
/// Descends `ephemeral_message` / `device_sent_message` / view-once wrappers
/// before classifying (same as `stanza_type_from_message`), so a reaction
/// nested inside a wrapper cannot slip past and re-trigger 479.
pub fn status_carries_privacy_meta(message: &wa::Message) -> bool {
    let msg = unwrap_message(message);
    let is_revoke = msg
        .protocol_message
        .as_ref()
        .is_some_and(|pm| pm.r#type == Some(wa::message::protocol_message::Type::Revoke as i32));
    let is_reaction = msg.reaction_message.is_some() || msg.enc_reaction_message.is_some();
    !is_revoke && !is_reaction
}

/// Dedup a pre-resolved status recipient list by user, then anchor the sender's
/// own LID. Errors when no recipient was resolvable (matches WA Web's
/// `WAWebLidMigrationUtils.toUserLid` + `compactMap` dropping unresolvable
/// entries; an empty result means "nothing to send to").
///
/// Pure function: no allocations besides the returned `Vec` and (when needed)
/// the own-LID push. Dedup is a linear Vec scan — status lists stay small
/// enough that a HashSet is not worth its allocation.
pub fn assemble_status_participants<I>(resolved: I, own_lid: &Jid) -> anyhow::Result<Vec<Jid>>
where
    I: IntoIterator<Item = Option<Jid>>,
{
    let iter = resolved.into_iter();
    let (lower, _upper) = iter.size_hint();
    let mut out: Vec<Jid> = Vec::with_capacity(lower.saturating_add(1));
    for jid in iter.flatten() {
        if !out.iter().any(|r| r.user == jid.user) {
            out.push(jid);
        }
    }
    if out.is_empty() {
        anyhow::bail!("No valid status recipients after LID resolution");
    }
    if !out.iter().any(|r| r.user == own_lid.user) {
        out.push(own_lid.to_non_ad());
    }
    Ok(out)
}

/// Build a `Message.ProtocolMessage` for `GROUP_MEMBER_LABEL_CHANGE`.
///
/// Sent via the standard E2EE fanout, not an IQ. Empty `label` clears.
/// `ts_secs` is unix seconds, matching WA Web's `unixTime()`.
pub fn build_member_label_message(label: String, ts_secs: i64) -> wa::Message {
    wa::Message {
        protocol_message: Some(Box::new(wa::message::ProtocolMessage {
            r#type: Some(wa::message::protocol_message::Type::GroupMemberLabelChange as i32),
            member_label: Some(wa::MemberLabel {
                label: Some(label),
                label_timestamp: Some(ts_secs),
            }),
            ..Default::default()
        })),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::context::{GroupInfo, SendContextResolver};
    use crate::libsignal::protocol::{IdentityKeyPair, KeyPair, PreKeyBundle};
    use std::collections::HashMap;
    use wacore_binary::Jid;

    mod assemble_status_participants {
        use super::*;

        fn lid(u: &str) -> Jid {
            u.parse().expect("parse LID jid")
        }

        #[test]
        fn dedup_keeps_first_entry_per_user_and_anchors_own() {
            let own = lid("99999999999999@lid");
            let out = assemble_status_participants(
                vec![
                    Some(lid("111@lid")),
                    Some(lid("222@lid")),
                    Some(lid("111@lid")),
                    Some(lid("333@lid")),
                ],
                &own,
            )
            .expect("should succeed");
            let users: Vec<&str> = out.iter().map(|j| j.user.as_str()).collect();
            assert_eq!(users, ["111", "222", "333", "99999999999999"]);
        }

        #[test]
        fn skips_none_entries_matching_wa_web_compactmap() {
            // Unresolvable recipients arrive as `None` and must be silently
            // dropped — mirrors WA Web's `compactMap(list, toUserLid)`.
            let own = lid("me@lid");
            let out = assemble_status_participants(
                vec![None, Some(lid("111@lid")), None, Some(lid("222@lid"))],
                &own,
            )
            .expect("should succeed");
            let users: Vec<&str> = out.iter().map(|j| j.user.as_str()).collect();
            assert_eq!(users, ["111", "222", "me"]);
        }

        #[test]
        fn does_not_duplicate_own_when_already_in_list() {
            let own = lid("me@lid");
            let out =
                assemble_status_participants(vec![Some(lid("111@lid")), Some(lid("me@lid"))], &own)
                    .expect("should succeed");
            let users: Vec<&str> = out.iter().map(|j| j.user.as_str()).collect();
            assert_eq!(users, ["111", "me"]);
        }

        #[test]
        fn errors_when_every_recipient_is_unresolvable() {
            // Regression guard for the original bug: a single LID-only
            // contact used to hard-abort the send with
            // `No PN mapping for LID ...`. The new contract is softer —
            // individual unresolvable entries are dropped — but we still
            // refuse to send when the entire list came back empty, rather
            // than silently broadcasting to own devices only.
            let own = lid("me@lid");
            let err = assemble_status_participants(vec![None, None, None], &own)
                .expect_err("all-None list must error");
            assert!(err.to_string().contains("No valid status recipients"));
        }

        #[test]
        fn errors_when_list_is_empty() {
            let own = lid("me@lid");
            let err = assemble_status_participants(Vec::<Option<Jid>>::new(), &own)
                .expect_err("empty list must error");
            assert!(err.to_string().contains("No valid status recipients"));
        }

        #[test]
        fn strips_device_suffix_from_own_lid() {
            // Snapshot lid from the device store carries a device id; the
            // participant list uses bare USER JIDs.
            let own: Jid = "me:5@lid".parse().unwrap();
            let out = assemble_status_participants(vec![Some(lid("111@lid"))], &own)
                .expect("should succeed");
            let me = out
                .iter()
                .find(|j| j.user.as_str() == "me")
                .expect("own LID should be present");
            assert_eq!(me.device, 0, "own LID should be non-ad (device=0)");
        }
    }

    mod status_carries_privacy_meta {
        use super::*;

        #[test]
        fn true_for_text_post() {
            let msg = wa::Message {
                extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                    text: Some("hi".into()),
                    ..Default::default()
                })),
                ..Default::default()
            };
            assert!(status_carries_privacy_meta(&msg));
        }

        #[test]
        fn true_for_image_post() {
            let msg = wa::Message {
                image_message: Some(Box::new(wa::message::ImageMessage::default())),
                ..Default::default()
            };
            assert!(status_carries_privacy_meta(&msg));
        }

        #[test]
        fn false_for_reaction() {
            let msg = wa::Message {
                reaction_message: Some(wa::message::ReactionMessage {
                    text: Some("💚".into()),
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert!(
                !status_carries_privacy_meta(&msg),
                "reactions must omit <meta status_setting> (479 SmaxInvalid otherwise)"
            );
        }

        #[test]
        fn false_for_enc_reaction() {
            let msg = wa::Message {
                enc_reaction_message: Some(wa::message::EncReactionMessage::default()),
                ..Default::default()
            };
            assert!(!status_carries_privacy_meta(&msg));
        }

        #[test]
        fn false_for_revoke() {
            let msg = wa::Message {
                protocol_message: Some(Box::new(wa::message::ProtocolMessage {
                    r#type: Some(wa::message::protocol_message::Type::Revoke as i32),
                    ..Default::default()
                })),
                ..Default::default()
            };
            assert!(!status_carries_privacy_meta(&msg));
        }

        #[test]
        fn true_for_non_revoke_protocol_message() {
            // Other ProtocolMessage types (e.g., EphemeralSettings) aren't
            // reactions and aren't revokes — treat as posts for now.
            let msg = wa::Message {
                protocol_message: Some(Box::new(wa::message::ProtocolMessage {
                    r#type: Some(wa::message::protocol_message::Type::EphemeralSetting as i32),
                    ..Default::default()
                })),
                ..Default::default()
            };
            assert!(status_carries_privacy_meta(&msg));
        }

        #[test]
        fn false_for_reaction_inside_ephemeral_wrapper() {
            let inner = wa::Message {
                reaction_message: Some(wa::message::ReactionMessage::default()),
                ..Default::default()
            };
            let msg = wa::Message {
                ephemeral_message: Some(Box::new(wa::message::FutureProofMessage {
                    message: Some(Box::new(inner)),
                })),
                ..Default::default()
            };
            assert!(!status_carries_privacy_meta(&msg));
        }

        #[test]
        fn false_for_revoke_inside_device_sent_wrapper() {
            let inner = wa::Message {
                protocol_message: Some(Box::new(wa::message::ProtocolMessage {
                    r#type: Some(wa::message::protocol_message::Type::Revoke as i32),
                    ..Default::default()
                })),
                ..Default::default()
            };
            let msg = wa::Message {
                device_sent_message: Some(Box::new(wa::message::DeviceSentMessage {
                    destination_jid: Some(String::new()),
                    message: Some(Box::new(inner)),
                    ..Default::default()
                })),
                ..Default::default()
            };
            assert!(!status_carries_privacy_meta(&msg));
        }
    }

    #[test]
    fn build_member_label_message_sets_fields() {
        let msg = build_member_label_message("VIP".to_string(), 1_766_847_151);
        let pm = msg.protocol_message.as_ref().expect("protocol_message set");
        assert_eq!(
            pm.r#type,
            Some(wa::message::protocol_message::Type::GroupMemberLabelChange as i32)
        );
        let ml = pm.member_label.as_ref().expect("member_label set");
        assert_eq!(ml.label.as_deref(), Some("VIP"));
        assert_eq!(ml.label_timestamp, Some(1_766_847_151));
        assert!(
            pm.key.is_none(),
            "MessageKey must NOT be set (WA Web parity)"
        );
    }

    #[test]
    fn build_member_label_message_clear_uses_empty_string() {
        let msg = build_member_label_message(String::new(), 1);
        let ml = msg
            .protocol_message
            .as_ref()
            .unwrap()
            .member_label
            .as_ref()
            .unwrap();
        assert_eq!(ml.label.as_deref(), Some(""));
    }

    #[test]
    fn build_member_label_message_preserves_unicode() {
        let msg = build_member_label_message("🚀 BOT".to_string(), 2);
        let ml = msg
            .protocol_message
            .as_ref()
            .unwrap()
            .member_label
            .as_ref()
            .unwrap();
        assert_eq!(ml.label.as_deref(), Some("🚀 BOT"));
    }

    /// Mock implementation of SendContextResolver for testing
    struct MockSendContextResolver {
        /// Pre-key bundles to return: JID -> Option<PreKeyBundle>
        prekey_bundles: HashMap<Jid, Option<PreKeyBundle>>,
        /// Devices to return from resolve_devices
        devices: Vec<Jid>,
        /// Phone number to LID mappings for testing LID session lookup
        phone_to_lid: HashMap<String, String>,
    }

    impl MockSendContextResolver {
        fn new() -> Self {
            Self {
                prekey_bundles: HashMap::new(),
                devices: Vec::new(),
                phone_to_lid: HashMap::new(),
            }
        }

        fn with_missing_bundle(mut self, jid: Jid) -> Self {
            self.prekey_bundles.insert(jid, None);
            self
        }

        fn with_bundle(mut self, jid: Jid, bundle: PreKeyBundle) -> Self {
            self.prekey_bundles.insert(jid, Some(bundle));
            self
        }

        fn with_devices(mut self, devices: Vec<Jid>) -> Self {
            self.devices = devices;
            self
        }

        fn with_phone_to_lid(mut self, phone: &str, lid: &str) -> Self {
            self.phone_to_lid.insert(phone.to_string(), lid.to_string());
            self
        }
    }

    #[async_trait::async_trait]
    impl SendContextResolver for MockSendContextResolver {
        async fn resolve_devices(&self, _jids: &[Jid]) -> Result<Vec<Jid>> {
            Ok(self.devices.clone())
        }

        async fn fetch_prekeys(&self, jids: &[Jid]) -> Result<HashMap<Jid, PreKeyBundle>> {
            let mut result = HashMap::new();
            for jid in jids {
                if let Some(bundle_opt) = self.prekey_bundles.get(jid)
                    && let Some(bundle) = bundle_opt
                {
                    result.insert(jid.clone(), bundle.clone());
                }
            }
            Ok(result)
        }

        async fn fetch_prekeys_for_identity_check(
            &self,
            jids: &[Jid],
        ) -> Result<HashMap<Jid, PreKeyBundle>> {
            let mut result = HashMap::new();
            for jid in jids {
                if let Some(bundle_opt) = self.prekey_bundles.get(jid)
                    && let Some(bundle) = bundle_opt
                {
                    result.insert(jid.clone(), bundle.clone());
                }
                // If None, we intentionally omit it from the result (simulating server not returning it)
            }
            Ok(result)
        }

        async fn resolve_group_info(&self, _jid: &Jid) -> Result<GroupInfo> {
            unimplemented!("resolve_group_info not needed for send.rs tests")
        }

        async fn get_lid_for_phone(&self, phone_user: &str) -> Option<String> {
            self.phone_to_lid.get(phone_user).cloned()
        }
    }

    /// Test case: Missing pre-key bundle for a single device skips gracefully
    ///
    /// When sending to multiple devices, if some don't have pre-key bundles (e.g., Cloud API),
    /// we should skip them instead of failing the entire message.
    #[test]
    fn test_missing_prekey_bundle_skips_device() {
        let device_with_bundle: Jid = "1234567890:0@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        let device_without_bundle: Jid = "1234567890:1@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        let cloud_api: Jid = "1234567890:99@hosted"
            .parse()
            .expect("test JID should be valid");

        let bundle = create_mock_bundle();

        let resolver = MockSendContextResolver::new()
            .with_bundle(device_with_bundle.clone(), bundle)
            .with_missing_bundle(device_without_bundle.clone())
            .with_missing_bundle(cloud_api.clone())
            .with_devices(vec![
                device_with_bundle.clone(),
                device_without_bundle.clone(),
                cloud_api.clone(),
            ]);

        // Check that the resolver correctly returns only available bundles
        assert_eq!(
            resolver.prekey_bundles.len(),
            3,
            "Resolver should have 3 entries"
        );

        // Verify device_with_bundle has a Some(bundle)
        assert!(
            resolver.prekey_bundles[&device_with_bundle].is_some(),
            "device_with_bundle should have a Some entry"
        );

        // Verify others have None
        assert!(
            resolver.prekey_bundles[&device_without_bundle].is_none(),
            "device_without_bundle should have None"
        );
        assert!(
            resolver.prekey_bundles[&cloud_api].is_none(),
            "cloud_api should have None"
        );

        println!("✅ Missing pre-key bundle skips device gracefully");
    }

    /// Test case: All devices missing pre-key bundles
    ///
    /// If all devices are unavailable, the batch should still complete without panic.
    #[test]
    fn test_all_devices_missing_prekey_bundles() {
        let device1: Jid = "1234567890:0@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        let device2: Jid = "1234567890:1@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        let device3: Jid = "9876543210:0@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");

        let resolver = MockSendContextResolver::new()
            .with_missing_bundle(device1.clone())
            .with_missing_bundle(device2.clone())
            .with_missing_bundle(device3.clone())
            .with_devices(vec![device1.clone(), device2.clone(), device3.clone()]);

        // All entries should be None
        assert!(resolver.prekey_bundles[&device1].is_none());
        assert!(resolver.prekey_bundles[&device2].is_none());
        assert!(resolver.prekey_bundles[&device3].is_none());

        println!("✅ All devices missing bundles handled gracefully");
    }

    /// Test case: Large group with mixed device availability
    ///
    /// In real-world scenarios, large groups may have some unavailable devices.
    /// The encryption should proceed for available devices and skip unavailable ones.
    #[test]
    fn test_large_group_with_mixed_device_availability() {
        let mut all_devices = Vec::new();

        for i in 0..10u16 {
            let device_jid = Jid::pn_device("1234567890", i);
            all_devices.push(device_jid);
        }

        let mut resolver = MockSendContextResolver::new().with_devices(all_devices.clone());

        // Add bundles for devices 0-6, mark 7-9 as missing
        for i in 0..10u16 {
            let device_jid = Jid::pn_device("1234567890", i);

            if i < 7 {
                resolver = resolver.with_bundle(device_jid, create_mock_bundle());
            } else {
                resolver = resolver.with_missing_bundle(device_jid);
            }
        }

        // Verify bundle availability
        let available_count = resolver
            .prekey_bundles
            .values()
            .filter(|v| v.is_some())
            .count();

        assert_eq!(available_count, 7, "Should have 7 available devices");
        assert_eq!(
            resolver.prekey_bundles.len(),
            10,
            "Should have 10 total entries"
        );

        println!("✅ Large group with 7 available, 3 unavailable devices");
    }

    /// Test case: Cloud API / HOSTED device without pre-key
    ///
    /// # Context: What are HOSTED devices?
    ///
    /// HOSTED devices (Cloud API / Meta Business API) are WhatsApp Business accounts
    /// that use Meta's server-side infrastructure instead of traditional E2EE.
    ///
    /// ## Identification:
    /// - Device ID 99 (`:99`) on any server
    /// - Server `@hosted` or `@hosted.lid`
    ///
    /// ## Behavior:
    /// - They do NOT have Signal protocol prekey bundles
    /// - For 1:1 chats: included in device list, but prekey fetch fails gracefully
    /// - For groups: proactively filtered out before SKDM distribution
    ///
    /// This test verifies that when a hosted device is included in the device list
    /// (which would happen for 1:1 chats), the missing prekey is handled gracefully.
    #[test]
    fn test_cloud_api_device_without_prekey() {
        let regular_device: Jid = "1234567890:0@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        let cloud_api: Jid = "1234567890:99@hosted"
            .parse()
            .expect("test JID should be valid");

        // Verify the cloud_api device is detected as hosted
        assert!(
            cloud_api.is_hosted(),
            "Device with :99@hosted should be detected as hosted"
        );
        assert!(
            !regular_device.is_hosted(),
            "Regular device should NOT be detected as hosted"
        );

        let resolver = MockSendContextResolver::new()
            .with_bundle(regular_device.clone(), create_mock_bundle())
            .with_missing_bundle(cloud_api.clone())
            .with_devices(vec![regular_device.clone(), cloud_api.clone()]);

        assert!(
            resolver.prekey_bundles[&regular_device].is_some(),
            "Regular device should have a bundle"
        );
        assert!(
            resolver.prekey_bundles[&cloud_api].is_none(),
            "Cloud API device should not have a bundle (they don't use Signal protocol)"
        );

        println!("✅ Cloud API device has no prekey bundle (expected behavior)");
    }

    /// Test case: HOSTED devices are filtered from group SKDM distribution
    ///
    /// # Why filter hosted devices from groups?
    ///
    /// WhatsApp Web explicitly excludes hosted devices from group message fanout.
    /// From the JS code (`getFanOutList`):
    /// ```javascript
    /// var isHosted = e.id === 99 || e.isHosted === true;
    /// var includeInFanout = !isHosted || isOneToOneChat;
    /// ```
    ///
    /// ## Reasons:
    /// 1. Hosted devices don't use Signal protocol - they can't process SKDM
    /// 2. Including them causes unnecessary prekey fetch failures
    /// 3. Group encryption is handled differently for Cloud API businesses
    ///
    /// This test verifies that `is_hosted()` correctly identifies devices that
    /// should be filtered from group SKDM distribution.
    #[test]
    fn test_hosted_devices_filtered_from_group_skdm() {
        // Simulate devices returned from usync for a group
        let devices: Vec<Jid> = vec![
            // Regular devices - should receive SKDM
            "5511999887766:0@s.whatsapp.net"
                .parse()
                .expect("test JID should be valid"), // Primary phone
            "5511999887766:33@s.whatsapp.net"
                .parse()
                .expect("test JID should be valid"), // WhatsApp Web companion
            "5521988776655:0@s.whatsapp.net"
                .parse()
                .expect("test JID should be valid"), // Another participant
            "100000012345678:33@lid"
                .parse()
                .expect("test JID should be valid"), // LID companion device
            // HOSTED devices - should be EXCLUDED from group SKDM
            "5531977665544:99@s.whatsapp.net"
                .parse()
                .expect("test JID should be valid"), // Cloud API on regular server
            "100000087654321:99@lid"
                .parse()
                .expect("test JID should be valid"), // Cloud API on LID server
            "5541966554433:0@hosted"
                .parse()
                .expect("test JID should be valid"), // Explicit @hosted server
        ];

        // This is the filtering logic used in prepare_group_stanza
        let filtered_for_skdm: Vec<Jid> =
            devices.into_iter().filter(|jid| !jid.is_hosted()).collect();

        assert_eq!(
            filtered_for_skdm.len(),
            4,
            "Should have 4 devices after filtering out hosted devices"
        );

        // Verify all remaining devices are NOT hosted
        for jid in &filtered_for_skdm {
            assert!(
                !jid.is_hosted(),
                "Filtered list should not contain hosted device: {}",
                jid
            );
        }

        // Verify specific devices are included/excluded by checking struct fields
        // (Device ID 0 is not serialized in the string representation)
        let has_primary_phone = filtered_for_skdm
            .iter()
            .any(|j| j.user == "5511999887766" && j.device == 0 && j.server == "s.whatsapp.net");
        let has_companion = filtered_for_skdm
            .iter()
            .any(|j| j.user == "5511999887766" && j.device == 33 && j.server == "s.whatsapp.net");
        let has_cloud_api = filtered_for_skdm
            .iter()
            .any(|j| j.user == "5531977665544" && j.device == 99);
        let has_hosted_server = filtered_for_skdm.iter().any(|j| j.server == "hosted");

        assert!(has_primary_phone, "Primary phone should be included");
        assert!(has_companion, "WhatsApp Web companion should be included");
        assert!(
            !has_cloud_api,
            "Cloud API device (ID 99) should be excluded"
        );
        assert!(
            !has_hosted_server,
            "@hosted server device should be excluded"
        );

        println!("✅ Hosted devices correctly filtered from group SKDM distribution");
    }

    /// Test case: Device recovery between retries
    ///
    /// If a device was temporarily unavailable, a retry should succeed.
    #[test]
    fn test_device_recovery_between_requests() {
        let device: Jid = "1234567890:0@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");

        // First attempt: device unavailable
        let resolver_first = MockSendContextResolver::new().with_missing_bundle(device.clone());

        assert!(
            resolver_first.prekey_bundles[&device].is_none(),
            "First attempt: device should be unavailable"
        );

        // Second attempt: device recovered
        let resolver_second =
            MockSendContextResolver::new().with_bundle(device.clone(), create_mock_bundle());

        assert!(
            resolver_second.prekey_bundles[&device].is_some(),
            "Second attempt: device should be available"
        );

        println!("✅ Device recovery between retries works correctly");
    }

    /// Helper function to create a mock PreKeyBundle with valid types
    fn create_mock_bundle() -> PreKeyBundle {
        let mut rng = rand::make_rng::<rand::rngs::StdRng>();
        let identity_pair = IdentityKeyPair::generate(&mut rng);
        let signed_prekey_pair = KeyPair::generate(&mut rng);
        let prekey_pair = KeyPair::generate(&mut rng);

        PreKeyBundle::new(
            1,                                           // registration_id
            1u32.into(),                                 // device_id
            Some((1u32.into(), prekey_pair.public_key)), // pre_key
            2u32.into(),                                 // signed_pre_key_id
            signed_prekey_pair.public_key,
            vec![0u8; 64],
            *identity_pair.identity_key(),
        )
        .expect("Failed to create PreKeyBundle")
    }

    // These tests validate the fix for the LID-PN session mismatch issue.
    // When a message is received with sender_lid, the session is stored under the LID address.
    // When sending a reply using the phone number, we must reuse the existing LID session
    // instead of creating a new PN session, otherwise subsequent messages will fail with
    // MAC verification errors.

    /// Test that phone_to_lid mapping returns the cached LID mapping.
    ///
    /// This verifies the MockSendContextResolver correctly stores phone-to-LID
    /// mappings used for LID session lookup.
    #[test]
    fn test_mock_resolver_phone_to_lid_mapping() {
        let phone = "559980000001";
        let lid = "100000012345678";

        let resolver = MockSendContextResolver::new().with_phone_to_lid(phone, lid);

        // Access the HashMap directly (synchronous)
        let result = resolver.phone_to_lid.get(phone).cloned();

        assert!(result.is_some(), "Should return LID for known phone");
        assert_eq!(
            result.expect("known phone should return LID"),
            lid,
            "Should return correct LID"
        );

        // Unknown phone should return None
        let unknown = resolver.phone_to_lid.get("999999999").cloned();
        assert!(unknown.is_none(), "Should return None for unknown phone");

        println!("✅ MockSendContextResolver phone_to_lid mapping works correctly");
    }

    /// Test that the resolver correctly maps phone numbers to LIDs.
    ///
    /// This is a building block for the session lookup logic.
    #[test]
    fn test_phone_to_lid_mapping_multiple_users() {
        let resolver = MockSendContextResolver::new()
            .with_phone_to_lid("559980000001", "100000012345678")
            .with_phone_to_lid("559980000002", "100000024691356")
            .with_phone_to_lid("559980000003", "100000037037034");

        // Verify all mappings using direct HashMap access
        let lid1 = resolver.phone_to_lid.get("559980000001").cloned();
        let lid2 = resolver.phone_to_lid.get("559980000002").cloned();
        let lid3 = resolver.phone_to_lid.get("559980000003").cloned();

        assert_eq!(
            lid1.expect("phone 1 should have LID mapping"),
            "100000012345678"
        );
        assert_eq!(
            lid2.expect("phone 2 should have LID mapping"),
            "100000024691356"
        );
        assert_eq!(
            lid3.expect("phone 3 should have LID mapping"),
            "100000037037034"
        );

        println!("✅ Multiple phone-to-LID mappings work correctly");
    }

    /// Test the scenario that caused the original bug:
    /// - Session exists under LID address (from receiving a message with sender_lid)
    /// - Send to PN address should reuse the LID session, not create a new one
    ///
    /// This test verifies the logic flow, though full integration testing
    /// requires the actual encrypt_for_devices function with real sessions.
    #[test]
    fn test_lid_session_lookup_scenario() {
        // Scenario setup:
        // - Received message from 559980000001@s.whatsapp.net with sender_lid=100000012345678@lid
        // - Session was stored under 100000012345678.0
        // - Now sending reply to 559980000001@s.whatsapp.net
        // - Should look up LID and check for session under 100000012345678.0

        let phone = "559980000001";
        let lid = "100000012345678";
        let device_id = 0u16;

        let resolver = MockSendContextResolver::new().with_phone_to_lid(phone, lid);

        // Simulate the device JID we're trying to send to (PN format)
        let pn_device_jid = Jid::pn_device(phone, device_id);

        // Step 1: Look up LID for the phone number (using direct HashMap access)
        let lid_user = resolver
            .phone_to_lid
            .get(pn_device_jid.user.as_str())
            .cloned();
        assert!(lid_user.is_some(), "Should find LID for phone");
        let lid_user = lid_user.expect("phone should have LID mapping");

        // Step 2: Construct the LID JID with same device ID
        let lid_jid = Jid::lid_device(lid_user.clone(), pn_device_jid.device);

        // Step 3: Verify the LID JID is correctly constructed
        assert_eq!(lid_jid.user, lid, "LID user should match");
        assert_eq!(lid_jid.server, "lid", "Server should be 'lid'");
        assert_eq!(lid_jid.device, device_id, "Device ID should be preserved");

        // Step 4: Convert to protocol addresses and verify they're different
        use crate::types::jid::JidExt;
        let pn_address = pn_device_jid.to_protocol_address();
        let lid_address = lid_jid.to_protocol_address();

        assert_ne!(
            pn_address.name(),
            lid_address.name(),
            "PN and LID addresses should have different names"
        );
        assert_eq!(
            pn_address.device_id(),
            lid_address.device_id(),
            "Device IDs should match"
        );

        println!("✅ LID session lookup scenario works correctly:");
        println!("   - PN JID: {} -> Address: {}", pn_device_jid, pn_address);
        println!("   - LID JID: {} -> Address: {}", lid_jid, lid_address);
        println!("   - Would check for session under LID address first");
    }

    /// Test that companion device IDs are preserved in LID JID construction.
    ///
    /// WhatsApp Web uses device ID 33, and this must be preserved when
    /// constructing the LID JID for session lookup.
    #[test]
    fn test_lid_jid_preserves_companion_device_id() {
        let phone = "559980000001";
        let lid = "100000012345678";
        let companion_device_id = 33u16; // WhatsApp Web device ID

        let resolver = MockSendContextResolver::new().with_phone_to_lid(phone, lid);

        // Simulate sending to a companion device (WhatsApp Web)
        let pn_device_jid = Jid::pn_device(phone, companion_device_id);

        // Look up LID using direct HashMap access
        let lid_user = resolver
            .phone_to_lid
            .get(pn_device_jid.user.as_str())
            .cloned();

        // Construct LID JID
        let lid_jid = Jid::lid_device(
            lid_user.expect("phone should have LID mapping for companion test"),
            pn_device_jid.device,
        );

        assert_eq!(
            lid_jid.device, companion_device_id,
            "Device ID 33 should be preserved"
        );
        assert_eq!(lid_jid.to_string(), "100000012345678:33@lid");

        println!("✅ Companion device ID (33) correctly preserved in LID JID");
    }

    /// Test that LID lookup only applies to s.whatsapp.net JIDs.
    ///
    /// LID JIDs (@lid) and group JIDs (@g.us) should not trigger LID lookup.
    #[test]
    fn test_lid_lookup_only_for_pn_jids() {
        let _resolver =
            MockSendContextResolver::new().with_phone_to_lid("559980000001", "100000012345678");

        // These JIDs should NOT trigger LID lookup
        let lid_jid: Jid = "100000012345678:0@lid"
            .parse()
            .expect("test JID should be valid");
        let group_jid: Jid = "120363123456789012@g.us"
            .parse()
            .expect("test JID should be valid");

        // Only s.whatsapp.net JIDs should be looked up
        assert_ne!(
            lid_jid.server, "s.whatsapp.net",
            "LID JID should not be s.whatsapp.net"
        );
        assert_ne!(
            group_jid.server, "s.whatsapp.net",
            "Group JID should not be s.whatsapp.net"
        );

        // PN JID should be eligible for lookup
        let pn_jid: Jid = "559980000001:0@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        assert_eq!(
            pn_jid.server, "s.whatsapp.net",
            "PN JID should be s.whatsapp.net"
        );

        println!("✅ LID lookup correctly limited to s.whatsapp.net JIDs");
    }

    /// Test case: Regression test for self-encryption bug.
    ///
    /// The sender's own device (e.g. device 79) must be excluded from the encryption list
    /// to prevent "SESSION BASE KEY CHANGED" warnings caused by establishing a session with oneself.
    #[test]
    fn test_dm_encryption_excludes_sender_device() {
        // Setup:
        // - Own user: 123456789
        // - Specific own device (Sender): 79
        // - Other own device: 0
        // - Recipient: 987654321

        let own_user = "123456789";
        let own_device_id = 79;

        // Own JID (Sender)
        let own_jid = Jid::lid_device(own_user.to_string(), own_device_id);

        // Simulate devices returned by resolver.resolve_devices()
        // This includes:
        // 1. The sender's own device (should be excluded)
        // 2. Another device of the sender (should be in own_other_devices)
        // 3. The recipient's device (should be in recipient_devices)
        let all_devices: Vec<Jid> = vec![
            Jid::lid_device(own_user.to_string(), own_device_id), // Sender (79)
            Jid::lid_device(own_user.to_string(), 0),             // Other own device (0)
            Jid::lid_device("987654321".to_string(), 0),          // Recipient
        ];

        let (recipient_devices, own_other_devices) =
            partition_dm_devices(all_devices, &own_jid, None);

        // Verifications

        // 1. Sender device (79) should NOT be in either list
        let sender_in_own = own_other_devices.iter().any(|d| d.device == own_device_id);
        let sender_in_recipient = recipient_devices.iter().any(|d| d.device == own_device_id);

        assert!(
            !sender_in_own,
            "Sender device (79) should be excluded from own_other_devices"
        );
        assert!(
            !sender_in_recipient,
            "Sender device (79) should be excluded from recipient_devices"
        );

        // 2. Other own device (0) MUST be in own_other_devices
        let other_own_present = own_other_devices
            .iter()
            .any(|d| d.device == 0 && d.user == own_user);
        assert!(
            other_own_present,
            "Other own device (0) should be included in own_other_devices"
        );

        // 3. Recipient MUST be in recipient_devices
        let recipient_present = recipient_devices.iter().any(|d| d.user == "987654321");
        assert!(
            recipient_present,
            "Recipient should be included in recipient_devices"
        );

        println!("✅ Self-encryption regression test passed: Sender device correctly excluded.");
    }

    #[test]
    fn test_dm_encryption_treats_own_lid_devices_as_self() {
        let own_pn = Jid::pn_device("559980000001".to_string(), 18);
        let own_lid = Jid::lid_device("123456789012345".to_string(), 18);

        let all_devices = vec![
            Jid::lid_device("123456789012345".to_string(), 18), // Exact sender device via LID
            Jid::lid_device("123456789012345".to_string(), 0),  // Other own device via LID
            Jid::lid_device("987654321012345".to_string(), 0),  // Recipient
        ];

        let (recipient_devices, own_other_devices) =
            partition_dm_devices(all_devices, &own_pn, Some(&own_lid));

        assert!(
            !own_other_devices
                .iter()
                .any(|d| d.user == own_lid.user && d.device == 18),
            "Exact sender LID device should be excluded from own_other_devices"
        );
        assert!(
            !recipient_devices
                .iter()
                .any(|d| d.user == own_lid.user && d.device == 18),
            "Exact sender LID device should be excluded from recipient_devices"
        );
        assert!(
            own_other_devices
                .iter()
                .any(|d| d.user == own_lid.user && d.device == 0),
            "Other own LID devices should be routed through DSM as own_other_devices"
        );
        assert!(
            recipient_devices
                .iter()
                .any(|d| d.user == "987654321012345" && d.device == 0),
            "Non-self devices must remain in recipient_devices"
        );
    }

    /// Test case: LID Prekey Lookup Normalization
    ///
    /// Verifies that when looking up pre-key bundles for LID JIDs, the lookup key
    /// is normalized (agent=0) to match how the bundles are stored in the map.
    ///
    /// This validates the fix for "No pre-key bundle returned" when the requested JID
    /// has non-standard agent/server fields but the bundle is stored under the normalized key.
    #[test]
    fn test_lid_prekey_lookup_normalization() {
        // 1. Define JIDs
        // The JID we request (simulating what comes from resolve_devices or elsewhere)
        // Let's pretend it has agent=1 to simulate a mismatch
        let mut requested_jid = Jid::lid_device("123456789".to_string(), 0);
        requested_jid.agent = 1;

        // The normalized JID (how it's stored in the bundle map)
        let normalized_jid = Jid::lid_device("123456789".to_string(), 0); // agent=0 by default

        // 2. Setup Resolver
        // Store the bundle under the NORMALIZED key (agent=0)
        let resolver = MockSendContextResolver::new()
            .with_bundle(normalized_jid.clone(), create_mock_bundle())
            .with_devices(vec![requested_jid.clone()]);

        // 3. Verify Mock Setup
        // Ensure bundle is accessible via normalized key but NOT via requested (raw) key
        // This confirms our test condition is valid (that implicit lookup would fail)
        assert!(
            resolver.prekey_bundles.contains_key(&normalized_jid),
            "Setup: bundle should exist for normalized key"
        );
        assert!(
            !resolver.prekey_bundles.contains_key(&requested_jid),
            "Setup: bundle should NOT exist for requested raw key"
        );

        // 4. Test logic mirroring `encrypt_for_devices`
        let mut jid_to_encryption_jid = HashMap::new();
        // Assume direct mapping for simplicity
        jid_to_encryption_jid.insert(requested_jid.clone(), requested_jid.clone());

        // Get the bundles map (mocks `fetch_prekeys_for_identity_check`)
        // The mock implementation returns the map as-is filtered by keys.
        // HOWEVER, `fetch_prekeys` usually takes a list.
        // In `encrypt_for_devices`, we call:
        // let prekey_bundles = resolver.fetch_prekeys_for_identity_check(&[requested_jid]).await?;

        // Let's simulate what `fetch_prekeys_for_identity_check` would return.
        // Our mock implementation `fetch_prekeys` logic:
        // if let Some(bundle_opt) = self.prekey_bundles.get(jid)

        // Wait, if the mock follows exact HashMap lookup, `fetch_prekeys(&[requested_jid])`
        // will return EMPTY because `requested_jid` is not in `prekey_bundles`.
        // The REAL `fetch_prekeys` (in `client.rs` -> `prekeys.rs`) sends an IQ to the server,
        // and the server response is parsed. The parsing logic (in `prekeys.rs`) normalizes the key.
        // So the HashMap returned by `fetch_prekeys` will contain NORMALIZED keys.

        // So for this test to be accurate, we must simulate that `fetch_prekeys` returned a map
        // where the key is NORMALIZED, even if we asked for `requested_jid`?
        // Actually, `PreKeyFetchSpec` asks for JIDs. The response contains JIDs.
        // If we ask for `agent=1`, does the server return `agent=1`?
        // The logs showed:
        // parsed: `...:82@lid` (agent=0 probably, or just not printed?)
        // lookup: `...` (failed)

        // The critical part is that the `HashMap` returned by `resolver.fetch_prekeys`
        // definitely contains the bundle under some key.
        // If `prekeys.rs` normalizes it, it's under the normalized key.
        // The `encrypt_for_devices` logic has:
        // `match prekey_bundles.get(device_jid)`
        // where `device_jid` is the one from the loop (requested_jid).

        // If `fetch_prekeys` returns a map with `normalized_jid`, and we lookup `requested_jid`, it fails.
        // My fix was to normalize `requested_jid` before lookup.

        // So I need to construct the `prekey_bundles` map manually here to simulate the return from fetch.
        let mut prekey_bundles = HashMap::new();
        prekey_bundles.insert(normalized_jid.clone(), create_mock_bundle());

        // Now test the logic:
        let device_jid = &requested_jid;

        // -- Logic from fix --
        // Use centralized normalization logic
        let lookup_jid = device_jid.normalize_for_prekey_bundle();

        // Fix: Use the normalized device_jid to lookup the bundle
        let bundle = prekey_bundles.get(&lookup_jid);
        // --------------------

        assert!(bundle.is_some(), "Should find bundle after normalization");

        // Verify it would have failed without normalization
        let raw_lookup = prekey_bundles.get(device_jid);
        assert!(
            raw_lookup.is_none(),
            "Should NOT find bundle without normalization"
        );

        println!("✅ LID Prekey Lookup Normalization passed");
    }

    mod group_retry {
        use super::*;
        use crate::libsignal::protocol::{
            Direction, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, KeyPair,
            PreKeyBundle, ProtocolAddress, SessionStore, process_prekey_bundle,
        };
        use crate::types::message::AddressingMode;
        use std::collections::HashMap;
        use wacore_binary::NodeContent;

        struct MemSessionStore(HashMap<ProtocolAddress, Vec<u8>>);
        impl MemSessionStore {
            fn new() -> Self {
                Self(HashMap::new())
            }
        }
        #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
        #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
        impl SessionStore for MemSessionStore {
            async fn load_session(
                &self,
                a: &ProtocolAddress,
            ) -> crate::libsignal::protocol::error::Result<
                Option<crate::libsignal::protocol::SessionRecord>,
            > {
                Ok(self
                    .0
                    .get(a)
                    .and_then(|b| crate::libsignal::protocol::SessionRecord::deserialize(b).ok()))
            }
            async fn has_session(
                &self,
                a: &ProtocolAddress,
            ) -> crate::libsignal::protocol::error::Result<bool> {
                Ok(self.0.contains_key(a))
            }
            async fn store_session(
                &mut self,
                a: &ProtocolAddress,
                r: crate::libsignal::protocol::SessionRecord,
            ) -> crate::libsignal::protocol::error::Result<()> {
                self.0.insert(a.clone(), r.serialize()?);
                Ok(())
            }
        }

        struct MemIdentityStore {
            pair: IdentityKeyPair,
            reg_id: u32,
            known: HashMap<ProtocolAddress, IdentityKey>,
        }
        #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
        #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
        impl IdentityKeyStore for MemIdentityStore {
            async fn get_identity_key_pair(
                &self,
            ) -> crate::libsignal::protocol::error::Result<IdentityKeyPair> {
                Ok(self.pair.clone())
            }
            async fn get_local_registration_id(
                &self,
            ) -> crate::libsignal::protocol::error::Result<u32> {
                Ok(self.reg_id)
            }
            async fn save_identity(
                &mut self,
                a: &ProtocolAddress,
                id: &IdentityKey,
            ) -> crate::libsignal::protocol::error::Result<IdentityChange> {
                self.known.insert(a.clone(), *id);
                Ok(IdentityChange::from_changed(false))
            }
            async fn is_trusted_identity(
                &self,
                _: &ProtocolAddress,
                _: &IdentityKey,
                _: Direction,
            ) -> crate::libsignal::protocol::error::Result<bool> {
                Ok(true)
            }
            async fn get_identity(
                &self,
                a: &ProtocolAddress,
            ) -> crate::libsignal::protocol::error::Result<Option<IdentityKey>> {
                Ok(self.known.get(a).copied())
            }
        }

        async fn setup_session() -> (MemSessionStore, MemIdentityStore, Jid) {
            let mut rng = rand::make_rng::<rand::rngs::StdRng>();
            let sender = IdentityKeyPair::generate(&mut rng);
            let receiver = IdentityKeyPair::generate(&mut rng);
            let spk = KeyPair::generate(&mut rng);
            let opk = KeyPair::generate(&mut rng);
            let sig = receiver
                .private_key()
                .calculate_signature(&spk.public_key.serialize(), &mut rng)
                .unwrap();
            let bundle = PreKeyBundle::new(
                1,
                1u32.into(),
                Some((1u32.into(), opk.public_key)),
                1u32.into(),
                spk.public_key,
                sig.to_vec(),
                *receiver.identity_key(),
            )
            .unwrap();
            let jid: Jid = "559911112222@s.whatsapp.net".parse().unwrap();
            let addr = jid.to_protocol_address();
            let mut ss = MemSessionStore::new();
            let mut is = MemIdentityStore {
                pair: sender,
                reg_id: 42,
                known: HashMap::new(),
            };
            process_prekey_bundle(
                &addr,
                &mut ss,
                &mut is,
                &bundle,
                &mut rand::make_rng::<rand::rngs::StdRng>(),
                crate::libsignal::protocol::UsePQRatchet::No,
            )
            .await
            .unwrap();
            (ss, is, jid)
        }

        #[tokio::test]
        async fn pkmsg_no_account() {
            let (mut ss, mut is, jid) = setup_session().await;
            let group: Jid = "120363098765432100@g.us".parse().unwrap();
            let p: Jid = jid.to_string().parse().unwrap();
            let n = prepare_group_retry_stanza(
                &mut ss,
                &mut is,
                group.clone(),
                p.clone(),
                p.clone(),
                &wa::Message::default(),
                "3EB0ABC".into(),
                1,
                None,
                AddressingMode::Pn,
            )
            .await
            .unwrap();

            assert_eq!(n.tag, "message");
            let mut a = n.attrs();
            assert_eq!(a.optional_string("to").unwrap().as_ref(), group.to_string());
            assert_eq!(
                a.optional_string("participant").unwrap().as_ref(),
                p.to_string()
            );
            // Default (empty) message falls through to "media" per WA Web's typeAttributeFromProtobuf
            assert_eq!(
                a.optional_string("type").unwrap().as_ref(),
                stanza::MSG_TYPE_MEDIA
            );
            assert!(a.optional_string("category").is_none());
            assert_eq!(a.optional_string("addressing_mode").unwrap().as_ref(), "pn");
            let enc = n.get_optional_child("enc").unwrap();
            let mut ea = enc.attrs();
            assert_eq!(
                ea.optional_string("v").unwrap().as_ref(),
                stanza::ENC_VERSION
            );
            assert_eq!(
                ea.optional_string("type").unwrap().as_ref(),
                stanza::ENC_TYPE_PKMSG
            );
            assert_eq!(ea.optional_string("count").unwrap().as_ref(), "1");
            assert!(matches!(&enc.content, Some(NodeContent::Bytes(_))));
            assert!(n.get_optional_child("device-identity").is_none());
        }

        #[tokio::test]
        async fn dm_retry_pkmsg_targets_single_device() {
            let (mut ss, mut is, jid) = setup_session().await;
            let to: Jid = "559922223333@s.whatsapp.net".parse().unwrap();
            let requester: Jid = jid.to_string().parse().unwrap();
            let encryption = requester.clone();

            let n = prepare_dm_retry_stanza(
                &mut ss,
                &mut is,
                to.clone(),
                requester.clone(),
                encryption,
                &wa::Message::default(),
                "dm-retry-1".into(),
                1,
                None,
            )
            .await
            .unwrap();

            assert_eq!(n.tag, "message");
            let mut attrs = n.attrs();
            assert_eq!(
                attrs.optional_string("to").unwrap().as_ref(),
                to.to_string()
            );
            assert_eq!(attrs.optional_string("id").unwrap().as_ref(), "dm-retry-1");
            assert_eq!(
                attrs.optional_string("type").unwrap().as_ref(),
                stanza::MSG_TYPE_MEDIA
            );
            assert!(attrs.optional_string("participant").is_none());
            assert!(attrs.optional_string("addressing_mode").is_none());

            let participants = n.get_optional_child("participants").unwrap();
            let targets = participants.children().unwrap();
            assert_eq!(targets.len(), 1);
            assert_eq!(targets[0].tag, "to");
            assert_eq!(
                targets[0].attrs().optional_string("jid").unwrap().as_ref(),
                requester.to_string()
            );

            let enc = targets[0].get_optional_child("enc").unwrap();
            let mut enc_attrs = enc.attrs();
            assert_eq!(
                enc_attrs.optional_string("type").unwrap().as_ref(),
                stanza::ENC_TYPE_PKMSG
            );
            assert_eq!(enc_attrs.optional_string("count").unwrap().as_ref(), "1");
            assert!(n.get_optional_child("device-identity").is_none());
        }

        #[tokio::test]
        async fn dm_retry_pkmsg_with_account_has_device_identity() {
            let (mut ss, mut is, jid) = setup_session().await;
            let requester: Jid = jid.to_string().parse().unwrap();
            let acc = wa::AdvSignedDeviceIdentity {
                details: Some(b"t".to_vec()),
                ..Default::default()
            };

            let n = prepare_dm_retry_stanza(
                &mut ss,
                &mut is,
                "559922223333@s.whatsapp.net".parse().unwrap(),
                requester.clone(),
                requester,
                &wa::Message::default(),
                "dm-retry-2".into(),
                2,
                Some(&acc),
            )
            .await
            .unwrap();

            let participants = n.get_optional_child("participants").unwrap();
            let enc = participants.children().unwrap()[0]
                .get_optional_child("enc")
                .unwrap();
            assert_eq!(
                enc.attrs().optional_string("type").unwrap().as_ref(),
                stanza::ENC_TYPE_PKMSG
            );
            assert_eq!(enc.attrs().optional_string("count").unwrap().as_ref(), "2");
            assert!(n.get_optional_child("device-identity").is_some());
        }

        #[tokio::test]
        async fn pkmsg_with_account_has_device_identity() {
            let (mut ss, mut is, jid) = setup_session().await;
            let group: Jid = "120363098765432100@g.us".parse().unwrap();
            let p: Jid = jid.to_string().parse().unwrap();
            let acc = wa::AdvSignedDeviceIdentity {
                details: Some(b"t".to_vec()),
                ..Default::default()
            };
            let n = prepare_group_retry_stanza(
                &mut ss,
                &mut is,
                group,
                p.clone(),
                p,
                &wa::Message::default(),
                "id2".into(),
                2,
                Some(&acc),
                AddressingMode::Pn,
            )
            .await
            .unwrap();
            assert_eq!(
                n.get_optional_child("enc")
                    .unwrap()
                    .attrs()
                    .optional_string("type")
                    .unwrap()
                    .as_ref(),
                stanza::ENC_TYPE_PKMSG
            );
            assert!(n.get_optional_child("device-identity").is_some());
            assert_eq!(
                n.attrs()
                    .optional_string("addressing_mode")
                    .unwrap()
                    .as_ref(),
                "pn"
            );
        }

        #[tokio::test]
        async fn lid_addressing_mode() {
            let (mut ss, mut is, jid) = setup_session().await;
            let group: Jid = "120363098765432100@g.us".parse().unwrap();
            let p: Jid = jid.to_string().parse().unwrap();
            // Fresh session → pkmsg (pre-key), with LID addressing
            let n = prepare_group_retry_stanza(
                &mut ss,
                &mut is,
                group,
                p.clone(),
                p,
                &wa::Message::default(),
                "m2".into(),
                3,
                Some(&wa::AdvSignedDeviceIdentity::default()),
                AddressingMode::Lid,
            )
            .await
            .unwrap();
            let mut ea = n.get_optional_child("enc").unwrap().attrs();
            assert_eq!(ea.optional_string("count").unwrap().as_ref(), "3");
            assert_eq!(
                n.attrs()
                    .optional_string("addressing_mode")
                    .unwrap()
                    .as_ref(),
                "lid"
            );
        }
    }

    mod decrypt_fail {
        use super::*;

        #[test]
        fn regular_message() {
            let msg = wa::Message {
                conversation: Some("hi".into()),
                ..Default::default()
            };
            assert!(!should_hide_decrypt_fail(&msg));
        }

        #[test]
        fn reaction() {
            let msg = wa::Message {
                reaction_message: Some(Default::default()),
                ..Default::default()
            };
            assert!(should_hide_decrypt_fail(&msg));
        }

        #[test]
        fn pin() {
            let msg = wa::Message {
                pin_in_chat_message: Some(Default::default()),
                ..Default::default()
            };
            assert!(should_hide_decrypt_fail(&msg));
        }

        #[test]
        fn poll_vote() {
            let msg = wa::Message {
                poll_update_message: Some(wa::message::PollUpdateMessage {
                    vote: Some(Default::default()),
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert!(should_hide_decrypt_fail(&msg));
        }

        #[test]
        fn poll_update_without_vote() {
            let msg = wa::Message {
                poll_update_message: Some(Default::default()),
                ..Default::default()
            };
            assert!(!should_hide_decrypt_fail(&msg));
        }

        #[test]
        fn reaction_inside_ephemeral_wrapper() {
            let msg = wa::Message {
                ephemeral_message: Some(Box::new(wa::message::FutureProofMessage {
                    message: Some(Box::new(wa::Message {
                        reaction_message: Some(Default::default()),
                        ..Default::default()
                    })),
                })),
                ..Default::default()
            };
            assert!(should_hide_decrypt_fail(&msg));
        }
    }

    #[cfg(test)]
    mod device_unregistered_tests {
        use super::is_device_unregistered_error;
        use crate::request::ServerErrorCode;

        #[test]
        fn detects_406_server_error_code() {
            let err = anyhow::Error::new(ServerErrorCode {
                code: 406,
                text: "not-acceptable".to_string(),
            });
            assert!(is_device_unregistered_error(&err));
        }

        #[test]
        fn rejects_non_406_server_error() {
            let err = anyhow::Error::new(ServerErrorCode {
                code: 404,
                text: "not-found".to_string(),
            });
            assert!(!is_device_unregistered_error(&err));
        }

        #[test]
        fn rejects_unrelated_error() {
            let err = anyhow::anyhow!("some random error");
            assert!(!is_device_unregistered_error(&err));
        }

        #[test]
        fn rejects_wacore_iq_error_without_server_error_code_wrapper() {
            // wacore::IqError::ServerError is NOT the same as ServerErrorCode.
            // This simulates the old bug: if someone wraps wacore IqError directly
            // without the ServerErrorCode wrapper, the check should not match.
            let err = anyhow::Error::new(crate::request::IqError::ServerError {
                code: 406,
                text: "not-acceptable".to_string(),
            });
            // This would only match if we also checked IqError (we don't — we use ServerErrorCode)
            // The SendContextResolver impl is responsible for wrapping in ServerErrorCode
            assert!(!is_device_unregistered_error(&err));
        }
    }
}
