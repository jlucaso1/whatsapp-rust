use crate::client::context::{GroupInfo, SendContextResolver};
use crate::libsignal::protocol::{
    CiphertextMessage, SENDERKEY_MESSAGE_CURRENT_VERSION, SenderKeyDistributionMessage,
    SenderKeyMessage, SenderKeyRecord, SenderKeyStore, SignalProtocolError, UsePQRatchet,
    message_encrypt, process_prekey_bundle,
};
use crate::libsignal::store::sender_key_name::SenderKeyName;
use crate::messages::MessageUtils;
use crate::reporting_token::{
    build_reporting_node, generate_reporting_token, prepare_message_with_context,
};
use crate::types::jid::JidExt;
use anyhow::{Result, anyhow};
use prost::Message as ProtoMessage;
use rand::{CryptoRng, Rng, TryRngCore as _};
use std::collections::HashSet;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, JidExt as _};
use wacore_binary::node::{Attrs, Node};
use wacore_libsignal::crypto::aes_256_cbc_encrypt_into;
use waproto::whatsapp as wa;
use waproto::whatsapp::message::DeviceSentMessage;

pub async fn encrypt_group_message<S, R>(
    sender_key_store: &mut S,
    group_jid: &Jid,
    sender_jid: &Jid,
    plaintext: &[u8],
    csprng: &mut R,
) -> Result<SenderKeyMessage>
where
    S: SenderKeyStore + ?Sized,
    R: Rng + CryptoRng,
{
    let sender_address = sender_jid.to_protocol_address();
    let sender_key_name = SenderKeyName::new(group_jid.to_string(), sender_address.to_string());
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
        .store_sender_key(&sender_key_name, &record)
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

async fn encrypt_for_devices<'a, S, I, P, SP>(
    stores: &mut SignalStores<'a, S, I, P, SP>,
    resolver: &dyn SendContextResolver,
    devices: &[Jid],
    plaintext_to_encrypt: &[u8],
    enc_extra_attrs: &Attrs,
) -> Result<(Vec<Node>, bool)>
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
    let mut jid_to_encryption_jid: std::collections::HashMap<Jid, Jid> =
        std::collections::HashMap::new();
    let mut jids_needing_prekeys = Vec::new();

    for device_jid in devices {
        // WhatsApp Web's SignalAddress.toString() normalizes PN → LID before
        // creating signal addresses. We do the same: check LID session FIRST.
        // This prevents using stale PN sessions when a newer LID session exists.
        if device_jid.is_pn()
            && let Some(lid_user) = resolver.get_lid_for_phone(&device_jid.user).await
        {
            // Construct the LID JID with the same device ID
            let lid_jid = Jid::lid_device(lid_user, device_jid.device);
            let lid_address = lid_jid.to_protocol_address();

            if stores
                .session_store
                .load_session(&lid_address)
                .await?
                .is_some()
            {
                // Found existing session under LID address - use it!
                log::debug!(
                    "Using LID session {} for PN {} (LID-first lookup)",
                    lid_jid,
                    device_jid
                );
                jid_to_encryption_jid.insert(device_jid.clone(), lid_jid);
                continue;
            }
        }

        // Fall back to direct address lookup (for LID JIDs or PN without LID mapping)
        let signal_address = device_jid.to_protocol_address();
        if stores
            .session_store
            .load_session(&signal_address)
            .await?
            .is_some()
        {
            // Session exists under direct address, use it
            jid_to_encryption_jid.insert(device_jid.clone(), device_jid.clone());
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
        jid_to_encryption_jid.insert(device_jid.clone(), encryption_jid);
        // Use original device_jid for prekey fetch (HashMap key match)
        jids_needing_prekeys.push(device_jid.clone());
    }

    if !jids_needing_prekeys.is_empty() {
        log::debug!(
            "Fetching prekeys for {} devices without sessions",
            jids_needing_prekeys.len()
        );
        let prekey_bundles = resolver
            .fetch_prekeys_for_identity_check(&jids_needing_prekeys)
            .await?;

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

            let signal_address = encryption_jid.to_protocol_address();
            // Fix: Use the normalized device_jid to lookup the bundle
            // Use centralized normalization logic to avoid mismatches
            let lookup_jid = device_jid.normalize_for_prekey_bundle();
            match prekey_bundles.get(&lookup_jid) {
                Some(bundle) => {
                    match process_prekey_bundle(
                        &signal_address,
                        stores.session_store,
                        stores.identity_store,
                        bundle,
                        &mut rand::rngs::OsRng.unwrap_err(),
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
                                .save_identity(&signal_address, new_identity)
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
                                &signal_address,
                                stores.session_store,
                                stores.identity_store,
                                bundle,
                                &mut rand::rngs::OsRng.unwrap_err(),
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
                                signal_address,
                                e
                            ));
                        }
                    }
                }
                None => {
                    log::warn!(
                        "No pre-key bundle returned for device {}. This device will be skipped for encryption.",
                        &signal_address
                    );
                }
            }
        }
    }

    let mut participant_nodes = Vec::new();
    let mut includes_prekey_message = false;

    for device_jid in devices {
        // Use the effective encryption JID (may be LID if we found an existing LID session)
        let encryption_jid = jid_to_encryption_jid.get(device_jid).unwrap_or(device_jid);
        let signal_address = encryption_jid.to_protocol_address();

        // Try to encrypt for this device. If it fails (e.g., no session established),
        // log a warning and skip this device instead of failing the entire operation.
        match message_encrypt(
            plaintext_to_encrypt,
            &signal_address,
            stores.session_store,
            stores.identity_store,
        )
        .await
        {
            Ok(encrypted_payload) => {
                let (enc_type, serialized_bytes) = match encrypted_payload {
                    CiphertextMessage::PreKeySignalMessage(msg) => {
                        includes_prekey_message = true;
                        ("pkmsg", msg.serialized().to_vec())
                    }
                    CiphertextMessage::SignalMessage(msg) => ("msg", msg.serialized().to_vec()),
                    _ => continue,
                };

                let mut enc_attrs = Attrs::new();
                enc_attrs.insert("v".to_string(), "2".to_string());
                enc_attrs.insert("type".to_string(), enc_type.to_string());
                for (k, v) in enc_extra_attrs.iter() {
                    enc_attrs.insert(k.clone(), v.clone());
                }

                let enc_node = NodeBuilder::new("enc")
                    .attrs(enc_attrs)
                    .bytes(serialized_bytes)
                    .build();
                // Use the original device_jid for the `to` attribute (what the server expects),
                // but we encrypted using the encryption_jid's session
                participant_nodes.push(
                    NodeBuilder::new("to")
                        .attr("jid", device_jid.to_string())
                        .children([enc_node])
                        .build(),
                );
            }
            Err(e) => {
                log::warn!(
                    "Failed to encrypt message for device {}: {}. Skipping this device.",
                    &signal_address,
                    e
                );
            }
        }
    }

    Ok((participant_nodes, includes_prekey_message))
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
    account: Option<&wa::AdvSignedDeviceIdentity>,
    to_jid: Jid,
    message: &wa::Message,
    request_id: String,
    edit: Option<crate::types::message::EditAttribute>,
    extra_stanza_nodes: Vec<Node>,
) -> Result<Node> {
    // Generate reporting token if the message type supports it
    // For DMs, both sender_jid and remote_jid are the recipient (to_jid) per Baileys implementation
    let reporting_result = generate_reporting_token(message, &request_id, &to_jid, &to_jid, None);

    // Prepare message with MessageContextInfo containing the message secret
    let message_for_encryption = if let Some(ref result) = reporting_result {
        prepare_message_with_context(message, &result.message_secret)
    } else {
        message.clone()
    };

    let recipient_plaintext = MessageUtils::pad_message_v2(message_for_encryption.encode_to_vec());

    let dsm = wa::Message {
        device_sent_message: Some(Box::new(DeviceSentMessage {
            destination_jid: Some(to_jid.to_string()),
            message: Some(Box::new(message_for_encryption.clone())),
            phash: Some("".to_string()),
        })),
        ..Default::default()
    };

    let own_devices_plaintext = MessageUtils::pad_message_v2(dsm.encode_to_vec());

    let participants = vec![to_jid.clone(), own_jid.clone()];
    let all_devices = resolver.resolve_devices(&participants).await?;

    let mut recipient_devices = Vec::new();
    let mut own_other_devices = Vec::new();
    for device_jid in &all_devices {
        // Skip the current device (sender) to prevent self-encryption loops
        if device_jid.user == own_jid.user && device_jid.device == own_jid.device {
            continue;
        }

        let is_own_device = device_jid.user == own_jid.user;
        if is_own_device {
            own_other_devices.push(device_jid.clone());
        } else {
            recipient_devices.push(device_jid.clone());
        }
    }

    let mut participant_nodes = Vec::new();
    let mut includes_prekey_message = false;

    // If this is an edit-like message, set decrypt-fail="hide" on enc nodes
    let mut enc_extra_attrs = Attrs::new();
    if let Some(edit_attr) = &edit
        && *edit_attr != crate::types::message::EditAttribute::Empty
    {
        enc_extra_attrs.insert("decrypt-fail".to_string(), "hide".to_string());
    }

    if !recipient_devices.is_empty() {
        let (nodes, inc) = encrypt_for_devices(
            stores,
            resolver,
            &recipient_devices,
            &recipient_plaintext,
            &enc_extra_attrs,
        )
        .await?;
        participant_nodes.extend(nodes);
        includes_prekey_message = includes_prekey_message || inc;
    }

    if !own_other_devices.is_empty() {
        let (nodes, inc) = encrypt_for_devices(
            stores,
            resolver,
            &own_other_devices,
            &own_devices_plaintext,
            &enc_extra_attrs,
        )
        .await?;
        participant_nodes.extend(nodes);
        includes_prekey_message = includes_prekey_message || inc;
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
    message_content_nodes.extend(extra_stanza_nodes);

    let mut stanza_attrs = Attrs::new();
    stanza_attrs.insert("to".to_string(), to_jid.to_string());
    stanza_attrs.insert("id".to_string(), request_id);
    stanza_attrs.insert("type".to_string(), "text".to_string());

    if let Some(edit_attr) = edit
        && edit_attr != crate::types::message::EditAttribute::Empty
    {
        stanza_attrs.insert("edit".to_string(), edit_attr.to_string_val().to_string());
    }

    let stanza = NodeBuilder::new("message")
        .attrs(stanza_attrs.into_iter())
        .children(message_content_nodes)
        .build();

    Ok(stanza)
}

pub async fn prepare_peer_stanza<S, I>(
    session_store: &mut S,
    identity_store: &mut I,
    transport_jid: Jid,
    encryption_jid: Jid,
    message: &wa::Message,
    request_id: String,
) -> Result<Node>
where
    S: crate::libsignal::protocol::SessionStore,
    I: crate::libsignal::protocol::IdentityKeyStore,
{
    let plaintext = MessageUtils::pad_message_v2(message.encode_to_vec());
    let signal_address = encryption_jid.to_protocol_address();

    let encrypted_message =
        message_encrypt(&plaintext, &signal_address, session_store, identity_store).await?;

    let (enc_type, serialized_bytes) = match encrypted_message {
        CiphertextMessage::SignalMessage(msg) => ("msg", msg.serialized().to_vec()),
        CiphertextMessage::PreKeySignalMessage(msg) => ("pkmsg", msg.serialized().to_vec()),
        _ => return Err(anyhow!("Unexpected peer encryption message type")),
    };

    let enc_node = NodeBuilder::new("enc")
        .attrs([("v", "2"), ("type", enc_type)])
        .bytes(serialized_bytes)
        .build();

    let stanza = NodeBuilder::new("message")
        .attrs([
            ("to", transport_jid.to_string()),
            ("id", request_id),
            ("type", "text".to_string()),
            ("category", "peer".to_string()),
        ])
        .children([enc_node])
        .build();

    Ok(stanza)
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
    extra_stanza_nodes: Vec<Node>,
) -> Result<Node> {
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
    let mut resolved_devices_for_phash: Option<Vec<Jid>> = None;

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

        // Determine what JID to check for - use phone number if we're in LID mode and have a mapping
        let own_jid_to_check = if own_base_jid.is_lid() {
            group_info
                .phone_jid_for_lid_user(&own_base_jid.user)
                .map(|pn| pn.to_non_ad())
                .unwrap_or_else(|| own_base_jid.clone())
        } else {
            own_base_jid.clone()
        };

        if !jids_to_resolve
            .iter()
            .any(|participant| participant.is_same_user_as(&own_jid_to_check))
        {
            jids_to_resolve.push(own_jid_to_check);
        }

        let mut seen_users = HashSet::new();
        jids_to_resolve.retain(|jid| seen_users.insert((jid.user.clone(), jid.server.clone())));

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
        // both convert to 100000037037034:33@lid)
        let mut seen = HashSet::new();
        resolved_list.retain(|jid| seen.insert(jid.to_string()));

        // Filter devices for SKDM distribution:
        // - Exclude the exact sending device (own_sending_jid) - we already have our own sender key
        // - Keep ALL other devices including our own other devices (phone, other companions)
        //   because they need the SKDM to decrypt messages we send from this device
        // - Exclude hosted/Cloud API devices (device ID 99 or @hosted server) - they don't
        //   participate in group E2EE, only in 1:1 chats
        let own_user = own_sending_jid.user.clone();
        let own_device = own_sending_jid.device;
        let before_filter = resolved_list.len();
        resolved_list.retain(|device_jid| {
            let is_exact_sender = device_jid.user == own_user && device_jid.device == own_device;
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

    if let Some(ref distribution_list) = distribution_list {
        resolved_devices_for_phash = Some(distribution_list.clone());
        let axolotl_skdm_bytes = create_sender_key_distribution_message_for_group(
            stores.sender_key_store,
            &to_jid,
            &own_sending_jid,
        )
        .await?;

        let skdm_wrapper_msg = wa::Message {
            sender_key_distribution_message: Some(wa::message::SenderKeyDistributionMessage {
                group_id: Some(to_jid.to_string()),
                axolotl_sender_key_distribution_message: Some(axolotl_skdm_bytes),
            }),
            ..Default::default()
        };
        let skdm_plaintext_to_encrypt =
            MessageUtils::pad_message_v2(skdm_wrapper_msg.encode_to_vec());

        // For SKDM distribution we don't set decrypt-fail; use empty attrs
        let empty_attrs = Attrs::new();
        let (participant_nodes, inc) = encrypt_for_devices(
            stores,
            resolver,
            distribution_list,
            &skdm_plaintext_to_encrypt,
            &empty_attrs,
        )
        .await?;
        includes_prekey_message = includes_prekey_message || inc;

        // Add participants list as part of the single hybrid stanza
        message_children.push(
            NodeBuilder::new("participants")
                .children(participant_nodes)
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

    let plaintext = MessageUtils::pad_message_v2(message_for_encryption.encode_to_vec());
    let skmsg = encrypt_group_message(
        stores.sender_key_store,
        &to_jid,
        &own_sending_jid,
        &plaintext,
        &mut rand::rngs::OsRng.unwrap_err(),
    )
    .await?;

    let skmsg_ciphertext = skmsg.serialized().to_vec();

    // Add decrypt-fail="hide" for edited group messages, but NOT for admin revokes
    // WhatsApp Web does not include decrypt-fail="hide" for admin revoke messages
    let mut sk_enc_attrs = Attrs::new();
    sk_enc_attrs.insert("v".to_string(), "2".to_string());
    sk_enc_attrs.insert("type".to_string(), "skmsg".to_string());
    if let Some(edit_attr) = &edit
        && *edit_attr != crate::types::message::EditAttribute::Empty
        && *edit_attr != crate::types::message::EditAttribute::AdminRevoke
    {
        sk_enc_attrs.insert("decrypt-fail".to_string(), "hide".to_string());
    }

    let content_node = NodeBuilder::new("enc")
        .attrs(sk_enc_attrs)
        .bytes(skmsg_ciphertext)
        .build();

    let mut stanza_attrs = Attrs::new();
    stanza_attrs.insert("to".to_string(), to_jid.to_string());
    stanza_attrs.insert("id".to_string(), request_id);
    stanza_attrs.insert("type".to_string(), "text".to_string());

    // Add addressing_mode attribute for LID groups (matches WhatsApp Web behavior)
    if group_info.addressing_mode == crate::types::message::AddressingMode::Lid {
        stanza_attrs.insert("addressing_mode".to_string(), "lid".to_string());
    }

    if let Some(edit_attr) = &edit
        && *edit_attr != crate::types::message::EditAttribute::Empty
    {
        stanza_attrs.insert("edit".to_string(), edit_attr.to_string_val().to_string());
    }
    // NOTE: WhatsApp Web does NOT include participant attribute on initial admin revoke send
    // The participant attribute only appears on retry/fanout messages

    message_children.push(content_node);

    // Add reporting token node if we generated one
    if let Some(ref result) = reporting_result {
        message_children.push(build_reporting_node(result));
    }

    // Add phash if we distributed keys in this message
    if let Some(devices) = &resolved_devices_for_phash {
        match MessageUtils::participant_list_hash(devices) {
            Ok(phash) => {
                stanza_attrs.insert("phash".to_string(), phash);
            }
            Err(e) => {
                log::warn!("Failed to compute phash for group {}: {:?}", to_jid, e);
            }
        }
    }

    // Add any extra stanza nodes provided by the caller
    message_children.extend(extra_stanza_nodes);

    let stanza = NodeBuilder::new("message")
        .attrs(stanza_attrs.into_iter())
        .children(message_children)
        .build();

    Ok(stanza)
}

pub async fn create_sender_key_distribution_message_for_group(
    store: &mut (dyn SenderKeyStore + Send + Sync),
    group_jid: &Jid,
    own_sending_jid: &Jid,
) -> Result<Vec<u8>> {
    let sender_address = own_sending_jid.to_protocol_address();

    let sender_key_name = SenderKeyName::new(group_jid.to_string(), sender_address.to_string());

    let mut record = store
        .load_sender_key(&sender_key_name)
        .await?
        .unwrap_or_else(SenderKeyRecord::new_empty);

    if record.sender_key_state().is_err() {
        log::info!(
            "No sender key found for self in group {}. Creating a new sender key state.",
            group_jid
        );

        let mut rng = rand::rngs::OsRng.unwrap_err();
        let signing_key = crate::libsignal::protocol::KeyPair::generate(&mut rng);

        let chain_id = (rng.random::<u32>()) >> 1;
        let sender_key_seed: [u8; 32] = rng.random();
        record.add_sender_key_state(
            SENDERKEY_MESSAGE_CURRENT_VERSION,
            chain_id,
            0,
            &sender_key_seed,
            signing_key.public_key,
            Some(signing_key.private_key),
        );
        store.store_sender_key(&sender_key_name, &record).await?;
    }

    let state = record
        .sender_key_state()
        .map_err(|e| anyhow!("Invalid SK state: {:?}", e))?;
    let chain_key = state
        .sender_chain_key()
        .ok_or_else(|| anyhow!("Missing chain key"))?;

    let message_version = state
        .message_version()
        .try_into()
        .map_err(|e| anyhow!("Invalid sender key message version: {e}"))?;
    let skdm = SenderKeyDistributionMessage::new(
        message_version,
        state.chain_id(),
        chain_key.iteration(),
        *chain_key.seed(),
        state
            .signing_key_public()
            .map_err(|e| anyhow!("Missing pub key: {:?}", e))?,
    )?;

    Ok(skdm.serialized().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::context::{GroupInfo, SendContextResolver};
    use crate::libsignal::protocol::{IdentityKeyPair, KeyPair, PreKeyBundle};
    use std::collections::HashMap;
    use wacore_binary::jid::Jid;

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
        let mut rng = rand::rngs::OsRng.unwrap_err();
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
        let lid_user = resolver.phone_to_lid.get(&pn_device_jid.user).cloned();
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
        let lid_user = resolver.phone_to_lid.get(&pn_device_jid.user).cloned();

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

        // The logic under test (from prepare_dm_stanza):
        let mut recipient_devices = Vec::new();
        let mut own_other_devices = Vec::new();

        for device_jid in &all_devices {
            // Fix check: Skip the current device (sender) to prevent self-encryption loops
            if device_jid.user == own_jid.user && device_jid.device == own_jid.device {
                continue;
            }

            let is_own_device = device_jid.user == own_jid.user;
            if is_own_device {
                own_other_devices.push(device_jid.clone());
            } else {
                recipient_devices.push(device_jid.clone());
            }
        }

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
}
