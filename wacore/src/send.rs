use crate::client::context::{GroupInfo, SendContextResolver};
use crate::libsignal::protocol::{
    aes_256_cbc_encrypt, message_encrypt, process_prekey_bundle, CiphertextMessage, SessionStore,
    SENDERKEY_MESSAGE_CURRENT_VERSION, SenderKeyDistributionMessage, SenderKeyMessage,
    SenderKeyRecord, SenderKeyStore, SignalProtocolError, UsePQRatchet,
};
use crate::libsignal::store::sender_key_name::SenderKeyName;
use crate::messages::MessageUtils;
use crate::store::SignalProtocolStoreAdapter;
use crate::types::jid::JidExt;
use anyhow::{anyhow, Result};
use futures::future;
use prost::Message as ProtoMessage;
use rand::{CryptoRng, Rng, TryRngCore as _};
use std::collections::HashSet;
use std::time::SystemTime;
use tokio::task;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, JidExt as _};
use wacore_binary::node::{Attrs, Node};
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
        .ok_or(SignalProtocolError::NoSenderKeyState)?;

    let sender_key_state = record
        .sender_key_state_mut()
        .map_err(|e| anyhow!("Invalid SenderKey session: {:?}", e))?;

    let sender_chain_key = sender_key_state
        .sender_chain_key()
        .ok_or_else(|| anyhow!("Invalid SenderKey session: missing chain key"))?;

    let message_keys = sender_chain_key.sender_message_key();

    let ciphertext = aes_256_cbc_encrypt(plaintext, message_keys.cipher_key(), message_keys.iv())
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


#[allow(clippy::too_many_arguments)]
pub async fn prepare_dm_stanza(
    mut stores: SignalProtocolStoreAdapter,
    resolver: &dyn SendContextResolver,
    own_jid: &Jid,
    account: Option<&wa::AdvSignedDeviceIdentity>,
    to_jid: Jid,
    message: &wa::Message,
    request_id: String,
    edit: Option<crate::types::message::EditAttribute>,
) -> Result<Node> {
    let recipient_plaintext = message.encode_to_vec();

    let dsm = wa::Message {
        device_sent_message: Some(Box::new(DeviceSentMessage {
            destination_jid: Some(to_jid.to_string()),
            message: Some(Box::new(message.clone())),
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
        let is_own_device = device_jid.user == own_jid.user && device_jid.device != own_jid.device;
        if is_own_device {
            own_other_devices.push(device_jid.clone());
        } else {
            recipient_devices.push(device_jid.clone());
        }
    }
    // If this is an edit-like message, set decrypt-fail="hide" on enc nodes
    let mut enc_extra_attrs = Attrs::new();
    if let Some(edit_attr) = &edit
        && *edit_attr != crate::types::message::EditAttribute::Empty
    {
        enc_extra_attrs.insert("decrypt-fail".to_string(), "hide".to_string());
    }

    let mut jids_needing_prekeys = Vec::new();
    for device_jid in &all_devices {
        let signal_address = device_jid.to_protocol_address();
        if stores
            .session_store
            .load_session(&signal_address)
            .await?
            .is_none()
        {
            jids_needing_prekeys.push(device_jid.clone());
        }
    }

    if !jids_needing_prekeys.is_empty() {
        log::info!(
            "Fetching prekeys for devices without sessions: {:?}",
            jids_needing_prekeys
        );
        let prekey_bundles = resolver
            .fetch_prekeys_for_identity_check(&jids_needing_prekeys)
            .await?;

        for device_jid in &jids_needing_prekeys {
            let signal_address = device_jid.to_protocol_address();
            let bundle = prekey_bundles
                .get(device_jid)
                .ok_or_else(|| anyhow!("Failed to fetch pre-key bundle for {}", &signal_address))?;
            process_prekey_bundle(
                &signal_address,
                &mut stores.session_store,
                &mut stores.identity_store,
                bundle,
                SystemTime::now(),
                &mut rand::rngs::OsRng.unwrap_err(),
                UsePQRatchet::No,
            )
            .await?;
        }
    }

    let mut tasks = Vec::new();

    for device_jid in recipient_devices {
        let mut task_stores = stores.clone();
        let task_plaintext = recipient_plaintext.clone();
        let signal_address = device_jid.to_protocol_address();
        let task_extra_attrs = enc_extra_attrs.clone();

        tasks.push(task::spawn(async move {
            let encrypted_payload = message_encrypt(
                &task_plaintext,
                &signal_address,
                &mut task_stores.session_store,
                &mut task_stores.identity_store,
                SystemTime::now(),
            )
            .await?;

            let (enc_type, serialized_bytes) = match encrypted_payload {
                CiphertextMessage::PreKeySignalMessage(msg) => ("pkmsg", msg.serialized().to_vec()),
                CiphertextMessage::SignalMessage(msg) => ("msg", msg.serialized().to_vec()),
                _ => return Err(anyhow::anyhow!("Unexpected encryption message type for DM")),
            };

            let mut enc_attrs = Attrs::new();
            enc_attrs.insert("v".to_string(), "2".to_string());
            enc_attrs.insert("type".to_string(), enc_type.to_string());
            for (k, v) in task_extra_attrs.iter() {
                enc_attrs.insert(k.clone(), v.clone());
            }

            let enc_node = NodeBuilder::new("enc")
                .attrs(enc_attrs)
                .bytes(serialized_bytes)
                .build();
            let participant_node = NodeBuilder::new("to")
                .attr("jid", device_jid.to_string())
                .children([enc_node])
                .build();
            Ok::<(Node, bool), anyhow::Error>((participant_node, enc_type == "pkmsg"))
        }));
    }

    for device_jid in own_other_devices {
        let mut task_stores = stores.clone();
        let task_plaintext = own_devices_plaintext.clone();
        let signal_address = device_jid.to_protocol_address();
        let task_extra_attrs = enc_extra_attrs.clone();

        tasks.push(task::spawn(async move {
            let encrypted_payload = message_encrypt(
                &task_plaintext,
                &signal_address,
                &mut task_stores.session_store,
                &mut task_stores.identity_store,
                SystemTime::now(),
            )
            .await?;

            let (enc_type, serialized_bytes) = match encrypted_payload {
                CiphertextMessage::PreKeySignalMessage(msg) => ("pkmsg", msg.serialized().to_vec()),
                CiphertextMessage::SignalMessage(msg) => ("msg", msg.serialized().to_vec()),
                _ => return Err(anyhow::anyhow!("Unexpected encryption message type for DM")),
            };

            let mut enc_attrs = Attrs::new();
            enc_attrs.insert("v".to_string(), "2".to_string());
            enc_attrs.insert("type".to_string(), enc_type.to_string());
            for (k, v) in task_extra_attrs.iter() {
                enc_attrs.insert(k.clone(), v.clone());
            }

            let enc_node = NodeBuilder::new("enc")
                .attrs(enc_attrs)
                .bytes(serialized_bytes)
                .build();
            let participant_node = NodeBuilder::new("to")
                .attr("jid", device_jid.to_string())
                .children([enc_node])
                .build();
            Ok::<(Node, bool), anyhow::Error>((participant_node, enc_type == "pkmsg"))
        }));
    }

    let results = future::join_all(tasks).await;
    let mut participant_nodes = Vec::new();
    let mut includes_prekey_message = false;
    for result in results {
        match result {
            Ok(Ok((node, uses_prekey))) => {
                participant_nodes.push(node);
                if uses_prekey {
                    includes_prekey_message = true;
                }
            }
            Ok(Err(e)) => return Err(anyhow!("An encryption task for DM failed: {}", e)),
            Err(e) => return Err(anyhow!("A tokio task for DM panicked: {}", e)),
        }
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
    to_jid: Jid,
    message: &wa::Message,
    request_id: String,
) -> Result<Node>
where
    S: crate::libsignal::protocol::SessionStore,
    I: crate::libsignal::protocol::IdentityKeyStore,
{
    let plaintext = MessageUtils::pad_message_v2(message.encode_to_vec());
    let signal_address = to_jid.to_protocol_address();

    let encrypted_message = message_encrypt(
        &plaintext,
        &signal_address,
        session_store,
        identity_store,
        SystemTime::now(),
    )
    .await?;

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
            ("to", to_jid.to_string()),
            ("id", request_id),
            ("type", "text".to_string()),
            ("category", "peer".to_string()),
        ])
        .children([enc_node])
        .build();

    Ok(stanza)
}

#[allow(clippy::too_many_arguments)]
pub async fn prepare_group_stanza(
    mut stores: SignalProtocolStoreAdapter,
    resolver: &dyn SendContextResolver,
    group_info: &mut GroupInfo,
    own_jid: &Jid,
    own_lid: &Jid,
    account: Option<&wa::AdvSignedDeviceIdentity>,
    to_jid: Jid,
    message: &wa::Message,
    request_id: String,
    force_skdm_distribution: bool,
    edit: Option<crate::types::message::EditAttribute>,
) -> Result<Node> {
    let (own_sending_jid, _) = match group_info.addressing_mode {
        crate::types::message::AddressingMode::Lid => (own_lid.clone(), "lid"),
        crate::types::message::AddressingMode::Pn => (own_jid.clone(), "pn"),
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

    if force_skdm_distribution {
        let expected_server = own_sending_jid.server.clone();
        let mut jids_to_resolve: Vec<Jid> = group_info
            .participants
            .iter()
            .map(|jid| {
                let mut base = jid.to_non_ad();
                if group_info.addressing_mode == crate::types::message::AddressingMode::Lid {
                    base.server = expected_server.clone();
                }
                base
            })
            .filter(|jid| {
                if group_info.addressing_mode == crate::types::message::AddressingMode::Lid {
                    jid.server == expected_server
                } else {
                    true
                }
            })
            .collect();
        if !jids_to_resolve
            .iter()
            .any(|participant| participant.is_same_user_as(&own_base_jid))
        {
            jids_to_resolve.push(own_base_jid.clone());
        }

        let mut seen_users = HashSet::new();
        jids_to_resolve.retain(|jid| seen_users.insert((jid.user.clone(), jid.server.clone())));

        log::info!("Resolving devices for participants: {:?}", jids_to_resolve);

        let mut distribution_list = resolver.resolve_devices(&jids_to_resolve).await?;

        let mut seen = HashSet::new();
        distribution_list.retain(|jid| seen.insert(jid.to_string()));

        log::info!(
            "SKDM distribution list for {} resolved to {} devices: {:?}",
            to_jid,
            distribution_list.len(),
            distribution_list
        );

        resolved_devices_for_phash = Some(distribution_list.clone());
        let axolotl_skdm_bytes = create_sender_key_distribution_message_for_group(
            &mut stores.sender_key_store,
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
        let mut jids_needing_prekeys = Vec::new();
        for device_jid in &distribution_list {
            let signal_address = device_jid.to_protocol_address();
            if stores
                .session_store
                .load_session(&signal_address)
                .await?
                .is_none()
            {
                jids_needing_prekeys.push(device_jid.clone());
            }
        }

        if !jids_needing_prekeys.is_empty() {
            log::info!(
                "Fetching prekeys for devices without sessions: {:?}",
                jids_needing_prekeys
            );
            let prekey_bundles = resolver
                .fetch_prekeys_for_identity_check(&jids_needing_prekeys)
                .await?;

            for device_jid in &jids_needing_prekeys {
                let signal_address = device_jid.to_protocol_address();
                let bundle = prekey_bundles.get(device_jid).ok_or_else(|| {
                    anyhow!("Failed to fetch pre-key bundle for {}", &signal_address)
                })?;
                process_prekey_bundle(
                    &signal_address,
                    &mut stores.session_store,
                    &mut stores.identity_store,
                    bundle,
                    SystemTime::now(),
                    &mut rand::rngs::OsRng.unwrap_err(),
                    UsePQRatchet::No,
                )
                .await?;
            }
        }

        let mut tasks = Vec::new();
        for device_jid in distribution_list {
            let mut task_stores = stores.clone();
            let task_plaintext = skdm_plaintext_to_encrypt.clone();
            let signal_address = device_jid.to_protocol_address();

            tasks.push(task::spawn(async move {
                let encrypted_payload = message_encrypt(
                    &task_plaintext,
                    &signal_address,
                    &mut task_stores.session_store,
                    &mut task_stores.identity_store,
                    SystemTime::now(),
                )
                .await?;

                let (enc_type, serialized_bytes) = match encrypted_payload {
                    CiphertextMessage::PreKeySignalMessage(msg) => {
                        ("pkmsg", msg.serialized().to_vec())
                    }
                    CiphertextMessage::SignalMessage(msg) => ("msg", msg.serialized().to_vec()),
                    _ => {
                        return Err(anyhow::anyhow!(
                            "Unexpected encryption message type for SKDM"
                        ))
                    }
                };

                let enc_node = NodeBuilder::new("enc")
                    .attrs([("v", "2"), ("type", enc_type)])
                    .bytes(serialized_bytes)
                    .build();

                let participant_node = NodeBuilder::new("to")
                    .attr("jid", device_jid.to_string())
                    .children([enc_node])
                    .build();

                Ok::<(Node, bool), anyhow::Error>((participant_node, enc_type == "pkmsg"))
            }));
        }

        let results = future::join_all(tasks).await;
        let mut participant_nodes = Vec::new();
        for result in results {
            match result {
                Ok(Ok((node, uses_prekey))) => {
                    participant_nodes.push(node);
                    if uses_prekey {
                        includes_prekey_message = true;
                    }
                }
                Ok(Err(e)) => return Err(anyhow!("An encryption task for SKDM failed: {}", e)),
                Err(e) => return Err(anyhow!("A tokio task for SKDM panicked: {}", e)),
            }
        }

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

    let plaintext = MessageUtils::pad_message_v2(message.encode_to_vec());
    let skmsg = encrypt_group_message(
        &mut stores.sender_key_store,
        &to_jid,
        &own_sending_jid,
        &plaintext,
        &mut rand::rngs::OsRng.unwrap_err(),
    )
    .await?;

    let skmsg_ciphertext = skmsg.serialized().to_vec();

    // Add decrypt-fail="hide" for edited group messages too
    let mut sk_enc_attrs = Attrs::new();
    sk_enc_attrs.insert("v".to_string(), "2".to_string());
    sk_enc_attrs.insert("type".to_string(), "skmsg".to_string());
    if let Some(edit_attr) = &edit
        && *edit_attr != crate::types::message::EditAttribute::Empty
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

    if let Some(edit_attr) = edit
        && edit_attr != crate::types::message::EditAttribute::Empty
    {
        stanza_attrs.insert("edit".to_string(), edit_attr.to_string_val().to_string());
    }

    message_children.push(content_node);

    // Add phash if we distributed keys in this message
    if let Some(devices) = &resolved_devices_for_phash {
        let phash = MessageUtils::participant_list_hash(devices);
        stanza_attrs.insert("phash".to_string(), phash);
    }

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

    let skdm = SenderKeyDistributionMessage::new(
        state.message_version().try_into().unwrap(),
        state.chain_id(),
        chain_key.iteration(),
        chain_key.seed().to_vec(),
        state
            .signing_key_public()
            .map_err(|e| anyhow!("Missing pub key: {:?}", e))?,
    )?;

    Ok(skdm.serialized().to_vec())
}
