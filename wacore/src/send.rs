use crate::binary::node::{Attrs, Node, NodeContent};
use crate::client::context::{GroupInfo, SendContextResolver};
use crate::client::MessageUtils;
use crate::signal::sender_key_name::SenderKeyName;
use crate::types::jid::Jid;
use anyhow::{anyhow, Result};
use libsignal_protocol::{
    create_sender_key_distribution_message, group_encrypt, message_encrypt, CiphertextMessage,
    ProtocolAddress, UsePQRatchet,
};
use prost::Message as ProtoMessage;
use rand::TryRngCore as _;
use std::time::SystemTime;
use waproto::whatsapp as wa;
use waproto::whatsapp::message::DeviceSentMessage;

// Local wrapper to allow swapping faulty library logic with a corrected implementation later
async fn process_prekey_bundle_workaround<
    S: libsignal_protocol::SessionStore + Send + Sync,
    I: libsignal_protocol::IdentityKeyStore + Send + Sync,
>(
    remote_address: &ProtocolAddress,
    session_store: &mut S,
    identity_store: &mut I,
    bundle: &libsignal_protocol::PreKeyBundle,
    now: SystemTime,
) -> Result<()> {
    // Delegate to the library for now; encapsulate to enable a drop-in replacement
    libsignal_protocol::process_prekey_bundle(
        remote_address,
        session_store,
        identity_store,
        bundle,
        now,
        &mut rand::rngs::OsRng.unwrap_err(),
        UsePQRatchet::No,
    )
    .await
    .map_err(Into::into)
}

pub struct SignalStores<'a, S, I, P, SP, KP> {
    pub sender_key_store: &'a mut (dyn libsignal_protocol::SenderKeyStore + Send + Sync),
    pub session_store: &'a mut S,
    pub identity_store: &'a mut I,
    pub prekey_store: &'a mut P,
    pub signed_prekey_store: &'a SP,
    pub kyber_prekey_store: &'a mut KP,
}

pub async fn prepare_dm_stanza<
    'a,
    S: libsignal_protocol::SessionStore + Send + Sync,
    I: libsignal_protocol::IdentityKeyStore + Send + Sync,
    P: libsignal_protocol::PreKeyStore + Send + Sync,
    SP: libsignal_protocol::SignedPreKeyStore + Send + Sync,
    KP: libsignal_protocol::KyberPreKeyStore + Send + Sync,
>(
    stores: &mut SignalStores<'a, S, I, P, SP, KP>,
    resolver: &dyn SendContextResolver,
    own_jid: &Jid,
    account: Option<&wa::AdvSignedDeviceIdentity>,
    to_jid: Jid,
    message: wa::Message,
    request_id: String,
) -> Result<Node> {
    let padded_message_plaintext = MessageUtils::pad_message_v2(message.encode_to_vec());

    let dsm = wa::Message {
        device_sent_message: Some(Box::new(DeviceSentMessage {
            destination_jid: Some(to_jid.to_string()),
            message: Some(Box::new(message)),
            phash: Some("".to_string()),
        })),
        ..Default::default()
    };
    let padded_dsm_plaintext = MessageUtils::pad_message_v2(dsm.encode_to_vec());

    let participants = vec![to_jid.clone(), own_jid.clone()];
    let all_devices = resolver.resolve_devices(&participants).await?;

    let mut participant_nodes = Vec::new();
    let mut includes_prekey_message = false;

    for device_jid in all_devices {
        let is_own_device = device_jid.user == own_jid.user && device_jid.device != own_jid.device;
        let plaintext_to_encrypt = if is_own_device {
            &padded_dsm_plaintext
        } else {
            &padded_message_plaintext
        };

        let signal_address =
            ProtocolAddress::new(device_jid.user.clone(), (device_jid.device as u32).into());
        let session_record = stores.session_store.load_session(&signal_address).await?;

        if session_record.is_none() {
            let prekey_bundles = resolver
                .fetch_prekeys(std::slice::from_ref(&device_jid))
                .await?;
            let bundle = prekey_bundles
                .get(&device_jid)
                .ok_or_else(|| anyhow!("Failed to fetch pre-key bundle for {}", &signal_address))?;
            process_prekey_bundle_workaround(
                &signal_address,
                stores.session_store,
                stores.identity_store,
                bundle,
                SystemTime::now(),
            )
            .await?;
        }

        let encrypted_message = message_encrypt(
            plaintext_to_encrypt,
            &signal_address,
            stores.session_store,
            stores.identity_store,
            SystemTime::now(),
            &mut rand::rngs::OsRng.unwrap_err(),
        )
        .await?;

        let (enc_type, serialized_bytes) = match encrypted_message {
            CiphertextMessage::PreKeySignalMessage(msg) => {
                includes_prekey_message = true;
                ("pkmsg", msg.serialized().to_vec())
            }
            CiphertextMessage::SignalMessage(msg) => ("msg", msg.serialized().to_vec()),
            _ => return Err(anyhow!("Unexpected encryption message type")),
        };

        let enc_node = Node {
            tag: "enc".to_string(),
            attrs: [
                ("v".to_string(), "2".to_string()),
                ("type".to_string(), enc_type.to_string()),
            ]
            .into(),
            content: Some(NodeContent::Bytes(serialized_bytes)),
        };
        participant_nodes.push(Node {
            tag: "to".to_string(),
            attrs: [("jid".to_string(), device_jid.to_string())].into(),
            content: Some(NodeContent::Nodes(vec![enc_node])),
        });
    }

    let mut message_content_nodes = vec![Node {
        tag: "participants".to_string(),
        attrs: Default::default(),
        content: Some(NodeContent::Nodes(participant_nodes)),
    }];

    if includes_prekey_message && let Some(acc) = account {
        let device_identity_bytes = acc.encode_to_vec();
        message_content_nodes.push(Node {
            tag: "device-identity".to_string(),
            attrs: Default::default(),
            content: Some(NodeContent::Bytes(device_identity_bytes)),
        });
    }

    let stanza = Node {
        tag: "message".to_string(),
        attrs: [
            ("to".to_string(), to_jid.to_string()),
            ("id".to_string(), request_id),
            ("type".to_string(), "text".to_string()),
        ]
        .into(),
        content: Some(NodeContent::Nodes(message_content_nodes)),
    };

    Ok(stanza)
}

pub async fn prepare_peer_stanza<S, I>(
    session_store: &mut S,
    identity_store: &mut I,
    to_jid: Jid,
    message: wa::Message,
    request_id: String,
) -> Result<Node>
where
    S: libsignal_protocol::SessionStore,
    I: libsignal_protocol::IdentityKeyStore,
{
    let plaintext = MessageUtils::pad_message_v2(message.encode_to_vec());
    let signal_address = ProtocolAddress::new(to_jid.user.clone(), (to_jid.device as u32).into());

    let encrypted_message = message_encrypt(
        &plaintext,
        &signal_address,
        session_store,
        identity_store,
        SystemTime::now(),
        &mut rand::rngs::OsRng.unwrap_err(),
    )
    .await?;

    let (enc_type, serialized_bytes) = match encrypted_message {
        CiphertextMessage::SignalMessage(msg) => ("msg", msg.serialized().to_vec()),
        CiphertextMessage::PreKeySignalMessage(msg) => ("pkmsg", msg.serialized().to_vec()),
        _ => return Err(anyhow!("Unexpected peer encryption message type")),
    };

    let enc_node = Node {
        tag: "enc".to_string(),
        attrs: [
            ("v".to_string(), "2".to_string()),
            ("type".to_string(), enc_type.to_string()),
        ]
        .into(),
        content: Some(NodeContent::Bytes(serialized_bytes)),
    };

    let stanza = Node {
        tag: "message".to_string(),
        attrs: [
            ("to".to_string(), to_jid.to_string()),
            ("id".to_string(), request_id),
            ("type".to_string(), "text".to_string()),
            ("category".to_string(), "peer".to_string()),
        ]
        .into(),
        content: Some(NodeContent::Nodes(vec![enc_node])),
    };

    Ok(stanza)
}

#[allow(clippy::too_many_arguments)]
pub async fn prepare_group_stanza<
    'a,
    S: libsignal_protocol::SessionStore + Send + Sync,
    I: libsignal_protocol::IdentityKeyStore + Send + Sync,
    P: libsignal_protocol::PreKeyStore + Send + Sync,
    SP: libsignal_protocol::SignedPreKeyStore + Send + Sync,
    KP: libsignal_protocol::KyberPreKeyStore + Send + Sync,
>(
    stores: &mut SignalStores<'a, S, I, P, SP, KP>,
    resolver: &dyn SendContextResolver,
    group_info: &mut GroupInfo,
    own_jid: &Jid,
    own_lid: &Jid,
    account: Option<&wa::AdvSignedDeviceIdentity>,
    to_jid: Jid,
    message: wa::Message,
    request_id: String,
    force_skdm_distribution: bool,
) -> Result<Node> {
    let (own_sending_jid, _) = match group_info.addressing_mode {
        crate::types::message::AddressingMode::Lid => (own_lid.clone(), "lid"),
        crate::types::message::AddressingMode::Pn => (own_jid.clone(), "pn"),
    };

    let own_base_jid = own_sending_jid.to_non_ad();
    if !group_info
        .participants
        .iter()
        .any(|p| p.user == own_base_jid.user)
    {
        group_info.participants.push(own_base_jid);
    }

    let mut message_content_nodes = Vec::new();
    let mut includes_prekey_message = false;

    if force_skdm_distribution {
        let all_devices = resolver.resolve_devices(&group_info.participants).await?;
        let (axolotl_skdm_bytes, _sender_key_name) = create_sender_key_distribution_message_for_group(
            stores.sender_key_store,
            &to_jid,
            &own_sending_jid,
        )
        .await?;

        // The raw SenderKeyDistributionMessage must be wrapped in a wa::Message
        // before being marshaled and encrypted for each participant device.
        let skdm_wrapper_msg = wa::Message {
            sender_key_distribution_message: Some(wa::message::SenderKeyDistributionMessage {
                group_id: Some(to_jid.to_string()),
                axolotl_sender_key_distribution_message: Some(axolotl_skdm_bytes),
            }),
            ..Default::default()
        };
        let skdm_plaintext_to_encrypt = skdm_wrapper_msg.encode_to_vec();

        let mut jids_needing_prekeys = Vec::new();
        for device_jid in &all_devices {
            let signal_address =
                ProtocolAddress::new(device_jid.user.clone(), (device_jid.device as u32).into());
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
            let prekey_bundles = resolver
                .fetch_prekeys_for_identity_check(&jids_needing_prekeys)
                .await?;

            for device_jid in &jids_needing_prekeys {
                let signal_address = ProtocolAddress::new(
                    device_jid.user.clone(),
                    (device_jid.device as u32).into(),
                );
                let bundle = prekey_bundles.get(device_jid).ok_or_else(|| {
                    anyhow!("Failed to fetch pre-key bundle for {}", &signal_address)
                })?;
                process_prekey_bundle_workaround(
                    &signal_address,
                    stores.session_store,
                    stores.identity_store,
                    bundle,
                    SystemTime::now(),
                )
                .await?;
            }
        }

        let mut participant_nodes = Vec::new();
        for device_jid in all_devices {
            let signal_address =
                ProtocolAddress::new(device_jid.user.clone(), (device_jid.device as u32).into());
            let encrypted_payload = message_encrypt(
                &skdm_plaintext_to_encrypt,
                &signal_address,
                stores.session_store,
                stores.identity_store,
                SystemTime::now(),
                &mut rand::rngs::OsRng.unwrap_err(),
            )
            .await?;
            let (enc_type, serialized_bytes) = match encrypted_payload {
                CiphertextMessage::PreKeySignalMessage(msg) => {
                    includes_prekey_message = true;
                    ("pkmsg", msg.serialized().to_vec())
                }
                CiphertextMessage::SignalMessage(msg) => ("msg", msg.serialized().to_vec()),
                _ => continue,
            };

            let enc_node = Node {
                tag: "enc".to_string(),
                attrs: [
                    ("v".to_string(), "2".to_string()),
                    ("type".to_string(), enc_type.to_string()),
                ]
                .into(),
                content: Some(NodeContent::Bytes(serialized_bytes)),
            };
            participant_nodes.push(Node {
                tag: "to".to_string(),
                attrs: [("jid".to_string(), device_jid.to_string())].into(),
                content: Some(NodeContent::Nodes(vec![enc_node])),
            });
        }
        message_content_nodes.push(Node {
            tag: "participants".to_string(),
            attrs: Default::default(),
            content: Some(NodeContent::Nodes(participant_nodes)),
        });
    }
    let sender_address = ProtocolAddress::new(
        own_sending_jid.user.clone(),
        u32::from(own_sending_jid.device).into(),
    );
    let sender_key_name = SenderKeyName::new(to_jid.to_string(), sender_address.to_string());
    let group_sender_address = sender_key_name.to_protocol_address();
    let padded_plaintext = MessageUtils::pad_message_v2(message.encode_to_vec());
    let skmsg_ciphertext = group_encrypt(
        stores.sender_key_store,
        &group_sender_address,
        &padded_plaintext,
        &mut rand::rngs::OsRng.unwrap_err(),
    )
    .await?
    .serialized()
    .to_vec();

    if includes_prekey_message && let Some(acc) = account {
        message_content_nodes.push(Node {
            tag: "device-identity".to_string(),
            attrs: Default::default(),
            content: Some(NodeContent::Bytes(acc.encode_to_vec())),
        });
    }

    message_content_nodes.push(Node {
        tag: "enc".to_string(),
        attrs: [
            ("v".to_string(), "2".to_string()),
            ("type".to_string(), "skmsg".to_string()),
        ]
        .into(),
        content: Some(NodeContent::Bytes(skmsg_ciphertext)),
    });

    let mut stanza_attrs = Attrs::new();
    stanza_attrs.insert("to".to_string(), to_jid.to_string());
    stanza_attrs.insert("id".to_string(), request_id);
    stanza_attrs.insert("type".to_string(), "text".to_string());

    if force_skdm_distribution {
        let all_devices = resolver.resolve_devices(&group_info.participants).await?;
        let phash = MessageUtils::participant_list_hash(&all_devices);
        // The `participant` and `addressing_mode` attributes are not needed on the root message node.
        stanza_attrs.insert("phash".to_string(), phash);
    }

    let stanza = Node {
        tag: "message".to_string(),
        attrs: stanza_attrs,
        content: Some(NodeContent::Nodes(message_content_nodes)),
    };
    Ok(stanza)
}

pub async fn create_sender_key_distribution_message_for_group(
    store: &mut dyn libsignal_protocol::SenderKeyStore,
    group_jid: &Jid,
    own_sending_jid: &Jid,
) -> Result<(Vec<u8>, SenderKeyName)> {
    let sender_address = ProtocolAddress::new(
        own_sending_jid.user.clone(),
        u32::from(own_sending_jid.device).into(),
    );
    let sender_key_name = SenderKeyName::new(group_jid.to_string(), sender_address.to_string());

    let group_sender_address = sender_key_name.to_protocol_address();
    let skdm = create_sender_key_distribution_message(
        &group_sender_address,
        store,
        &mut rand::rngs::OsRng.unwrap_err(),
    )
    .await?;

    let skdm_bytes = skdm.serialized().to_vec();
    Ok((skdm_bytes, sender_key_name))
}
