use crate::binary::node::{Node, NodeContent};
use crate::client::MessageUtils;
use crate::client::context::SendContextResolver;
use crate::signal::sender_key_name::SenderKeyName;
use crate::types::jid::Jid;
use anyhow::{Result, anyhow};
use libsignal_protocol::{
    CiphertextMessage, ProtocolAddress, UsePQRatchet, create_sender_key_distribution_message,
    group_encrypt, message_encrypt, process_prekey_bundle,
};
use prost::Message as ProtoMessage;
use rand::TryRngCore as _;
use std::time::SystemTime;
use waproto::whatsapp as wa;
use waproto::whatsapp::message::DeviceSentMessage;

pub struct SignalStores<'a, S, I, P, SP, KP> {
    pub session_store: &'a mut S,
    pub identity_store: &'a mut I,
    pub prekey_store: &'a mut P,
    pub signed_prekey_store: &'a SP,
    pub kyber_prekey_store: &'a mut KP,
}

pub async fn prepare_dm_stanza<'a, S, I, P, SP, KP>(
    stores: &mut SignalStores<'a, S, I, P, SP, KP>,
    resolver: &dyn SendContextResolver,
    own_jid: &Jid,
    account: Option<&wa::AdvSignedDeviceIdentity>,
    to_jid: Jid,
    message: wa::Message,
    request_id: String,
) -> Result<Node>
where
    S: libsignal_protocol::SessionStore,
    I: libsignal_protocol::IdentityKeyStore,
    P: libsignal_protocol::PreKeyStore,
    SP: libsignal_protocol::SignedPreKeyStore,
    KP: libsignal_protocol::KyberPreKeyStore,
{
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
        let session_exists = match session_record {
            Some(record) => record.has_usable_sender_chain(SystemTime::now())?,
            None => false,
        };

        if !session_exists {
            let prekey_bundles = resolver
                .fetch_prekeys(std::slice::from_ref(&device_jid))
                .await?;
            let bundle = prekey_bundles
                .get(&device_jid)
                .ok_or_else(|| anyhow!("Failed to fetch pre-key bundle for {}", &signal_address))?;
            process_prekey_bundle(
                &signal_address,
                stores.session_store,
                stores.identity_store,
                bundle,
                SystemTime::now(),
                &mut rand::rngs::OsRng.unwrap_err(),
                UsePQRatchet::Yes,
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
pub async fn prepare_group_stanza<'a, SK, S, I, P, SP, KP>(
    sender_key_store: &mut SK,
    stores: &mut SignalStores<'a, S, I, P, SP, KP>,
    resolver: &dyn SendContextResolver,
    own_jid: &Jid,
    own_lid: &Jid,
    account: Option<&wa::AdvSignedDeviceIdentity>,
    to_jid: Jid,
    message: wa::Message,
    request_id: String,
) -> Result<Node>
where
    SK: libsignal_protocol::SenderKeyStore,
    S: libsignal_protocol::SessionStore,
    I: libsignal_protocol::IdentityKeyStore,
    P: libsignal_protocol::PreKeyStore,
    SP: libsignal_protocol::SignedPreKeyStore,
    KP: libsignal_protocol::KyberPreKeyStore,
{
    let mut group_info = resolver.resolve_group_info(&to_jid).await?;

    let (own_sending_jid, addressing_mode_str) = match group_info.addressing_mode {
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

    let all_devices = resolver.resolve_devices(&group_info.participants).await?;

    let (skdm_bytes, sender_key_name) = create_sender_key_distribution_message_for_group(
        sender_key_store,
        &to_jid,
        &own_sending_jid,
    )
    .await?;

    let padded_plaintext = MessageUtils::pad_message_v2(message.encode_to_vec());

    let group_sender_address =
        ProtocolAddress::new(sender_key_name.group_id().to_string(), 0.into());
    let skmsg_ciphertext = group_encrypt(
        sender_key_store,
        &group_sender_address,
        &padded_plaintext,
        &mut rand::rngs::OsRng.unwrap_err(),
    )
    .await?
    .serialized()
    .to_vec();

    let mut participant_nodes = Vec::new();
    let mut includes_prekey_message = false;
    let phash = MessageUtils::participant_list_hash(&all_devices);

    let recipient_devices: Vec<_> = all_devices
        .into_iter()
        .filter(|d| d != &own_sending_jid)
        .collect();

    for device_jid in recipient_devices {
        let signal_address =
            ProtocolAddress::new(device_jid.user.clone(), (device_jid.device as u32).into());
        let session_record = stores.session_store.load_session(&signal_address).await?;
        if session_record.is_none()
            || !session_record
                .unwrap()
                .has_usable_sender_chain(SystemTime::now())?
        {
            let prekey_bundles = resolver
                .fetch_prekeys(std::slice::from_ref(&device_jid))
                .await?;
            let bundle = prekey_bundles
                .get(&device_jid)
                .ok_or_else(|| anyhow!("Failed to fetch pre-key bundle for {}", &signal_address))?;
            process_prekey_bundle(
                &signal_address,
                stores.session_store,
                stores.identity_store,
                bundle,
                SystemTime::now(),
                &mut rand::rngs::OsRng.unwrap_err(),
                UsePQRatchet::Yes,
            )
            .await?;
        }

        let encrypted_payload = message_encrypt(
            &skdm_bytes,
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

    let mut message_content_nodes = vec![
        Node {
            tag: "participants".to_string(),
            attrs: Default::default(),
            content: Some(NodeContent::Nodes(participant_nodes)),
        },
        Node {
            tag: "enc".to_string(),
            attrs: [
                ("v".to_string(), "2".to_string()),
                ("type".to_string(), "skmsg".to_string()),
            ]
            .into(),
            content: Some(NodeContent::Bytes(skmsg_ciphertext)),
        },
    ];

    if includes_prekey_message && let Some(acc) = account {
        message_content_nodes.push(Node {
            tag: "device-identity".to_string(),
            attrs: Default::default(),
            content: Some(NodeContent::Bytes(acc.encode_to_vec())),
        });
    }

    let stanza = Node {
        tag: "message".to_string(),
        attrs: [
            ("to".to_string(), to_jid.to_string()),
            ("id".to_string(), request_id),
            ("type".to_string(), "text".to_string()),
            ("participant".to_string(), own_sending_jid.to_string()),
            (
                "addressing_mode".to_string(),
                addressing_mode_str.to_string(),
            ),
            ("phash".to_string(), phash),
        ]
        .into(),
        content: Some(NodeContent::Nodes(message_content_nodes)),
    };
    Ok(stanza)
}

pub async fn create_sender_key_distribution_message_for_group<S>(
    store: &mut S,
    group_jid: &Jid,
    own_lid: &Jid,
) -> Result<(Vec<u8>, SenderKeyName)>
where
    S: libsignal_protocol::SenderKeyStore,
{
    let sender_address =
        ProtocolAddress::new(own_lid.user.clone(), u32::from(own_lid.device).into());
    let sender_key_name = SenderKeyName::new(group_jid.to_string(), sender_address.to_string());
    let skdm = create_sender_key_distribution_message(
        &ProtocolAddress::new(sender_key_name.group_id().to_string(), 0.into()),
        store,
        &mut rand::rngs::OsRng.unwrap_err(),
    )
    .await?;
    let skdm_wrapper = wa::Message {
        sender_key_distribution_message: Some(wa::message::SenderKeyDistributionMessage {
            group_id: Some(group_jid.to_string()),
            axolotl_sender_key_distribution_message: Some(skdm.serialized().to_vec()),
        }),
        ..Default::default()
    };
    let padded_skdm = MessageUtils::pad_message_v2(skdm_wrapper.encode_to_vec());
    Ok((padded_skdm, sender_key_name))
}
