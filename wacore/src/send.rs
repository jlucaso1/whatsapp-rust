use crate::binary::node::{Attrs, Node, NodeContent};
use crate::client::MessageUtils;
use crate::client::context::{GroupInfo, SendContextResolver};
use crate::signal::sender_key_name::SenderKeyName;
use crate::types::jid::Jid;
use anyhow::{Result, anyhow};
use libsignal_protocol::{
    CiphertextMessage, ProtocolAddress, SerializedState, create_sender_key_distribution_message,
    group_encrypt, message_encrypt,
};
use prost::Message as ProtoMessage;
use rand::TryRngCore as _;
use std::time::SystemTime;
use waproto::whatsapp as wa;
use waproto::whatsapp::message::DeviceSentMessage;

// HKDF-based key derivation to obtain RootKey and initial sending ChainKey.
pub fn derive_keys_pre_kyber(
    secret_input: &[u8],
) -> Result<(libsignal_protocol::RootKey, libsignal_protocol::ChainKey)> {
    // Mirror reference Signal: salt = None, info label for pre-kyber
    let label = b"WhisperText";
    let mut okm = [0u8; 64];
    hkdf::Hkdf::<sha2::Sha256>::new(None, secret_input)
        .expand(label, &mut okm)
        .map_err(|_| anyhow!("HKDF expand failed"))?;

    let mut rk_bytes = [0u8; 32];
    let mut ck_bytes = [0u8; 32];
    rk_bytes.copy_from_slice(&okm[0..32]);
    ck_bytes.copy_from_slice(&okm[32..64]);

    let root_key = libsignal_protocol::RootKey::new(rk_bytes);
    let chain_key = libsignal_protocol::ChainKey::new(ck_bytes, 0);
    Ok((root_key, chain_key))
}

// Full local implementation to build a fresh session from a PreKeyBundle without premature ratchet.
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
    use libsignal_protocol::{Direction, IdentityKey, KeyPair, SessionRecord};

    // 1) Trust and signature checks
    let their_identity_key: &IdentityKey = bundle
        .identity_key()
        .map_err(|e| anyhow!("bundle.identity_key: {e}"))?;

    let trusted = identity_store
        .is_trusted_identity(remote_address, their_identity_key, Direction::Sending)
        .await?;
    if !trusted {
        return Err(anyhow!(
            "Untrusted identity for {}",
            remote_address.to_string()
        ));
    }

    let spk_pub = bundle
        .signed_pre_key_public()
        .map_err(|e| anyhow!("bundle.signed_pre_key_public: {e}"))?;
    let spk_sig = bundle
        .signed_pre_key_signature()
        .map_err(|e| anyhow!("bundle.signed_pre_key_signature: {e}"))?;

    // Verify SPK signature
    let their_pub_for_verify = their_identity_key.public_key();
    if !their_pub_for_verify.verify_signature(&spk_pub.serialize(), spk_sig) {
        return Err(anyhow!("Signed prekey signature invalid"));
    }

    // 2) Load or create session record
    let mut record: SessionRecord = match session_store.load_session(remote_address).await? {
        Some(r) => r,
        None => SessionRecord::new_fresh(),
    };

    // 3) Generate our ephemeral (base) key pair; fetch our identity key pair
    let our_base_kp: KeyPair = KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
    let our_id_kp = identity_store.get_identity_key_pair().await?;

    // 4) X3DH secret computation for Alice
    // Secrets = 0xFF*32 || DH(IKa, SPKb) || DH(EKa, IKb) || DH(EKa, SPKb) || (optional DH(EKa, OPKb))
    let mut secrets: Vec<u8> = Vec::with_capacity(32 * 5);
    secrets.extend_from_slice(&[0xFFu8; 32]);

    // DH1: IKa x SPKb
    let dh1 = our_id_kp
        .private_key()
        .calculate_agreement(&spk_pub)
        .map_err(|e| anyhow!("DH1 failed: {e}"))?;
    secrets.extend_from_slice(&dh1);

    // DH2: EKa x IKb
    let their_ik_pub = their_identity_key.public_key();
    let dh2 = our_base_kp
        .private_key
        .calculate_agreement(their_ik_pub)
        .map_err(|e| anyhow!("DH2 failed: {e}"))?;
    secrets.extend_from_slice(&dh2);

    // DH3: EKa x SPKb
    let dh3 = our_base_kp
        .private_key
        .calculate_agreement(&spk_pub)
        .map_err(|e| anyhow!("DH3 failed: {e}"))?;
    secrets.extend_from_slice(&dh3);

    // Optional DH4: EKa x OPKb
    if let Some(opk_pub) = bundle
        .pre_key_public()
        .map_err(|e| anyhow!("bundle.pre_key_public: {e}"))?
    {
        let dh4 = our_base_kp
            .private_key
            .calculate_agreement(&opk_pub)
            .map_err(|e| anyhow!("DH4 failed: {e}"))?;
        secrets.extend_from_slice(&dh4);
    }

    // 5) Derive RootKey and initial ChainKey from X3DH master secret
    let (root_key, _initial_ck) = derive_keys_pre_kyber(&secrets)?;

    // 6) Perform the required initial ratchet step:
    //    Create a fresh sending ratchet keypair and derive the new root and sending chain.
    let our_sending_ratchet_kp: libsignal_protocol::KeyPair =
        libsignal_protocol::KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
    let (new_root_key, new_sending_chain_key) =
        root_key.create_chain(&spk_pub, &our_sending_ratchet_kp.private_key)?;

    // 7) Build initial SessionState (pre-kyber) using ratcheted keys
    let version = libsignal_protocol::CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION;
    let mut state = libsignal_protocol::SessionState::new(
        version,
        our_id_kp.identity_key(),
        their_identity_key,
        &new_root_key,
        &spk_pub,
        SerializedState::new(),
    )
    .with_sender_chain(&our_sending_ratchet_kp, &new_sending_chain_key);

    // 8) Unacknowledged PreKey metadata so first message is pkmsg
    let prekey_id = bundle.pre_key_id().ok().flatten();
    let spk_id = bundle
        .signed_pre_key_id()
        .map_err(|e| anyhow!("bundle.signed_pre_key_id: {e}"))?;
    state.set_unacknowledged_pre_key_message(prekey_id, spk_id, &our_base_kp.public_key, now);

    state.set_local_registration_id(identity_store.get_local_registration_id().await?);
    state.set_remote_registration_id(bundle.registration_id()?);

    // 9) Promote and persist
    record.promote_state(state);
    identity_store
        .save_identity(remote_address, their_identity_key)
        .await?;
    session_store.store_session(remote_address, &record).await?;

    Ok(())
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
        let (axolotl_skdm_bytes, _sender_key_name) =
            create_sender_key_distribution_message_for_group(
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
