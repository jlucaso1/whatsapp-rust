use crate::binary::builder::NodeBuilder;
use crate::binary::node::{Attrs, Node};
use crate::client::MessageUtils;
use crate::client::context::{GroupInfo, SendContextResolver};
use crate::signal::store::GroupSenderKeyStore;
use crate::types::jid::Jid;
use anyhow::{Result, anyhow};
use hex;
use libsignal_protocol::{
    CiphertextMessage, ProtocolAddress, SENDERKEY_MESSAGE_CURRENT_VERSION,
    SenderKeyDistributionMessage, SenderKeyMessage, SenderKeyRecord, SerializedState,
    aes_256_cbc_encrypt, message_encrypt, process_prekey_bundle, UsePQRatchet,
};
use log;
use prost::Message as ProtoMessage;
use rand::{CryptoRng, Rng, TryRngCore as _};
use std::time::SystemTime;
use waproto::whatsapp as wa;
use waproto::whatsapp::message::DeviceSentMessage;

pub async fn encrypt_group_message_correctly<S, R>(
    sender_key_store: &mut S,
    group_id: &Jid,
    sender: &ProtocolAddress,
    plaintext: &[u8],
    csprng: &mut R,
) -> Result<SenderKeyMessage>
where
    S: GroupSenderKeyStore + ?Sized,
    R: Rng + CryptoRng,
{
    let mut record = sender_key_store
        .load_sender_key(group_id, sender)
        .await?
        .ok_or_else(|| anyhow!("No SenderKeyRecord found for group session"))?;

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
        .store_sender_key(group_id, sender, &record)
        .await?;

    Ok(skm)
}

pub fn derive_keys_pre_kyber(
    secret_input: &[u8],
) -> Result<(libsignal_protocol::RootKey, libsignal_protocol::ChainKey)> {
    log::debug!("derive_keys_pre_kyber called");
    log::debug!("  Secret input length: {}", secret_input.len());
    log::debug!("  Secret input (hex): {}", hex::encode(secret_input));
    
    let label = b"WhisperText";
    log::debug!("  HKDF label: {:?}", std::str::from_utf8(label).unwrap_or("invalid utf8"));
    
    let mut okm = [0u8; 64];
    hkdf::Hkdf::<sha2::Sha256>::new(None, secret_input)
        .expand(label, &mut okm)
        .map_err(|_| anyhow!("HKDF expand failed"))?;

    log::debug!("  HKDF output (64 bytes): {}", hex::encode(&okm));

    let mut rk_bytes = [0u8; 32];
    let mut ck_bytes = [0u8; 32];
    rk_bytes.copy_from_slice(&okm[0..32]);
    ck_bytes.copy_from_slice(&okm[32..64]);

    log::debug!("  RootKey bytes: {}", hex::encode(&rk_bytes));
    log::debug!("  ChainKey bytes: {}", hex::encode(&ck_bytes));

    let root_key = libsignal_protocol::RootKey::new(rk_bytes);
    let chain_key = libsignal_protocol::ChainKey::new(ck_bytes, 0);
    
    Ok((root_key, chain_key))
}

pub async fn process_prekey_bundle_workaround<
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

    let their_pub_for_verify = their_identity_key.public_key();
    if !their_pub_for_verify.verify_signature(&spk_pub.serialize(), spk_sig) {
        return Err(anyhow!("Signed prekey signature invalid"));
    }

    let mut record: SessionRecord = match session_store.load_session(remote_address).await? {
        Some(r) => r,
        None => SessionRecord::new_fresh(),
    };

    let our_base_kp: KeyPair = KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
    let our_id_kp = identity_store.get_identity_key_pair().await?;

    log::debug!("X3DH Inputs for {}:", remote_address);
    log::debug!("  Our IK(priv): {}", hex::encode(our_id_kp.private_key().serialize()));
    log::debug!("  Our EK(priv): {}", hex::encode(our_base_kp.private_key.serialize()));
    log::debug!("  Their IK(pub): {}", hex::encode(their_identity_key.public_key().public_key_bytes()));
    log::debug!("  Their SPK(pub): {}", hex::encode(spk_pub.serialize()));
    
    let opk_pub = bundle
        .pre_key_public()
        .map_err(|e| anyhow!("bundle.pre_key_public: {e}"))?;
    if let Some(opk) = opk_pub {
        log::debug!("  Their OPK(pub): {}", hex::encode(opk.serialize()));
    } else {
        log::debug!("  Their OPK(pub): None");
    }

    let mut secrets: Vec<u8> = Vec::with_capacity(32 * 5);
    secrets.extend_from_slice(&[0xFFu8; 32]);

    let dh1 = our_id_kp
        .private_key()
        .calculate_agreement(&spk_pub)
        .map_err(|e| anyhow!("DH1 failed: {e}"))?;
    secrets.extend_from_slice(&dh1);

    let their_ik_pub = their_identity_key.public_key();
    let dh2 = our_base_kp
        .private_key
        .calculate_agreement(their_ik_pub)
        .map_err(|e| anyhow!("DH2 failed: {e}"))?;
    secrets.extend_from_slice(&dh2);

    let dh3 = our_base_kp
        .private_key
        .calculate_agreement(&spk_pub)
        .map_err(|e| anyhow!("DH3 failed: {e}"))?;
    secrets.extend_from_slice(&dh3);

    if let Some(opk_pub_val) = opk_pub {
        let dh4 = our_base_kp
            .private_key
            .calculate_agreement(&opk_pub_val)
            .map_err(|e| anyhow!("DH4 failed: {e}"))?;
        secrets.extend_from_slice(&dh4);
    }

    log::debug!("X3DH Outputs:");
    log::debug!("  DH1 (IKa, SPKb): {}", hex::encode(&dh1));
    log::debug!("  DH2 (EKa, IKb): {}", hex::encode(&dh2));
    log::debug!("  DH3 (EKa, SPKb): {}", hex::encode(&dh3));
    if let Some(opk_pub_val) = opk_pub {
        let dh4 = our_base_kp
            .private_key
            .calculate_agreement(&opk_pub_val)
            .map_err(|e| anyhow!("DH4 recalc failed: {e}"))?;
        log::debug!("  DH4 (EKa, OPKb): {}", hex::encode(&dh4));
    }
    log::debug!("  Final secrets blob for HKDF: {}", hex::encode(&secrets));

    let (root_key, _initial_ck) = derive_keys_pre_kyber(&secrets)?;

    let our_sending_ratchet_kp: libsignal_protocol::KeyPair =
        libsignal_protocol::KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
    let (new_root_key, new_sending_chain_key) =
        root_key.create_chain(&spk_pub, &our_sending_ratchet_kp.private_key)?;

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

    let prekey_id = bundle.pre_key_id().ok().flatten();
    let spk_id = bundle
        .signed_pre_key_id()
        .map_err(|e| anyhow!("bundle.signed_pre_key_id: {e}"))?;
    state.set_unacknowledged_pre_key_message(prekey_id, spk_id, &our_base_kp.public_key, now);

    state.set_local_registration_id(identity_store.get_local_registration_id().await?);
    state.set_remote_registration_id(bundle.registration_id()?);

    record.promote_state(state);
    identity_store
        .save_identity(remote_address, their_identity_key)
        .await?;
    session_store.store_session(remote_address, &record).await?;

    Ok(())
}

pub struct SignalStores<'a, S, I, P, SP, KP> {
    pub sender_key_store: &'a mut (dyn GroupSenderKeyStore + Send + Sync),
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
            process_prekey_bundle(
                &signal_address,
                stores.session_store,
                stores.identity_store,
                bundle,
                SystemTime::now(),
                &mut rand::rngs::OsRng.unwrap_err(),
                UsePQRatchet::No,
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

        let enc_node = NodeBuilder::new("enc")
            .attrs([("v", "2"), ("type", enc_type)])
            .bytes(serialized_bytes)
            .build();
        participant_nodes.push(
            NodeBuilder::new("to")
                .attr("jid", device_jid.to_string())
                .children([enc_node])
                .build(),
        );
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

    let stanza = NodeBuilder::new("message")
        .attrs([
            ("to", to_jid.to_string()),
            ("id", request_id),
            ("type", "text".to_string()),
        ])
        .children(message_content_nodes)
        .build();

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
    let signal_address = to_jid.to_protocol_address();

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
                let signal_address = device_jid.to_protocol_address();
                let bundle = prekey_bundles.get(device_jid).ok_or_else(|| {
                    anyhow!("Failed to fetch pre-key bundle for {}", &signal_address)
                })?;
                process_prekey_bundle(
                    &signal_address,
                    stores.session_store,
                    stores.identity_store,
                    bundle,
                    SystemTime::now(),
                    &mut rand::rngs::OsRng.unwrap_err(),
                    UsePQRatchet::No,
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

            let enc_node = NodeBuilder::new("enc")
                .attrs([("v", "2"), ("type", enc_type)])
                .bytes(serialized_bytes)
                .build();
            participant_nodes.push(
                NodeBuilder::new("to")
                    .attr("jid", device_jid.to_string())
                    .children([enc_node])
                    .build(),
            );
        }
        message_content_nodes.push(
            NodeBuilder::new("participants")
                .children(participant_nodes)
                .build(),
        );
    }
    let sender_address = own_sending_jid.to_protocol_address();
    let padded_plaintext = MessageUtils::pad_message_v2(message.encode_to_vec());
    let skmsg = encrypt_group_message_correctly(
        stores.sender_key_store,
        &to_jid,
        &sender_address,
        &padded_plaintext,
        &mut rand::rngs::OsRng.unwrap_err(),
    )
    .await?;

    let skmsg_ciphertext = skmsg.serialized().to_vec();

    if includes_prekey_message && let Some(acc) = account {
        message_content_nodes.push(
            NodeBuilder::new("device-identity")
                .bytes(acc.encode_to_vec())
                .build(),
        );
    }

    message_content_nodes.push(
        NodeBuilder::new("enc")
            .attrs([("v", "2"), ("type", "skmsg")])
            .bytes(skmsg_ciphertext)
            .build(),
    );

    let mut stanza_attrs = Attrs::new();
    stanza_attrs.insert("to".to_string(), to_jid.to_string());
    stanza_attrs.insert("id".to_string(), request_id);
    stanza_attrs.insert("type".to_string(), "text".to_string());

    if force_skdm_distribution {
        let all_devices = resolver.resolve_devices(&group_info.participants).await?;
        let phash = MessageUtils::participant_list_hash(&all_devices);
        stanza_attrs.insert("phash".to_string(), phash);
    }

    let stanza = NodeBuilder::new("message")
        .attrs(stanza_attrs.into_iter())
        .children(message_content_nodes)
        .build();
    Ok(stanza)
}
pub async fn create_sender_key_distribution_message_for_group(
    store: &mut (dyn GroupSenderKeyStore + Send + Sync),
    group_jid: &Jid,
    own_sending_jid: &Jid,
) -> Result<Vec<u8>> {
    let sender_address = own_sending_jid.to_protocol_address();

    let mut record = store
        .load_sender_key(group_jid, &sender_address)
        .await?
        .unwrap_or_else(SenderKeyRecord::new_empty);

    if record.sender_key_state().is_err() {
        let signing_key =
            libsignal_protocol::KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());

        let chain_id = (rand::rngs::OsRng.unwrap_err().random::<u32>()) >> 1;
        let sender_key_seed: [u8; 32] = rand::rngs::OsRng.unwrap_err().random();
        record.add_sender_key_state(
            SENDERKEY_MESSAGE_CURRENT_VERSION,
            chain_id,
            0,
            &sender_key_seed,
            signing_key.public_key,
            Some(signing_key.private_key),
        );
        store
            .store_sender_key(group_jid, &sender_address, &record)
            .await?;
    }

    let state = record
        .sender_key_state()
        .map_err(|e| anyhow!("Invalid SK state: {:?}", e))?;
    let chain_key = state
        .sender_chain_key()
        .ok_or(anyhow!("Missing chain key"))?;

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
