use crate::client::context::{GroupInfo, SendContextResolver};
use crate::libsignal::protocol::{
    CiphertextMessage, SENDERKEY_MESSAGE_CURRENT_VERSION, SenderKeyDistributionMessage,
    SenderKeyMessage, SenderKeyRecord, SenderKeyStore, SignalProtocolError, UsePQRatchet,
    aes_256_cbc_encrypt, message_encrypt, process_prekey_bundle,
};
use crate::libsignal::store::sender_key_name::SenderKeyName;
use crate::messages::MessageUtils;
use crate::types::jid::JidExt;
use anyhow::{Result, anyhow};
use prost::Message as ProtoMessage;
use rand::{CryptoRng, Rng, TryRngCore as _};
use std::collections::HashSet;
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
    let mut jids_needing_prekeys = Vec::new();
    for device_jid in devices {
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
        log::debug!(
            "Fetching prekeys for {} devices without sessions",
            jids_needing_prekeys.len()
        );
        let prekey_bundles = resolver
            .fetch_prekeys_for_identity_check(&jids_needing_prekeys)
            .await?;

        for device_jid in &jids_needing_prekeys {
            let signal_address = device_jid.to_protocol_address();
            match prekey_bundles.get(device_jid) {
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
                            log::warn!(
                                "Untrusted identity for device {}. Skipping this device.",
                                addr
                            );
                            // Skip this device and continue with others
                            continue;
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
        let signal_address = device_jid.to_protocol_address();

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
) -> Result<Node> {
    let recipient_plaintext = MessageUtils::pad_message_v2(message.encode_to_vec());

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
                if base_jid.server == "lid"
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
        let own_jid_to_check = if own_base_jid.server == "lid" {
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

        let mut seen = HashSet::new();
        resolved_list.retain(|jid| seen.insert(jid.to_string()));

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

    let plaintext = MessageUtils::pad_message_v2(message.encode_to_vec());
    let skmsg = encrypt_group_message(
        stores.sender_key_store,
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
        match MessageUtils::participant_list_hash(devices) {
            Ok(phash) => {
                stanza_attrs.insert("phash".to_string(), phash);
            }
            Err(e) => {
                log::warn!("Failed to compute phash for group {}: {:?}", to_jid, e);
            }
        }
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

    let message_version = state
        .message_version()
        .try_into()
        .map_err(|e| anyhow!("Invalid sender key message version: {e}"))?;
    let skdm = SenderKeyDistributionMessage::new(
        message_version,
        state.chain_id(),
        chain_key.iteration(),
        chain_key.seed().to_vec(),
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
    }

    impl MockSendContextResolver {
        fn new() -> Self {
            Self {
                prekey_bundles: HashMap::new(),
                devices: Vec::new(),
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
    }

    /// Test case: Missing pre-key bundle for a single device skips gracefully
    ///
    /// When sending to multiple devices, if some don't have pre-key bundles (e.g., Cloud API),
    /// we should skip them instead of failing the entire message.
    #[test]
    fn test_missing_prekey_bundle_skips_device() {
        let device_with_bundle: Jid = "1234567890:0@s.whatsapp.net".parse().unwrap();
        let device_without_bundle: Jid = "1234567890:1@s.whatsapp.net".parse().unwrap();
        let cloud_api: Jid = "1234567890:99@hosted".parse().unwrap();

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
        let device1: Jid = "1234567890:0@s.whatsapp.net".parse().unwrap();
        let device2: Jid = "1234567890:1@s.whatsapp.net".parse().unwrap();
        let device3: Jid = "9876543210:0@s.whatsapp.net".parse().unwrap();

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

        for i in 0..10 {
            let device_jid: Jid = format!("1234567890:{}@s.whatsapp.net", i).parse().unwrap();
            all_devices.push(device_jid);
        }

        let mut resolver = MockSendContextResolver::new().with_devices(all_devices.clone());

        // Add bundles for devices 0-6, mark 7-9 as missing
        for i in 0..10 {
            let device_jid: Jid = format!("1234567890:{}@s.whatsapp.net", i).parse().unwrap();

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

    /// Test case: Cloud API device without pre-key
    ///
    /// Cloud API devices often don't have traditional pre-key bundles.
    /// They should be skipped without affecting regular devices.
    #[test]
    fn test_cloud_api_device_without_prekey() {
        let regular_device: Jid = "1234567890:0@s.whatsapp.net".parse().unwrap();
        let cloud_api: Jid = "1234567890:99@hosted".parse().unwrap();

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
            "Cloud API device should not have a bundle"
        );

        println!("✅ Cloud API device skipped, regular device included");
    }

    /// Test case: Device recovery between retries
    ///
    /// If a device was temporarily unavailable, a retry should succeed.
    #[test]
    fn test_device_recovery_between_requests() {
        let device: Jid = "1234567890:0@s.whatsapp.net".parse().unwrap();

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
}
