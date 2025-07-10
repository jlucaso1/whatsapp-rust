use crate::binary::node::{Node, NodeContent};
use crate::client::Client;
use crate::signal::address::SignalAddress;
use crate::signal::session::SessionBuilder;
use crate::signal::state::prekey_bundle::PreKeyBundle;
use crate::signal::state::session_record::SessionRecord;
use crate::signal::store::SessionStore;
use crate::signal::SessionCipher;
use crate::types::jid::{Jid, SERVER_JID};
use rand::Rng;
use whatsapp_proto::whatsapp as wa;
use whatsapp_proto::whatsapp::message::DeviceSentMessage;

// Group messaging imports
use base64::Engine;
use sha2::{Digest, Sha256};

// Helper function to pad messages for encryption
fn pad_message_v2(mut plaintext: Vec<u8>) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let mut pad_val = rng.gen::<u8>() & 0x0F;
    if pad_val == 0 {
        pad_val = 0x0F;
    }

    let padding = vec![pad_val; pad_val as usize];
    plaintext.extend_from_slice(&padding);
    plaintext
}

use base64::engine::general_purpose::STANDARD_NO_PAD;

fn participant_list_hash(devices: &[Jid]) -> String {
    let mut jids: Vec<String> = devices.iter().map(|j| j.to_ad_string()).collect();
    jids.sort();

    // Concatenate all JIDs into a single string before hashing
    let concatenated_jids = jids.join("");

    let mut hasher = Sha256::new();
    hasher.update(concatenated_jids.as_bytes());
    let full_hash = hasher.finalize();

    // Truncate the hash to the first 6 bytes
    let truncated_hash = &full_hash[..6];

    // Encode using base64 without padding
    format!("2:{}", STANDARD_NO_PAD.encode(truncated_hash))
}

impl Client {
    /// Sends a text message to the given JID.
    pub async fn send_text_message(&self, to: Jid, text: &str) -> Result<(), anyhow::Error> {
        let content = wa::Message {
            conversation: Some(text.to_string()),
            ..Default::default()
        };
        self.send_message(to, content).await
    }

    /// Encrypts and sends a protobuf message to the given JID.
    /// Multi-device compatible: builds <participants> node and syncs to own devices.
    pub async fn send_message(&self, to: Jid, message: wa::Message) -> Result<(), anyhow::Error> {
        if to.is_group() {
            self.send_group_message(to, message).await
        } else {
            self.send_dm_message(to, message).await
        }
    }

    // Moved from send_message: direct message logic
    async fn send_dm_message(&self, to: Jid, message: wa::Message) -> Result<(), anyhow::Error> {
        use crate::binary::node::{Node, NodeContent};
        use prost::Message as ProtoMessage;

        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let own_jid = device_snapshot
            .id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Not logged in"))?;
        // drop(device_snapshot); // Not needed

        let request_id = self.generate_message_id().await;

        self.add_recent_message(to.clone(), request_id.clone(), message.clone())
            .await;

        let padded_message_plaintext = pad_message_v2(message.encode_to_vec());
        let dsm = wa::Message {
            device_sent_message: Some(Box::new(DeviceSentMessage {
                destination_jid: Some(to.to_string()),
                message: Some(Box::new(message.clone())),
                phash: Some("".to_string()),
            })),
            ..Default::default()
        };
        let padded_dsm_plaintext = pad_message_v2(dsm.encode_to_vec());

        let participants = vec![to.clone(), own_jid.clone()];
        let all_devices = self.get_user_devices(&participants).await?;

        let mut participant_nodes = Vec::new();
        let mut includes_prekey_message = false;

        // store_arc is now persistence_manager. We need to pass Arc<PersistenceManager>
        // to SessionBuilder and SessionCipher if they need it, or pass the backend Arc directly.
        // For now, assuming SessionStore methods on PersistenceManager will be sufficient,
        // or that Device itself holds Arc<dyn Backend>.
        // Let's assume Device has `backend: Arc<dyn Backend>` and PersistenceManager provides access to it
        // or that SessionStore methods on PM directly use its filestore/memorystore.

        // If SessionStore methods are on Device, we'd get a device snapshot and use its backend.
        // If SessionStore methods are on PersistenceManager, we'd use self.persistence_manager.
        // The current store::Device has `backend: Arc<dyn Backend>`.
        // So, we get a device snapshot from PM, then use its backend.

        let pm_for_sessions = self.persistence_manager.clone();

        for device_jid in all_devices {
            let is_own_device =
                device_jid.user == own_jid.user && device_jid.device != own_jid.device;
            let plaintext_to_encrypt = if is_own_device {
                &padded_dsm_plaintext
            } else {
                &padded_message_plaintext
            };

            let signal_address =
                SignalAddress::new(device_jid.user.clone(), device_jid.device as u32);

            // Use Arc<Mutex<Device>> as the store for signal operations
            let device_store = pm_for_sessions.get_device_arc().await;

            // Load SessionRecord using the device_store
            let mut session_record = device_store
                .load_session(&signal_address) // Corrected name
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to load session record for {}: {}",
                        signal_address,
                        e
                    )
                })?;
            // .unwrap_or_default(); // Removed, as load_session returns SessionRecord::new() on not found

            let mut is_prekey_msg = false;
            let mut needs_new_session = session_record.is_fresh();

            // PROACTIVE SESSION VALIDATION: Test encryption with existing session
            if !needs_new_session {
                let test_cipher = SessionCipher::new(device_store.clone(), signal_address.clone());
                let test_data = b"test";
                let mut test_session = session_record.clone();

                match test_cipher.encrypt(&mut test_session, test_data).await {
                    Ok(_) => {
                        log::debug!("Session validation passed for {}", device_jid);
                        // Session is good, use the original session_record
                    }
                    Err(e) => {
                        log::warn!(
                            "Session validation failed for {}: {}. Fetching new pre-key.",
                            device_jid,
                            e
                        );
                        needs_new_session = true;
                        // Reset to fresh session since the existing one is stale
                        session_record = SessionRecord::new();
                    }
                }
            }

            if needs_new_session {
                let bundles = self.fetch_pre_keys(&[device_jid.clone()]).await?;
                let bundle = bundles
                    .get(&device_jid)
                    .ok_or_else(|| anyhow::anyhow!("No prekey bundle for {}", device_jid))?;

                let builder = SessionBuilder::new(device_store.clone(), signal_address.clone());
                builder.process_bundle(&mut session_record, bundle).await?;
                is_prekey_msg = true;
            }

            let cipher = SessionCipher::new(device_store.clone(), signal_address.clone());
            let encrypted_message = cipher
                .encrypt(&mut session_record, plaintext_to_encrypt)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("Final encryption failed for {}: {}", device_jid, e)
                })?;

            device_store
                .store_session(&signal_address, &session_record) // Corrected name
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to store session record for {}: {}",
                        signal_address,
                        e
                    )
                })?;

            if is_prekey_msg
                || matches!(
                    encrypted_message.q_type(),
                    crate::signal::protocol::PREKEY_TYPE
                )
            {
                includes_prekey_message = true;
            }

            let enc_type = match encrypted_message.q_type() {
                crate::signal::protocol::PREKEY_TYPE => "pkmsg",
                _ => "msg",
            };

            let enc_node = Node {
                tag: "enc".to_string(),
                attrs: [
                    ("v".to_string(), "2".to_string()),
                    ("type".to_string(), enc_type.to_string()),
                ]
                .into(),
                content: Some(NodeContent::Bytes(encrypted_message.serialize())),
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

        if includes_prekey_message {
            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            if let Some(account) = &device_snapshot.account {
                let device_identity_bytes = account.encode_to_vec();
                message_content_nodes.push(Node {
                    tag: "device-identity".to_string(),
                    attrs: Default::default(),
                    content: Some(NodeContent::Bytes(device_identity_bytes)),
                });
            } else {
                return Err(anyhow::anyhow!("Cannot send pre-key message: device account identity is missing. Please re-pair."));
            }
        }

        let stanza = Node {
            tag: "message".to_string(),
            attrs: [
                ("to".to_string(), to.to_string()),
                ("id".to_string(), request_id),
                ("type".to_string(), "text".to_string()),
            ]
            .into(),
            content: Some(NodeContent::Nodes(message_content_nodes)),
        };

        self.send_node(stanza).await.map_err(|e| e.into())
    }

    // Group message logic
    async fn send_group_message(&self, to: Jid, message: wa::Message) -> Result<(), anyhow::Error> {
        use crate::binary::node::{Node, NodeContent};
        use crate::signal::address::SignalAddress;
        use crate::signal::groups::builder::GroupSessionBuilder;
        use crate::signal::groups::cipher::GroupCipher;
        use crate::signal::sender_key_name::SenderKeyName;
        use crate::signal::session::SessionBuilder;
        use crate::signal::SessionCipher;
        use prost::Message as ProtoMessage;

        // Get own_jid and own_lid from PersistenceManager
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let _own_jid = device_snapshot
            .id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Not logged in: id missing"))?;
        let own_lid = device_snapshot
            .lid
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Not logged in: lid missing"))?;
        // let backend = device_snapshot.backend.clone(); // No longer need separate backend variable.
        // device_store (Arc<Mutex<Device>>) will be used directly.
        let device_store = self.persistence_manager.get_device_arc().await;

        let request_id = self.generate_message_id().await;

        // Add message to cache for potential retries
        self.add_recent_message(to.clone(), request_id.clone(), message.clone())
            .await;

        // 1. Get all members of the group, then get all of their devices.
        let participants = self.query_group_info(&to).await?;
        log::debug!("Group participants for {:?}: {:?}", to, participants);
        let all_devices = self.get_user_devices(&participants).await?;
        log::debug!("All devices for group {:?}: {:?}", to, all_devices);

        let mut includes_prekey_message = false;

        // 2. Create the SenderKeyDistributionMessage to be sent to participants who need it.
        // The sender identifier for group messages must be a unique identifier
        // for the sending device within the group context. Using the LID's
        // signal address (user:device) is the correct approach.
        let sender_address = SignalAddress::new(own_lid.user.clone(), own_lid.device as u32);
        let sender_key_name = SenderKeyName::new(to.to_string(), sender_address.to_string());
        let group_builder = GroupSessionBuilder::new(device_store.clone()); // Use device_store
        let distribution_message = group_builder.create(&sender_key_name).await.map_err(|e| {
            anyhow::anyhow!("Failed to create sender key distribution message: {e}")
        })?;
        let distribution_message_bytes = distribution_message.encode_to_vec();

        // 3. Encrypt the actual message content with the shared group sender key.
        let group_cipher =
            GroupCipher::new(sender_key_name.clone(), device_store.clone(), group_builder); // Use device_store
        let padded_message_plaintext = pad_message_v2(message.encode_to_vec());
        let sk_msg_ciphertext = group_cipher
            .encrypt(&padded_message_plaintext)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to encrypt group message: {e}"))?;

        // 4. Bulk-fetch prekeys for devices without a session, then process per device.
        let mut devices_needing_prekeys_for_check = Vec::new();
        for device_jid in &all_devices {
            let signal_address =
                SignalAddress::new(device_jid.user.clone(), device_jid.device as u32);
            // Use device_store for contains_session
            if !device_store
                .contains_session(&signal_address) // Corrected name
                .await
                .unwrap_or(false)
            {
                devices_needing_prekeys_for_check.push(device_jid.clone());
            }
        }

        // Re-assign to avoid confusion with the later devices_needing_prekeys for bundle fetching
        let devices_to_fetch_bundles_for = devices_needing_prekeys_for_check;

        let prekey_bundles = if !devices_to_fetch_bundles_for.is_empty() {
            self.fetch_pre_keys(&devices_to_fetch_bundles_for)
                .await
                .unwrap_or_default()
        } else {
            std::collections::HashMap::new()
        };

        let mut participant_pkmsg_nodes = Vec::new();
        // Lock the LID-PN map for lookup
        let lid_pn_map = self.lid_pn_map.lock().await;

        // --- MODIFICATION START: Pre-calculate identities and perform session migration ---
        let mut devices_to_process = Vec::new();
        // This devices_needing_prekeys is for the inner loop, distinct from above.
        // let mut devices_needing_prekeys_inner_loop = Vec::new();

        for wire_identity in &all_devices {
            let encryption_identity =
                if wire_identity.server == crate::types::jid::DEFAULT_USER_SERVER {
                    lid_pn_map
                        .get(wire_identity)
                        .cloned()
                        .unwrap_or_else(|| wire_identity.clone())
                } else {
                    wire_identity.clone()
                };

            // If a LID is being used for a PN identity, check if we need to migrate the session.
            if &encryption_identity != wire_identity {
                let pn_address =
                    SignalAddress::new(wire_identity.user.clone(), wire_identity.device as u32);
                let lid_address = SignalAddress::new(
                    encryption_identity.user.clone(),
                    encryption_identity.device as u32,
                );

                // If a session exists for the PN but not the LID, migrate it.
                // Use device_store for session operations
                if device_store
                    .contains_session(&pn_address) // Corrected name
                    .await
                    .unwrap_or(false)
                    && !device_store
                        .contains_session(&lid_address) // Corrected name
                        .await
                        .unwrap_or(false)
                {
                    log::debug!("Migrating session from {} to {}", pn_address, lid_address);
                    // Corrected: load_session returns Result<SessionRecord, _>
                    if let Ok(session_record_data) = device_store.load_session(&pn_address).await {
                        // Only store if it's not a fresh/empty record, or handle is_fresh appropriately
                        if !session_record_data.is_fresh() {
                            let _ = device_store
                                .store_session(&lid_address, &session_record_data)
                                .await;
                        }
                        // Not deleting the old one is safer for now.
                    }
                }
            }

            let signal_address = SignalAddress::new(
                encryption_identity.user.clone(),
                encryption_identity.device as u32,
            );
            // This check was already done above, but keeping it aligned with original logic for now.
            // if !device_store.contains_session(&signal_address).await.unwrap_or(false) { // Corrected name
            //     devices_needing_prekeys_inner_loop.push(wire_identity.clone());
            // }
            devices_to_process.push((wire_identity.clone(), encryption_identity, signal_address));
        }
        // --- MODIFICATION END ---

        for (wire_identity, encryption_identity, signal_address) in devices_to_process {
            // Load SessionRecord using device_store
            let mut session_record =
                device_store
                    .load_session(&signal_address)
                    .await
                    .map_err(|e| {
                        // Corrected name
                        anyhow::anyhow!("Failed to load session for {}: {}", signal_address, e)
                    })?; // Removed unwrap_or_default

            let mut needs_new_session = session_record.is_fresh();

            // PROACTIVE SESSION VALIDATION: Test encryption with existing session
            if !needs_new_session {
                let test_cipher = SessionCipher::new(device_store.clone(), signal_address.clone());
                let test_data = b"test";
                let mut test_session = session_record.clone();

                match test_cipher.encrypt(&mut test_session, test_data).await {
                    Ok(_) => {
                        log::debug!("Group session validation passed for {}", wire_identity);
                        // Session is good, use the original session_record
                    }
                    Err(e) => {
                        log::warn!("Group session validation failed for {}: {}. Will fetch new pre-key if available.", wire_identity, e);
                        needs_new_session = true;
                        // Reset to fresh session since the existing one is stale
                        session_record = SessionRecord::new();
                    }
                }
            }

            // If we fetched a bundle for this device, process it now.
            if let Some(bundle) = prekey_bundles.get(&wire_identity) {
                let builder = SessionBuilder::new(device_store.clone(), signal_address.clone());
                if let Err(e) = builder.process_bundle(&mut session_record, bundle).await {
                    log::warn!(
                        "Failed to process prekey bundle for {}: {}. Skipping.",
                        wire_identity,
                        e
                    );
                    continue;
                }
            } else if needs_new_session {
                // Session is fresh or stale, but no prekey bundle was fetched
                log::warn!(
                    "Device {} needs new session but no prekey bundle was fetched. Skipping.",
                    wire_identity
                );
                continue;
            }

            let session_cipher = SessionCipher::new(device_store.clone(), signal_address.clone());
            let encrypted_distribution_message = session_cipher
                .encrypt(&mut session_record, &distribution_message_bytes)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("Failed to encrypt SKDM for {}: {}", encryption_identity, e)
                })?;

            device_store
                .store_session(&signal_address, &session_record) // Corrected name
                .await
                .map_err(|e| {
                    anyhow::anyhow!("Failed to store session for {}: {}", encryption_identity, e)
                })?;

            if encrypted_distribution_message.q_type() == crate::signal::protocol::PREKEY_TYPE {
                includes_prekey_message = true;
            }

            let enc_type = match encrypted_distribution_message.q_type() {
                crate::signal::protocol::PREKEY_TYPE => "pkmsg",
                _ => "msg",
            };

            let pkmsg_enc_node = Node {
                tag: "enc".to_string(),
                attrs: [
                    ("v".to_string(), "2".to_string()),
                    ("type".to_string(), enc_type.to_string()),
                ]
                .into(),
                content: Some(NodeContent::Bytes(
                    encrypted_distribution_message.serialize(),
                )),
            };

            participant_pkmsg_nodes.push(Node {
                tag: "to".to_string(),
                attrs: [("jid".to_string(), wire_identity.to_string())].into(),
                content: Some(NodeContent::Nodes(vec![pkmsg_enc_node])),
            });
        }

        // 5. CORRECTLY CONSTRUCT THE FINAL STANZA
        let sk_msg_node = Node {
            tag: "enc".to_string(),
            attrs: [
                ("v".to_string(), "2".to_string()),
                ("type".to_string(), "skmsg".to_string()),
            ]
            .into(),
            content: Some(NodeContent::Bytes(sk_msg_ciphertext.serialize())),
        };

        let mut message_content_nodes = Vec::new();

        // Add the participants block *if* we have any keys to distribute.
        if !participant_pkmsg_nodes.is_empty() {
            message_content_nodes.push(Node {
                tag: "participants".to_string(),
                attrs: Default::default(),
                content: Some(NodeContent::Nodes(participant_pkmsg_nodes)),
            });
        }

        // Add device identity if we sent any pre-key messages.
        if includes_prekey_message {
            // Get account from device_snapshot which was fetched at the beginning of the function
            if let Some(account) = &device_snapshot.account {
                log::debug!("Including device-identity node because a pkmsg was sent");
                let device_identity_bytes = account.encode_to_vec();
                message_content_nodes.push(Node {
                    tag: "device-identity".to_string(),
                    attrs: Default::default(),
                    content: Some(NodeContent::Bytes(device_identity_bytes)),
                });
            }
        }

        // The skmsg is always at the top level of the message content.
        message_content_nodes.push(sk_msg_node);

        let phash = participant_list_hash(&all_devices);
        let stanza = Node {
            tag: "message".to_string(),
            attrs: [
                ("to".to_string(), to.to_string()),
                ("phash".to_string(), phash),
                ("id".to_string(), request_id),
                ("type".to_string(), "text".to_string()),
            ]
            .into(),
            content: Some(NodeContent::Nodes(message_content_nodes)),
        };

        self.send_node(stanza).await.map_err(|e| e.into())
    }

    /// Fetches pre-key bundles for a list of JIDs.
    pub async fn fetch_pre_keys(
        &self,
        jids: &[Jid],
    ) -> Result<std::collections::HashMap<Jid, PreKeyBundle>, anyhow::Error> {
        let mut user_nodes = Vec::with_capacity(jids.len());
        for jid in jids {
            user_nodes.push(Node {
                tag: "user".into(),
                attrs: [("jid".to_string(), jid.to_string())].into(),
                content: None,
            });
        }

        let resp_node = self
            .send_iq(crate::request::InfoQuery {
                namespace: "encrypt",
                query_type: crate::request::InfoQueryType::Get,
                to: SERVER_JID.parse().unwrap(),
                content: Some(NodeContent::Nodes(vec![Node {
                    tag: "key".into(),
                    attrs: Default::default(),
                    content: Some(NodeContent::Nodes(user_nodes)),
                }])),
                id: None,
                target: None,
                timeout: None,
            })
            .await?;

        let list_node = resp_node
            .get_optional_child("list")
            .ok_or_else(|| anyhow::anyhow!("<list> not found in pre-key response"))?;

        let mut bundles = std::collections::HashMap::new();
        for user_node in list_node.children().unwrap_or_default() {
            if user_node.tag != "user" {
                continue;
            }
            let mut attrs = user_node.attrs();
            let jid = attrs.jid("jid");
            let bundle = match self.node_to_pre_key_bundle(&jid, user_node) {
                Ok(b) => b,
                Err(e) => {
                    log::warn!("Failed to parse pre-key bundle for {jid}: {e}");
                    continue;
                }
            };
            bundles.insert(jid, bundle);
        }

        Ok(bundles)
    }

    fn node_to_pre_key_bundle(
        &self,
        jid: &Jid,
        node: &Node,
    ) -> Result<PreKeyBundle, anyhow::Error> {
        fn extract_bytes(node: Option<&Node>) -> Result<Vec<u8>, anyhow::Error> {
            match node.and_then(|n| n.content.as_ref()) {
                Some(NodeContent::Bytes(b)) => Ok(b.clone()),
                _ => Err(anyhow::anyhow!("Expected bytes in node content")),
            }
        }

        if let Some(error_node) = node.get_optional_child("error") {
            return Err(anyhow::anyhow!(
                "Error getting prekeys: {}",
                error_node.to_string()
            ));
        }

        let reg_id_bytes = extract_bytes(node.get_optional_child("registration"))?;
        if reg_id_bytes.len() != 4 {
            return Err(anyhow::anyhow!("Invalid registration ID length"));
        }
        let registration_id = u32::from_be_bytes(reg_id_bytes.try_into().unwrap());

        let keys_node = node.get_optional_child("keys").unwrap_or(node);

        let identity_key_bytes = extract_bytes(keys_node.get_optional_child("identity"))?;
        if identity_key_bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "Invalid identity key length: got {}, expected 32",
                identity_key_bytes.len()
            ));
        }
        let identity_key = crate::signal::identity::IdentityKey::new(
            crate::signal::ecc::keys::DjbEcPublicKey::new(identity_key_bytes.try_into().unwrap()),
        );

        let mut pre_key_id = None;
        let mut pre_key_public = None;
        if let Some(pre_key_node) = keys_node.get_optional_child("key") {
            if let Some((id, key)) = self.node_to_pre_key(pre_key_node)? {
                pre_key_id = Some(id);
                pre_key_public = Some(key);
            }
        }

        let signed_pre_key_node = keys_node
            .get_optional_child("skey")
            .ok_or(anyhow::anyhow!("Missing signed prekey"))?;
        let (signed_pre_key_id, signed_pre_key_public, signed_pre_key_signature) =
            self.node_to_signed_pre_key(signed_pre_key_node)?;

        Ok(PreKeyBundle {
            registration_id,
            device_id: jid.device as u32,
            pre_key_id,
            pre_key_public,
            signed_pre_key_id,
            signed_pre_key_public,
            signed_pre_key_signature,
            identity_key,
        })
    }

    fn node_to_pre_key(
        &self,
        node: &Node,
    ) -> Result<Option<(u32, crate::signal::ecc::keys::DjbEcPublicKey)>, anyhow::Error> {
        let id_node_content = node
            .get_optional_child("id")
            .and_then(|n| n.content.as_ref());

        let id = match id_node_content {
            Some(NodeContent::Bytes(b)) if !b.is_empty() => {
                if b.len() == 3 {
                    // Handle 3-byte big-endian integer ID
                    Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
                } else if let Ok(s) = std::str::from_utf8(b) {
                    // Handle hex string ID
                    u32::from_str_radix(s, 16).map_err(|e| e.into())
                } else {
                    Err(anyhow::anyhow!("ID is not valid UTF-8 hex or 3-byte int"))
                }
            }
            // ID is empty or missing, this is invalid for a one-time pre-key
            _ => Err(anyhow::anyhow!("Missing or empty pre-key ID content")),
        };

        let id = match id {
            Ok(val) => val,
            Err(_) => return Ok(None), // Gracefully ignore invalid one-time pre-keys
        };

        let value_bytes = node
            .get_optional_child("value")
            .and_then(|n| n.content.as_ref())
            .and_then(|c| {
                if let NodeContent::Bytes(b) = c {
                    Some(b.clone())
                } else {
                    None
                }
            })
            .ok_or(anyhow::anyhow!("Missing pre-key value"))?;
        if value_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Invalid pre-key value length"));
        }
        let public_key =
            crate::signal::ecc::keys::DjbEcPublicKey::new(value_bytes.try_into().unwrap());

        Ok(Some((id, public_key)))
    }

    fn node_to_signed_pre_key(
        &self,
        node: &Node,
    ) -> Result<(u32, crate::signal::ecc::keys::DjbEcPublicKey, [u8; 64]), anyhow::Error> {
        // HACK: In some cases, the signed prekey ID is missing. The Go implementation seems to default to 1 in this scenario.
        // This is a bit of a magic number, but it matches the behavior of the reference implementation.
        let (id, public_key) = match self.node_to_pre_key(node)? {
            Some((id, key)) => (id, key),
            None => (1, crate::signal::ecc::keys::DjbEcPublicKey::new([0u8; 32])),
        };
        let signature_bytes = node
            .get_optional_child("signature")
            .and_then(|n| n.content.as_ref())
            .and_then(|c| {
                if let NodeContent::Bytes(b) = c {
                    Some(b.clone())
                } else {
                    None
                }
            })
            .ok_or(anyhow::anyhow!("Missing signed pre-key signature"))?;
        if signature_bytes.len() != 64 {
            return Err(anyhow::anyhow!("Invalid signature length"));
        }

        Ok((id, public_key, signature_bytes.try_into().unwrap()))
    }
}
