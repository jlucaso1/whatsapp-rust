use crate::client::Client;
use crate::signal::SessionCipher;
use crate::signal::address::SignalAddress;
use crate::signal::session::SessionBuilder;
use crate::signal::state::session_record::SessionRecord;
use crate::signal::store::SessionStore;
use crate::types::jid::Jid;
use rand::Rng;
use whatsapp_proto::whatsapp as wa;
use whatsapp_proto::whatsapp::message::DeviceSentMessage;

// Group messaging imports
use base64::prelude::*;
use sha2::{Digest, Sha256};

// Helper function to pad messages for encryption
fn pad_message_v2(mut plaintext: Vec<u8>) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let mut pad_val = rng.r#gen::<u8>() & 0x0F;
    if pad_val == 0 {
        pad_val = 0x0F;
    }

    let padding = vec![pad_val; pad_val as usize];
    plaintext.extend_from_slice(&padding);
    plaintext
}

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
    format!(
        "2:{hash}",
        hash = BASE64_STANDARD_NO_PAD.encode(truncated_hash)
    )
}

impl Client {
    /// Sends a text message to the given JID.
    pub async fn send_text_message(&self, to: Jid, text: &str) -> Result<(), anyhow::Error> {
        let content = wa::Message {
            conversation: Some(text.to_string()),
            ..Default::default()
        };
        // Generate a new ID for a new message and call the internal implementation.
        let request_id = self.generate_message_id().await;
        self.send_message_impl(to, content, request_id).await
    }

    /// Encrypts and sends a protobuf message to the given JID.
    /// Multi-device compatible: builds <participants> node and syncs to own devices.
    pub async fn send_message_impl(
        &self,
        to: Jid,
        message: wa::Message,
        request_id: String,
    ) -> Result<(), anyhow::Error> {
        if to.is_group() {
            self.send_group_message(to, message, request_id).await
        } else {
            self.send_dm_message(to, message, request_id).await
        }
    }

    // Moved from send_message: direct message logic
    async fn send_dm_message(
        &self,
        to: Jid,
        message: wa::Message,
        request_id: String,
    ) -> Result<(), anyhow::Error> {
        use crate::binary::node::{Node, NodeContent};
        use prost::Message as ProtoMessage;

        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let own_jid = device_snapshot
            .id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Not logged in"))?;

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
            let device_store_wrapper = crate::store::signal::DeviceStore::new(device_store.clone());
            let mut session_record = device_store_wrapper
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
                let device_store_wrapper =
                    crate::store::signal::DeviceStore::new(device_store.clone());
                let test_cipher = SessionCipher::new(device_store_wrapper, signal_address.clone());
                let test_data = b"test";
                let mut test_session = session_record.clone();

                match test_cipher.encrypt(&mut test_session, test_data).await {
                    Ok(_) => {
                        log::debug!("Session validation passed for {device_jid}");
                        // Session is good, use the original session_record
                    }
                    Err(e) => {
                        log::warn!(
                            "Session validation failed for {device_jid}: {e}. Fetching new pre-key."
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

                let device_store_wrapper =
                    crate::store::signal::DeviceStore::new(device_store.clone());
                let builder = SessionBuilder::new(device_store_wrapper, signal_address.clone());
                builder.process_bundle(&mut session_record, bundle).await?;
                is_prekey_msg = true;
            }

            let device_store_wrapper = crate::store::signal::DeviceStore::new(device_store.clone());
            let cipher = SessionCipher::new(device_store_wrapper.clone(), signal_address.clone());
            let encrypted_message = cipher
                .encrypt(&mut session_record, plaintext_to_encrypt)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("Final encryption failed for {}: {}", device_jid, e)
                })?;

            device_store_wrapper
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
                return Err(anyhow::anyhow!(
                    "Cannot send pre-key message: device account identity is missing. Please re-pair."
                ));
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
    async fn send_group_message(
        &self,
        to: Jid,
        message: wa::Message,
        request_id: String,
    ) -> Result<(), anyhow::Error> {
        use crate::binary::node::{Node, NodeContent};
        use crate::signal::SessionCipher;
        use crate::signal::address::SignalAddress;
        use crate::signal::groups::builder::GroupSessionBuilder;
        use crate::signal::groups::cipher::GroupCipher;
        use crate::signal::sender_key_name::SenderKeyName;
        use crate::signal::session::SessionBuilder;
        use prost::Message as ProtoMessage;

        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let own_lid = device_snapshot
            .lid
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Not logged in: lid missing"))?;
        let device_store = self.persistence_manager.get_device_arc().await;

        // Add message to cache for potential retries
        self.add_recent_message(to.clone(), request_id.clone(), message.clone())
            .await;

        // 1. Get all members of the group, then get all of their devices.
        let participants = self.query_group_info(&to).await?;
        log::debug!("Group participants for {to:?}: {participants:?}");
        let all_devices = self.get_user_devices(&participants).await?;
        log::debug!("All devices for group {to:?}: {all_devices:?}");

        let mut includes_prekey_message = false;

        // 2. Create the SenderKeyDistributionMessage to be sent to participants who need it.
        // The sender identifier for group messages must be a unique identifier
        // for the sending device within the group context. Using the LID's
        // signal address (user:device) is the correct approach.
        let sender_address = SignalAddress::new(own_lid.user.clone(), own_lid.device as u32);
        let sender_key_name = SenderKeyName::new(to.to_string(), sender_address.to_string());
        let device_store_wrapper = crate::store::signal::DeviceStore::new(device_store.clone());
        let group_builder = GroupSessionBuilder::new(device_store_wrapper.clone()); // Use device_store
        let distribution_message = group_builder.create(&sender_key_name).await.map_err(|e| {
            anyhow::anyhow!("Failed to create sender key distribution message: {e}")
        })?;

        // The axolotl protocol message (distribution_message) must be wrapped in a wa::Message
        // before being encrypted for each participant.
        let skdm_for_encryption = wa::Message {
            sender_key_distribution_message: Some(wa::message::SenderKeyDistributionMessage {
                group_id: Some(to.to_string()),
                axolotl_sender_key_distribution_message: Some(distribution_message.encode_to_vec()),
            }),
            ..Default::default()
        };
        let distribution_message_bytes = skdm_for_encryption.encode_to_vec();

        // 3. Encrypt the actual message content with the shared group sender key.
        let group_cipher = GroupCipher::new(
            sender_key_name.clone(),
            device_store_wrapper.clone(),
            group_builder,
        ); // Use device_store
        let message_plaintext = message.encode_to_vec();
        let sk_msg_ciphertext = group_cipher
            .encrypt(&message_plaintext)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to encrypt group message: {e}"))?;

        // 4. Bulk-fetch prekeys for devices without a session, then process per device.
        let mut devices_needing_prekeys_for_check = Vec::new();
        for device_jid in &all_devices {
            let signal_address =
                SignalAddress::new(device_jid.user.clone(), device_jid.device as u32);
            // Use device_store for contains_session
            if !device_store_wrapper
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
                if device_store_wrapper
                    .contains_session(&pn_address) // Corrected name
                    .await
                    .unwrap_or(false)
                    && !device_store_wrapper
                        .contains_session(&lid_address) // Corrected name
                        .await
                        .unwrap_or(false)
                {
                    log::debug!("Migrating session from {pn_address} to {lid_address}");
                    // Corrected: load_session returns Result<SessionRecord, _>
                    if let Ok(session_record_data) =
                        device_store_wrapper.load_session(&pn_address).await
                    {
                        // Only store if it's not a fresh/empty record, or handle is_fresh appropriately
                        if !session_record_data.is_fresh() {
                            let _ = device_store_wrapper
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

        for (wire_identity, encryption_identity, signal_address) in devices_to_process {
            // Load SessionRecord using device_store
            let mut session_record = device_store_wrapper
                .load_session(&signal_address)
                .await
                .map_err(|e| {
                    // Corrected name
                    anyhow::anyhow!("Failed to load session for {}: {}", signal_address, e)
                })?; // Removed unwrap_or_default

            let mut needs_new_session = session_record.is_fresh();

            // PROACTIVE SESSION VALIDATION: Test encryption with existing session
            if !needs_new_session {
                let device_store_wrapper =
                    crate::store::signal::DeviceStore::new(device_store.clone());
                let test_cipher = SessionCipher::new(device_store_wrapper, signal_address.clone());
                let test_data = b"test";
                let mut test_session = session_record.clone();

                match test_cipher.encrypt(&mut test_session, test_data).await {
                    Ok(_) => {
                        log::debug!("Group session validation passed for {wire_identity}");
                        // Session is good, use the original session_record
                    }
                    Err(e) => {
                        log::warn!(
                            "Group session validation failed for {wire_identity}: {e}. Will fetch new pre-key if available."
                        );
                        needs_new_session = true;
                        // Reset to fresh session since the existing one is stale
                        session_record = SessionRecord::new();
                    }
                }
            }

            // If we fetched a bundle for this device, process it now.
            if let Some(bundle) = prekey_bundles.get(&wire_identity) {
                let device_store_wrapper_builder =
                    crate::store::signal::DeviceStore::new(device_store.clone());
                let builder =
                    SessionBuilder::new(device_store_wrapper_builder, signal_address.clone());
                if let Err(e) = builder.process_bundle(&mut session_record, bundle).await {
                    log::warn!(
                        "Failed to process prekey bundle for {wire_identity}: {e}. Skipping."
                    );
                    continue;
                }
            } else if needs_new_session {
                // Session is fresh or stale, but no prekey bundle was fetched
                log::warn!(
                    "Device {wire_identity} needs new session but no prekey bundle was fetched. Skipping."
                );
                continue;
            }

            let device_store_wrapper = crate::store::signal::DeviceStore::new(device_store.clone());
            let session_cipher =
                SessionCipher::new(device_store_wrapper.clone(), signal_address.clone());
            let encrypted_distribution_message = session_cipher
                .encrypt(&mut session_record, &distribution_message_bytes)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("Failed to encrypt SKDM for {}: {}", encryption_identity, e)
                })?;

            device_store_wrapper
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
}
