use crate::client::Client;
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use anyhow::anyhow;
use std::sync::Arc;
use wacore::libsignal::protocol::{SignalProtocolError, SessionStore};
use wacore::types::jid::JidExt;
use wacore_binary::jid::{Jid, JidExt as _};
use waproto::whatsapp as wa;
use wacore_binary::node::{Attrs, Node};
use wacore_binary::builder::NodeBuilder;
use wacore::libsignal::protocol::{CiphertextMessage, message_encrypt, process_prekey_bundle, UsePQRatchet};
use std::time::SystemTime;
use futures_util::{stream, StreamExt};
use rand::TryRngCore;

/// Parallel encryption for SKDM distribution to improve performance for large groups
async fn encrypt_for_devices_parallel(
    store_adapter: &SignalProtocolStoreAdapter,
    resolver: &dyn wacore::client::context::SendContextResolver,
    devices: &[Jid],
    plaintext_to_encrypt: &[u8],
    enc_extra_attrs: &Attrs,
) -> Result<(Vec<Node>, bool), anyhow::Error> {
    // First, identify devices needing prekeys using a mutable clone
    let mut jids_needing_prekeys = Vec::new();
    let cloned_adapter_for_check = store_adapter.clone();
    for device_jid in devices {
        let signal_address = device_jid.to_protocol_address();
        if cloned_adapter_for_check
            .session_store
            .load_session(&signal_address)
            .await?
            .is_none()
        {
            jids_needing_prekeys.push(device_jid.clone());
        }
    }

    // Fetch prekeys sequentially (this part can't be parallelized due to resolver trait)
    if !jids_needing_prekeys.is_empty() {
        log::info!(
            "Fetching prekeys for devices without sessions: {:?}",
            jids_needing_prekeys
        );
        let prekey_bundles = resolver
            .fetch_prekeys_for_identity_check(&jids_needing_prekeys)
            .await?;

        // Process prekeys sequentially to maintain store consistency
        // Create a single mutable RNG instance instead of OsRng.unwrap_err() for each call
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let mut cloned_adapter = store_adapter.clone();
        for device_jid in &jids_needing_prekeys {
            let signal_address = device_jid.to_protocol_address();
            let bundle = prekey_bundles
                .get(device_jid)
                .ok_or_else(|| anyhow!("Failed to fetch pre-key bundle for {}", &signal_address))?;
            process_prekey_bundle(
                &signal_address,
                &mut cloned_adapter.session_store,
                &mut cloned_adapter.identity_store,
                bundle,
                SystemTime::now(),
                &mut rng,
                UsePQRatchet::No,
            )
            .await?;
        }
    }

    // Now perform bounded parallel encryption
    let concurrency = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4) // Default to 4 concurrent tasks if unavailable
        .clamp(1, 16); // Ensure at least 1, cap at 16 to avoid overwhelming the system

    let plaintext = plaintext_to_encrypt.to_vec();
    let attrs = enc_extra_attrs.clone();

    let encryption_tasks = devices.iter().cloned().map(|device_jid| {
        let plaintext_clone = plaintext.clone();
        let attrs_clone = attrs.clone();
        let mut store_clone = store_adapter.clone();

        async move {
            let signal_address = device_jid.to_protocol_address();
            
            let encrypted_payload = message_encrypt(
                &plaintext_clone,
                &signal_address,
                &mut store_clone.session_store,
                &mut store_clone.identity_store,
                SystemTime::now(),
            )
            .await?;

            let (enc_type, serialized_bytes) = match encrypted_payload {
                CiphertextMessage::PreKeySignalMessage(msg) => ("pkmsg", msg.serialized().to_vec()),
                CiphertextMessage::SignalMessage(msg) => ("msg", msg.serialized().to_vec()),
                _ => return Err(anyhow!("Unexpected encryption message type for SKDM")),
            };

            let mut enc_attrs = Attrs::new();
            enc_attrs.insert("v".to_string(), "2".to_string());
            enc_attrs.insert("type".to_string(), enc_type.to_string());
            for (k, v) in attrs_clone.iter() {
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
            
            // Return the node and whether a pre-key message was used
            Ok::<(Node, bool), anyhow::Error>((participant_node, enc_type == "pkmsg"))
        }
    });

    // Use bounded concurrency instead of unbounded task spawning
    let results: Vec<Result<(Node, bool), anyhow::Error>> = stream::iter(encryption_tasks)
        .buffer_unordered(concurrency)
        .collect()
        .await;

    let mut participant_nodes = Vec::new();
    let mut includes_prekey_message = false;

    for result in results {
        match result {
            Ok((node, uses_prekey)) => {
                participant_nodes.push(node);
                if uses_prekey {
                    includes_prekey_message = true;
                }
            }
            Err(e) => {
                return Err(anyhow!("An encryption task for SKDM failed: {}", e));
            }
        }
    }

    Ok((participant_nodes, includes_prekey_message))
}

/// Implementation of parallel encryption processor for Client
pub struct ClientParallelProcessor {
    store_adapter: SignalProtocolStoreAdapter,
}

impl ClientParallelProcessor {
    pub fn new(store_adapter: SignalProtocolStoreAdapter) -> Self {
        Self { store_adapter }
    }
}

#[async_trait::async_trait]
impl wacore::send::ParallelEncryptionProcessor for ClientParallelProcessor {
    async fn encrypt_for_devices_parallel(
        &self,
        resolver: &dyn wacore::client::context::SendContextResolver,
        devices: &[Jid],
        plaintext_to_encrypt: &[u8],
        enc_extra_attrs: &Attrs,
    ) -> Result<(Vec<Node>, bool), anyhow::Error> {
        // Use our parallel implementation
        encrypt_for_devices_parallel(
            &self.store_adapter,
            resolver,
            devices,
            plaintext_to_encrypt,
            enc_extra_attrs,
        )
        .await
    }
}

impl Client {
    pub async fn send_message(
        &self,
        to: Jid,
        message: wa::Message,
    ) -> Result<String, anyhow::Error> {
        let request_id = self.generate_message_id().await;
        self.send_message_impl(
            to,
            Arc::new(message),
            Some(request_id.clone()),
            false,
            false,
            None,
        )
        .await?;
        Ok(request_id)
    }

    pub(crate) async fn send_message_impl(
        &self,
        to: Jid,
        message: Arc<wa::Message>,
        request_id_override: Option<String>,
        peer: bool,
        force_key_distribution: bool,
        edit: Option<crate::types::message::EditAttribute>,
    ) -> Result<(), anyhow::Error> {
        let chat_mutex = self
            .chat_locks
            .entry(to.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _chat_guard = chat_mutex.lock().await;

        let request_id = match request_id_override {
            Some(id) => id,
            None => self.generate_message_id().await,
        };

        let stanza_to_send: wacore_binary::Node = if peer {
            let device_store_arc = self.persistence_manager.get_device_arc().await;
            let mut store_adapter = SignalProtocolStoreAdapter::new(device_store_arc);

            wacore::send::prepare_peer_stanza(
                &mut store_adapter.session_store,
                &mut store_adapter.identity_store,
                to,
                message.as_ref(),
                request_id,
            )
            .await?
        } else if to.is_group() {
            let mut group_info = self.query_group_info(&to).await?;

            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            let own_jid = device_snapshot
                .pn
                .clone()
                .ok_or_else(|| anyhow!("Not logged in"))?;
            let own_lid = device_snapshot
                .lid
                .clone()
                .ok_or_else(|| anyhow!("LID not set, cannot send to group"))?;
            let account_info = device_snapshot.account.clone();

            let _ = self
                .add_recent_message(to.clone(), request_id.clone(), Arc::clone(&message))
                .await;

            let device_store_arc = self.persistence_manager.get_device_arc().await;

            let (own_sending_jid, _) = match group_info.addressing_mode {
                crate::types::message::AddressingMode::Lid => (own_lid.clone(), "lid"),
                crate::types::message::AddressingMode::Pn => (own_jid.clone(), "pn"),
            };

            if !group_info
                .participants
                .iter()
                .any(|participant| participant.is_same_user_as(&own_sending_jid))
            {
                group_info.participants.push(own_sending_jid.to_non_ad());
            }

            let force_skdm = {
                use wacore::libsignal::protocol::SenderKeyStore;
                use wacore::libsignal::store::sender_key_name::SenderKeyName;
                let mut device_guard = device_store_arc.write().await;
                let sender_address = own_sending_jid.to_protocol_address();
                let sender_key_name =
                    SenderKeyName::new(to.to_string(), sender_address.to_string());

                let key_exists = device_guard
                    .load_sender_key(&sender_key_name)
                    .await?
                    .is_some();

                force_key_distribution || !key_exists
            };

            let mut store_adapter = SignalProtocolStoreAdapter::new(device_store_arc.clone());
            
            // Create parallel processor for SKDM distribution
            let parallel_processor = ClientParallelProcessor::new(store_adapter.clone());

            let mut stores = wacore::send::SignalStores {
                session_store: &mut store_adapter.session_store,
                identity_store: &mut store_adapter.identity_store,
                prekey_store: &mut store_adapter.pre_key_store,
                signed_prekey_store: &store_adapter.signed_pre_key_store,
                sender_key_store: &mut store_adapter.sender_key_store,
            };

            match wacore::send::prepare_group_stanza(
                &mut stores,
                self,
                &mut group_info,
                &own_jid,
                &own_lid,
                account_info.as_ref(),
                to.clone(),
                message.as_ref(),
                request_id.clone(),
                force_skdm,
                edit.clone(),
                Some(&parallel_processor), // Enable parallel processing
            )
            .await
            {
                Ok(stanza) => stanza,
                Err(e) => {
                    if let Some(SignalProtocolError::NoSenderKeyState) =
                        e.downcast_ref::<SignalProtocolError>()
                    {
                        log::warn!("No sender key for group {}, forcing distribution.", to);

                        let mut store_adapter_retry =
                            SignalProtocolStoreAdapter::new(device_store_arc.clone());
                            
                        // Create parallel processor for retry
                        let parallel_processor_retry = ClientParallelProcessor::new(store_adapter_retry.clone());
                            
                        let mut stores_retry = wacore::send::SignalStores {
                            session_store: &mut store_adapter_retry.session_store,
                            identity_store: &mut store_adapter_retry.identity_store,
                            prekey_store: &mut store_adapter_retry.pre_key_store,
                            signed_prekey_store: &store_adapter_retry.signed_pre_key_store,
                            sender_key_store: &mut store_adapter_retry.sender_key_store,
                        };

                        wacore::send::prepare_group_stanza(
                            &mut stores_retry,
                            self,
                            &mut group_info,
                            &own_jid,
                            &own_lid,
                            account_info.as_ref(),
                            to,
                            message.as_ref(),
                            request_id,
                            true, // Force distribution on retry
                            edit.clone(),
                            Some(&parallel_processor_retry), // Enable parallel processing on retry
                        )
                        .await?
                    } else {
                        return Err(e);
                    }
                }
            }
        } else {
            let _ = self
                .add_recent_message(to.clone(), request_id.clone(), Arc::clone(&message))
                .await;

            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            let own_jid = device_snapshot
                .pn
                .clone()
                .ok_or_else(|| anyhow!("Not logged in"))?;
            let account_info = device_snapshot.account.clone();

            let device_store_arc = self.persistence_manager.get_device_arc().await;
            let mut store_adapter = SignalProtocolStoreAdapter::new(device_store_arc);
            
            // Create parallel processor for DM encryption
            let parallel_processor = ClientParallelProcessor::new(store_adapter.clone());

            let mut stores = wacore::send::SignalStores {
                session_store: &mut store_adapter.session_store,
                identity_store: &mut store_adapter.identity_store,
                prekey_store: &mut store_adapter.pre_key_store,
                signed_prekey_store: &store_adapter.signed_pre_key_store,
                sender_key_store: &mut store_adapter.sender_key_store,
            };

            wacore::send::prepare_dm_stanza(
                &mut stores,
                self,
                &own_jid,
                account_info.as_ref(),
                to,
                message.as_ref(),
                request_id,
                edit,
                Some(&parallel_processor), // Enable parallel processing for DMs too
            )
            .await?
        };
        self.send_node(stanza_to_send).await.map_err(|e| e.into())
    }
}
