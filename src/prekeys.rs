use crate::binary::node::NodeContent;
use crate::client::Client;
use crate::types::jid::{Jid, SERVER_JID};
use libsignal_protocol::PreKeyBundle;
use log;

use crate::binary::builder::NodeBuilder;
use crate::request::{InfoQuery, InfoQueryType};

use anyhow;
use libsignal_protocol::KeyPair;
use rand::TryRngCore;
use wacore::signal::state::record::new_pre_key_record;

pub use wacore::prekeys::PreKeyUtils;

const WANTED_PRE_KEY_COUNT: usize = 50;
const MIN_PRE_KEY_COUNT: usize = 5;

impl Client {
    pub async fn fetch_pre_keys(
        &self,
        jids: &[Jid],
        reason: Option<&str>,
    ) -> Result<std::collections::HashMap<Jid, PreKeyBundle>, anyhow::Error> {
        if self.test_mode.load(std::sync::atomic::Ordering::Relaxed) {
            use libsignal_protocol::{
                DeviceId, IdentityKey, PreKeyBundle, PreKeyId, PublicKey, SignedPreKeyId,
            };

            let mut bundles = std::collections::HashMap::new();
            for jid in jids {
                let device_snapshot = self.persistence_manager.get_device_snapshot().await;

                let identity_public_key = PublicKey::from_djb_public_key_bytes(
                    device_snapshot
                        .core
                        .identity_key
                        .public_key
                        .public_key_bytes(),
                )?;
                let identity_key = IdentityKey::new(identity_public_key);

                let signed_pre_key_public = PublicKey::from_djb_public_key_bytes(
                    device_snapshot
                        .core
                        .signed_pre_key
                        .public_key
                        .public_key_bytes(),
                )?;
                let signed_pre_key_id: SignedPreKeyId =
                    device_snapshot.core.signed_pre_key_id.into();
                let signed_pre_key_signature =
                    device_snapshot.core.signed_pre_key_signature.to_vec();

                let pre_key_id: PreKeyId = 1u32.into();
                let pre_key_public = identity_public_key;
                let pre_key_tuple = Some((pre_key_id, pre_key_public));

                let bundle = PreKeyBundle::new(
                    device_snapshot.core.registration_id,
                    DeviceId::from(jid.device as u32),
                    pre_key_tuple,
                    signed_pre_key_id,
                    signed_pre_key_public,
                    signed_pre_key_signature,
                    identity_key,
                )?;
                bundles.insert(jid.clone(), bundle);
            }
            return Ok(bundles);
        }

        let content = PreKeyUtils::build_fetch_prekeys_request(jids, reason);

        let resp_node = self
            .send_iq(crate::request::InfoQuery {
                namespace: "encrypt",
                query_type: crate::request::InfoQueryType::Get,
                to: SERVER_JID.parse().unwrap(),
                content: Some(NodeContent::Nodes(vec![content])),
                id: None,
                target: None,
                timeout: None,
            })
            .await?;

        let bundles = PreKeyUtils::parse_prekeys_response(&resp_node)?;

        for jid in bundles.keys() {
            log::debug!("Successfully parsed pre-key bundle for {jid}");
        }

        Ok(bundles)
    }

    /// Query the WhatsApp server for how many pre-keys it currently has for this device.
    pub async fn get_server_pre_key_count(&self) -> Result<usize, crate::request::IqError> {
        let count_node = NodeBuilder::new("count").build();
        let iq = InfoQuery {
            namespace: "encrypt",
            query_type: InfoQueryType::Get,
            to: SERVER_JID.parse().unwrap(),
            content: Some(crate::binary::node::NodeContent::Nodes(vec![count_node])),
            id: None,
            target: None,
            timeout: None,
        };

        let resp_node = self.send_iq(iq).await?;
        let count_resp_node = resp_node.get_optional_child("count").ok_or_else(|| {
            crate::request::IqError::ServerError {
                code: 500,
                text: "Missing count node in response".to_string(),
            }
        })?;

        let count_str = count_resp_node
            .attrs()
            .optional_string("value")
            .unwrap_or("0");
        let count = count_str.parse::<usize>().unwrap_or(0);
        Ok(count)
    }

    /// Ensure the server has at least MIN_PRE_KEY_COUNT pre-keys, and upload a batch of
    /// WANTED_PRE_KEY_COUNT pre-keys when it is below the threshold.
    pub async fn upload_pre_keys(&self) -> Result<(), anyhow::Error> {
        let server_count = match self.get_server_pre_key_count().await {
            Ok(c) => c,
            Err(e) => return Err(anyhow::anyhow!(e)),
        };

        if server_count >= MIN_PRE_KEY_COUNT {
            log::info!("Server has {} pre-keys, no upload needed.", server_count);
            return Ok(());
        }

        log::info!("Server has {} pre-keys, uploading more.", server_count);

        let device_snapshot = self.persistence_manager.get_device_snapshot().await;

        let mut pre_key_nodes = Vec::new();
        let mut new_pre_keys_to_store: Vec<(u32, waproto::whatsapp::PreKeyRecordStructure)> =
            Vec::new();

        // Pre-key IDs should be random within the valid range (1 to 0xFFFFFF).
        for _ in 0..WANTED_PRE_KEY_COUNT {
            let pre_key_id = (rand::random::<u32>() % 16777215) + 1;
            let key_pair = KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
            let pre_key_record = new_pre_key_record(pre_key_id, &key_pair);

            // The ID is sent as 3 bytes, big-endian.
            let id_bytes = pre_key_id.to_be_bytes()[1..].to_vec();
            let node = NodeBuilder::new("key")
                .children([
                    NodeBuilder::new("id").bytes(id_bytes).build(),
                    NodeBuilder::new("value")
                        .bytes(key_pair.public_key.public_key_bytes().to_vec())
                        .build(),
                ])
                .build();
            pre_key_nodes.push(node);
            new_pre_keys_to_store.push((pre_key_id, pre_key_record));
        }

        let registration_id_bytes = device_snapshot.registration_id.to_be_bytes().to_vec();

        // Construct the signed pre-key node from the device store
        let signed_pre_key_id_bytes = device_snapshot.signed_pre_key_id.to_be_bytes()[1..].to_vec();
        let signed_pre_key_node = NodeBuilder::new("skey")
            .children([
                NodeBuilder::new("id")
                    .bytes(signed_pre_key_id_bytes)
                    .build(),
                NodeBuilder::new("value")
                    .bytes(
                        device_snapshot
                            .signed_pre_key
                            .public_key
                            .public_key_bytes()
                            .to_vec(),
                    )
                    .build(),
                NodeBuilder::new("signature")
                    .bytes(device_snapshot.signed_pre_key_signature.to_vec())
                    .build(),
            ])
            .build();

        let type_bytes = vec![5u8];

        let iq_content = vec![
            NodeBuilder::new("registration")
                .bytes(registration_id_bytes)
                .build(),
            NodeBuilder::new("type").bytes(type_bytes.clone()).build(),
            NodeBuilder::new("identity")
                .bytes(
                    device_snapshot
                        .identity_key
                        .public_key
                        .public_key_bytes()
                        .to_vec(),
                )
                .build(),
            NodeBuilder::new("list").children(pre_key_nodes).build(),
            signed_pre_key_node,
        ];

        let iq = InfoQuery {
            namespace: "encrypt",
            query_type: InfoQueryType::Set,
            to: SERVER_JID.parse().unwrap(),
            content: Some(crate::binary::node::NodeContent::Nodes(iq_content)),
            id: None,
            target: None,
            timeout: None,
        };

        // Send IQ to upload pre-keys
        if let Err(e) = self.send_iq(iq).await {
            return Err(anyhow::anyhow!(e));
        }

        // Persist the new pre-keys using the backend (delegate to storage implementation)
        let device_store = self.persistence_manager.get_device_arc().await;
        let device_guard = device_store.read().await;
        for (id, record) in new_pre_keys_to_store {
            if let Err(e) = device_guard.backend.store_prekey(id, record).await {
                log::warn!("Failed to store prekey id {}: {:?}", id, e);
            }
        }

        log::info!(
            "Successfully uploaded {} new pre-keys.",
            WANTED_PRE_KEY_COUNT
        );

        Ok(())
    }
}
