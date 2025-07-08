use crate::binary::node::{Node, NodeContent};
use crate::client::Client;
use crate::signal::address::SignalAddress;
use crate::signal::session::SessionBuilder;
use crate::signal::state::prekey_bundle::PreKeyBundle;
use crate::signal::store::SessionStore;
use crate::signal::SessionCipher;
use crate::types::jid::{Jid, SERVER_JID};
use rand::Rng;
use whatsapp_proto::whatsapp as wa;
use whatsapp_proto::whatsapp::message::DeviceSentMessage;

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
        use crate::binary::node::{Node, NodeContent};
        use prost::Message as ProtoMessage;

        let store = self.store.read().await;
        let own_jid = store
            .id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Not logged in"))?;
        drop(store);

        let request_id = self.generate_request_id();

        // Cache the outgoing message for retry support
        self.add_recent_message(to.clone(), request_id.clone(), message.clone())
            .await;

        // Prepare two payloads
        let message_plaintext = message.encode_to_vec();
        let dsm = wa::Message {
            device_sent_message: Some(Box::new(DeviceSentMessage {
                destination_jid: Some(to.to_string()),
                message: Some(Box::new(message.clone())),
                phash: Some("".to_string()),
            })),
            ..Default::default()
        };
        let dsm_plaintext = dsm.encode_to_vec();

        // Get all devices for both sender and recipient
        let participants = vec![to.clone(), own_jid.clone()];
        let all_devices = self.get_user_devices(&participants).await?;

        let mut participant_nodes = Vec::new();
        let mut includes_prekey_message = false;

        let store_arc = self.store.clone();

        for device_jid in all_devices {
            let is_own_device =
                device_jid.user == own_jid.user && device_jid.device != own_jid.device;
            let plaintext_to_encrypt = if is_own_device {
                &dsm_plaintext
            } else {
                &message_plaintext
            };

            let padded_plaintext = pad_message_v2(plaintext_to_encrypt.clone());

            let signal_address =
                SignalAddress::new(device_jid.user.clone(), device_jid.device as u32);
            let mut session_record = store_arc
                .load_session(&signal_address)
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            let mut is_prekey_msg = false;

            if session_record.is_fresh() {
                let bundles = self.fetch_pre_keys(&[device_jid.clone()]).await?;
                let bundle = bundles
                    .get(&device_jid)
                    .ok_or_else(|| anyhow::anyhow!("No prekey bundle for {}", device_jid))?;
                let builder = SessionBuilder::new(store_arc.clone(), signal_address.clone());
                builder.process_bundle(&mut session_record, bundle).await?;
                is_prekey_msg = true;
            }

            let cipher = SessionCipher::new(store_arc.clone(), signal_address.clone());
            let encrypted_message = cipher
                .encrypt(&mut session_record, &padded_plaintext)
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            store_arc
                .store_session(&signal_address, &session_record)
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;

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
            let store_guard = self.store.read().await;
            if let Some(account) = &store_guard.account {
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

    /// Fetch all devices for the given JIDs (stub, needs real usync IQ).
    pub async fn get_user_devices(&self, jids: &[Jid]) -> Result<Vec<Jid>, anyhow::Error> {
        // TODO: Replace this stub with a real usync IQ device fetch.
        let mut devices = Vec::new();
        for jid in jids {
            devices.push(jid.clone());
        }
        Ok(devices)
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
            let (id, key) = self.node_to_pre_key(pre_key_node)?;
            pre_key_id = Some(id);
            pre_key_public = Some(key);
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
    ) -> Result<(u32, crate::signal::ecc::keys::DjbEcPublicKey), anyhow::Error> {
        let id_bytes = node
            .get_optional_child("id")
            .and_then(|n| n.content.as_ref())
            .and_then(|c| {
                if let NodeContent::Bytes(b) = c {
                    Some(b.clone())
                } else {
                    None
                }
            })
            .ok_or(anyhow::anyhow!("Missing pre-key ID"))?;
        if id_bytes.len() != 3 {
            return Err(anyhow::anyhow!("Invalid pre-key ID length"));
        }
        let id = u32::from_be_bytes([0, id_bytes[0], id_bytes[1], id_bytes[2]]);

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

        Ok((
            id,
            crate::signal::ecc::keys::DjbEcPublicKey::new(value_bytes.try_into().unwrap()),
        ))
    }

    fn node_to_signed_pre_key(
        &self,
        node: &Node,
    ) -> Result<(u32, crate::signal::ecc::keys::DjbEcPublicKey, [u8; 64]), anyhow::Error> {
        let (id, public_key) = self.node_to_pre_key(node)?;
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
