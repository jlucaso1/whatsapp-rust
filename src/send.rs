use crate::binary::node::{Node, NodeContent};
use crate::client::Client;
use whatsapp_proto::whatsapp as wa;
use crate::signal::address::SignalAddress;
use crate::signal::session::SessionBuilder;
use crate::signal::state::prekey_bundle::PreKeyBundle;
use crate::signal::store::SessionStore;
use crate::signal::SessionCipher;
use crate::types::jid::{Jid, SERVER_JID};
use prost::Message as ProtoMessage;
use rand::Rng;

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
    /// This is the core sending logic.
    pub async fn send_message(&self, to: Jid, message: wa::Message) -> Result<(), anyhow::Error> {
        let store = self.store.read().await;
        if store.id.is_none() {
            return Err(anyhow::anyhow!("Not logged in"));
        }

        let signal_address = SignalAddress::new(to.user.clone(), to.device as u32);

        let store_arc = std::sync::Arc::new(store.clone());
        let mut session_record = store
            .load_session(&signal_address)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let session_exists = !session_record.is_fresh();

        if !session_exists {
            log::info!("No session found for {}, building a new one.", to);
            let bundles = self.fetch_pre_keys(&[to.clone()]).await?;
            let bundle = bundles
                .get(&to)
                .ok_or_else(|| anyhow::anyhow!("No prekey bundle for {}", to))?;
            let builder = SessionBuilder::new(store_arc.clone(), signal_address.clone());
            if let Err(e) = builder.process_bundle(&mut session_record, bundle).await {
                return Err(anyhow::anyhow!(e.to_string()));
            }
        }

        let cipher = SessionCipher::new(store_arc.clone(), signal_address.clone());
        let serialized_msg_proto = <wa::Message as ProtoMessage>::encode_to_vec(&message);

        let padded_plaintext = pad_message_v2(serialized_msg_proto);

        let encrypted_message = match cipher.encrypt(&mut session_record, &padded_plaintext).await {
            Ok(msg) => msg,
            Err(e) => return Err(anyhow::anyhow!(format!("{:?}", e))),
        };

        store_arc
            .store_session(&signal_address, &session_record)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        let enc_type = match encrypted_message.q_type() {
            crate::signal::protocol::PREKEY_TYPE => "pkmsg",
            _ => "msg",
        };

        let mut message_content_nodes = vec![crate::binary::node::Node {
            tag: "enc".to_string(),
            attrs: [
                ("v".to_string(), "2".to_string()),
                ("type".to_string(), enc_type.to_string()),
            ]
            .into(),
            content: Some(crate::binary::node::NodeContent::Bytes(
                encrypted_message.serialize(),
            )),
        }];

        if enc_type == "pkmsg" {
            if let Some(account) = &store.account {
                let device_identity_bytes = account.encode_to_vec();
                let identity_node = crate::binary::node::Node {
                    tag: "device-identity".to_string(),
                    attrs: Default::default(),
                    content: Some(crate::binary::node::NodeContent::Bytes(
                        device_identity_bytes,
                    )),
                };
                message_content_nodes.push(identity_node);
            } else {
                return Err(anyhow::anyhow!("Cannot send pre-key message: device account identity is missing from store. Please re-pair."));
            }
        }

        let stanza = crate::binary::node::Node {
            tag: "message".to_string(),
            attrs: [
                ("to".to_string(), to.to_string()),
                ("id".to_string(), self.generate_request_id()),
                ("type".to_string(), "text".to_string()),
            ]
            .into(),
            content: Some(crate::binary::node::NodeContent::Nodes(
                message_content_nodes,
            )),
        };

        self.send_node(stanza).await?;

        Ok(())
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
                    log::warn!("Failed to parse pre-key bundle for {}: {}", jid, e);
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
