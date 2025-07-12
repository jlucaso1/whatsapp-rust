use crate::binary::node::{Node, NodeContent};
use crate::signal::state::prekey_bundle::PreKeyBundle;
use crate::types::jid::Jid;
use std::collections::HashMap;

/// Core prekey utilities that are platform-independent
pub struct PreKeyUtils;

impl PreKeyUtils {
    /// Builds the IQ node for fetching pre-key bundles
    pub fn build_fetch_prekeys_request(jids: &[Jid]) -> Node {
        let mut user_nodes = Vec::with_capacity(jids.len());
        for jid in jids {
            user_nodes.push(Node {
                tag: "user".into(),
                attrs: [("jid".to_string(), jid.to_string())].into(),
                content: None,
            });
        }

        Node {
            tag: "key".into(),
            attrs: Default::default(),
            content: Some(NodeContent::Nodes(user_nodes)),
        }
    }

    /// Parses the IQ response and extracts pre-key bundles
    pub fn parse_prekeys_response(
        resp_node: &Node,
    ) -> Result<HashMap<Jid, PreKeyBundle>, anyhow::Error> {
        let list_node = resp_node
            .get_optional_child("list")
            .ok_or_else(|| anyhow::anyhow!("<list> not found in pre-key response"))?;

        let mut bundles = HashMap::new();
        for user_node in list_node.children().unwrap_or_default() {
            if user_node.tag != "user" {
                continue;
            }
            let mut attrs = user_node.attrs();
            let jid = attrs.jid("jid");
            let bundle = match Self::node_to_pre_key_bundle(&jid, user_node) {
                Ok(b) => b,
                Err(_e) => {
                    // Log warning would be done by the driver
                    continue;
                }
            };
            bundles.insert(jid, bundle);
        }

        Ok(bundles)
    }

    fn node_to_pre_key_bundle(
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
            if let Some((id, key)) = Self::node_to_pre_key(pre_key_node)? {
                pre_key_id = Some(id);
                pre_key_public = Some(key);
            }
        }

        let signed_pre_key_node = keys_node
            .get_optional_child("skey")
            .ok_or(anyhow::anyhow!("Missing signed prekey"))?;
        let (signed_pre_key_id, signed_pre_key_public, signed_pre_key_signature) =
            Self::node_to_signed_pre_key(signed_pre_key_node)?;

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
                    let trimmed_s = s.trim();
                    if trimmed_s.is_empty() {
                        Err(anyhow::anyhow!("ID content is only whitespace"))
                    } else {
                        u32::from_str_radix(trimmed_s, 16).map_err(|e| e.into())
                    }
                } else {
                    Err(anyhow::anyhow!("ID is not valid UTF-8 hex or 3-byte int"))
                }
            }
            // ID is empty or missing, this is invalid for a one-time pre-key
            _ => Err(anyhow::anyhow!("Missing or empty pre-key ID content")),
        };

        let id = match id {
            Ok(val) => val,
            Err(_e) => {
                // Driver would log this warning
                return Ok(None);
            } // Gracefully ignore invalid one-time pre-keys
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
        node: &Node,
    ) -> Result<(u32, crate::signal::ecc::keys::DjbEcPublicKey, [u8; 64]), anyhow::Error> {
        // HACK: In some cases, the signed prekey ID is missing. The Go implementation seems to default to 1 in this scenario.
        // This is a bit of a magic number, but it matches the behavior of the reference implementation.
        let (id, public_key) = match Self::node_to_pre_key(node)? {
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