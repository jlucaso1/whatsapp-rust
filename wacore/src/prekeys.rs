use crate::binary::builder::NodeBuilder;
use crate::binary::node::{Node, NodeContent};
use crate::libsignal::protocol::{IdentityKey, PreKeyBundle, PreKeyId, PublicKey, SignedPreKeyId};
use crate::types::jid::Jid;
use std::collections::HashMap;

pub struct PreKeyUtils;

impl PreKeyUtils {
    pub fn build_fetch_prekeys_request(jids: &[Jid], reason: Option<&str>) -> Node {
        let user_nodes = jids.iter().map(|jid| {
            let mut user_builder = NodeBuilder::new("user").attr("jid", jid.to_string());
            if let Some(r) = reason {
                user_builder = user_builder.attr("reason", r);
            }
            user_builder.build()
        });

        NodeBuilder::new("key").children(user_nodes).build()
    }

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
                    continue;
                }
            };
            bundles.insert(jid, bundle);
        }

        Ok(bundles)
    }

    fn node_to_pre_key_bundle(jid: &Jid, node: &Node) -> Result<PreKeyBundle, anyhow::Error> {
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

        let identity_key_array: [u8; 32] =
            identity_key_bytes.try_into().map_err(|v: Vec<u8>| {
                anyhow::anyhow!("Invalid identity key length: got {}, expected 32", v.len())
            })?;

        let identity_key =
            IdentityKey::new(PublicKey::from_djb_public_key_bytes(&identity_key_array)?);

        let mut pre_key_tuple = None;
        if let Some(pre_key_node) = keys_node.get_optional_child("key")
            && let Some((id, key_bytes)) = Self::node_to_pre_key(pre_key_node)?
        {
            let pre_key_id: PreKeyId = id.into();
            let pre_key_public = PublicKey::from_djb_public_key_bytes(&key_bytes)?;
            pre_key_tuple = Some((pre_key_id, pre_key_public));
        }

        let signed_pre_key_node = keys_node
            .get_optional_child("skey")
            .ok_or(anyhow::anyhow!("Missing signed prekey"))?;
        let (signed_pre_key_id_u32, signed_pre_key_public_bytes, signed_pre_key_signature) =
            Self::node_to_signed_pre_key(signed_pre_key_node)?;

        let signed_pre_key_id: SignedPreKeyId = signed_pre_key_id_u32.into();
        let signed_pre_key_public =
            PublicKey::from_djb_public_key_bytes(&signed_pre_key_public_bytes)?;

        let bundle = PreKeyBundle::new(
            registration_id,
            (jid.device as u32).into(),
            pre_key_tuple,
            signed_pre_key_id,
            signed_pre_key_public,
            signed_pre_key_signature.to_vec(),
            identity_key,
        )?;

        Ok(bundle)
    }

    fn node_to_pre_key(node: &Node) -> Result<Option<(u32, [u8; 32])>, anyhow::Error> {
        let id_node_content = node
            .get_optional_child("id")
            .and_then(|n| n.content.as_ref());

        let id = match id_node_content {
            Some(NodeContent::Bytes(b)) if !b.is_empty() => {
                if b.len() == 3 {
                    Ok(u32::from_be_bytes([0, b[0], b[1], b[2]]))
                } else if let Ok(s) = std::str::from_utf8(b) {
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
            _ => Err(anyhow::anyhow!("Missing or empty pre-key ID content")),
        };

        let id = match id {
            Ok(val) => val,
            Err(_e) => return Ok(None),
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

        Ok(Some((id, value_bytes.try_into().unwrap())))
    }

    fn node_to_signed_pre_key(node: &Node) -> Result<(u32, [u8; 32], [u8; 64]), anyhow::Error> {
        let (id, public_key_bytes) = match Self::node_to_pre_key(node)? {
            Some((id, key)) => (id, key),
            None => return Err(anyhow::anyhow!("Signed pre-key is missing ID or value")),
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

        Ok((id, public_key_bytes, signature_bytes.try_into().unwrap()))
    }
}
