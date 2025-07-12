use crate::binary::node::{Attrs, Node, NodeContent};
use prost::Message;
use whatsapp_proto::whatsapp as wa;

pub struct SyncUtils;

impl SyncUtils {
    /// Build the app state key request message
    /// Platform-independent core logic
    pub fn build_app_state_key_request(keys: Vec<Vec<u8>>) -> wa::Message {
        use whatsapp_proto::whatsapp::message::protocol_message;

        let key_ids = keys
            .into_iter()
            .map(|id| wa::message::AppStateSyncKeyId { key_id: Some(id) })
            .collect();

        wa::Message {
            protocol_message: Some(Box::new(wa::message::ProtocolMessage {
                r#type: Some(protocol_message::Type::AppStateSyncKeyRequest as i32),
                app_state_sync_key_request: Some(wa::message::AppStateSyncKeyRequest { key_ids }),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    /// Build the fetch app state patches query node
    /// Platform-independent core logic
    pub fn build_fetch_patches_query(name: &str, version: u64, is_full_sync: bool) -> Node {
        let mut attrs = Attrs::new();
        attrs.insert("name".to_string(), name.to_string());
        attrs.insert("return_snapshot".to_string(), is_full_sync.to_string());
        if !is_full_sync {
            attrs.insert("version".to_string(), version.to_string());
        }

        let collection_node = Node {
            tag: "collection".to_string(),
            attrs,
            content: None,
        };

        Node {
            tag: "sync".to_string(),
            attrs: Attrs::new(),
            content: Some(NodeContent::Nodes(vec![collection_node])),
        }
    }

    /// Parse app state sync response and extract patches
    /// Platform-independent core logic
    pub fn parse_sync_response(resp_node: &Node) -> Option<(bool, Vec<wa::SyncdPatch>)> {
        let sync_node = resp_node.get_optional_child("sync")?;
        let collection_node = sync_node.get_optional_child("collection")?;

        let mut attrs = collection_node.attrs();
        let has_more = attrs.optional_bool("has_more_patches");

        let mut patches = Vec::new();
        if let Some(patches_node) = collection_node.get_optional_child("patches") {
            for patch_child in patches_node.children().unwrap_or_default() {
                if let Some(NodeContent::Bytes(b)) = &patch_child.content {
                    if let Ok(patch) = wa::SyncdPatch::decode(b.as_slice()) {
                        patches.push(patch);
                    }
                }
            }
        }

        Some((has_more, patches))
    }
}
