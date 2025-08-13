use crate::binary::{
    builder::NodeBuilder,
    node::{Node, NodeContent},
};
use prost::Message;
use waproto::whatsapp as wa;

pub struct SyncUtils;

impl SyncUtils {
    pub fn build_app_state_key_request(keys: Vec<Vec<u8>>) -> wa::Message {
        use waproto::whatsapp::message::protocol_message;

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

    pub fn build_fetch_patches_query(name: &str, version: u64, is_full_sync: bool) -> Node {
        let mut collection_builder = NodeBuilder::new("collection")
            .attr("name", name)
            .attr("return_snapshot", is_full_sync.to_string());

        if !is_full_sync {
            collection_builder = collection_builder.attr("version", version.to_string());
        }

        NodeBuilder::new("sync")
            .children([collection_builder.build()])
            .build()
    }

    pub fn parse_sync_response(resp_node: &Node) -> Option<(bool, Vec<wa::SyncdPatch>)> {
        let sync_node = resp_node.get_optional_child("sync")?;
        let collection_node = sync_node.get_optional_child("collection")?;

        let mut attrs = collection_node.attrs();
        let has_more = attrs.optional_bool("has_more_patches");

        let mut patches = Vec::new();
        if let Some(patches_node) = collection_node.get_optional_child("patches") {
            for patch_child in patches_node.children().unwrap_or_default() {
                if let Some(NodeContent::Bytes(b)) = &patch_child.content
                    && let Ok(patch) = wa::SyncdPatch::decode(b.as_slice())
                {
                    patches.push(patch);
                }
            }
        }

        Some((has_more, patches))
    }
}
