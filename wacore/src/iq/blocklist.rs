//! Blocklist IQ types and specifications.
//!
//! This module provides type-safe structures for blocklist operations following
//! the `ProtocolNode` pattern defined in `wacore/src/protocol.rs`.

use crate::StringEnum;
use crate::iq::node::{optional_child, optional_u64};
use crate::iq::spec::IqSpec;
use crate::protocol::ProtocolNode;
use crate::request::InfoQuery;
use anyhow::{Result, anyhow};
use log::warn;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};
/// IQ namespace for blocklist operations.
pub const BLOCKLIST_IQ_NAMESPACE: &str = "blocklist";
/// Action to perform on a blocklist entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, StringEnum)]
pub enum BlocklistAction {
    #[str = "block"]
    Block,
    #[str = "unblock"]
    Unblock,
}
/// Request node for updating blocklist.
///
/// Wire format: `<item action="block|unblock" jid="...@s.whatsapp.net"/>`
#[derive(Debug, Clone)]
pub struct BlocklistItemRequest {
    pub jid: Jid,
    pub action: BlocklistAction,
}

impl BlocklistItemRequest {
    pub fn new(jid: &Jid, action: BlocklistAction) -> Self {
        Self {
            jid: jid.clone(),
            action,
        }
    }

    pub fn block(jid: &Jid) -> Self {
        Self::new(jid, BlocklistAction::Block)
    }

    pub fn unblock(jid: &Jid) -> Self {
        Self::new(jid, BlocklistAction::Unblock)
    }
}

impl ProtocolNode for BlocklistItemRequest {
    fn tag(&self) -> &'static str {
        "item"
    }

    fn into_node(self) -> Node {
        NodeBuilder::new("item")
            .attr("action", self.action.as_str())
            .attr("jid", self.jid.to_string())
            .build()
    }

    fn try_from_node(node: &Node) -> Result<Self> {
        if node.tag != "item" {
            return Err(anyhow!("expected <item>, got <{}>", node.tag));
        }

        let mut attrs = node.attrs();
        let action_str = attrs
            .optional_string("action")
            .ok_or_else(|| anyhow!("missing action attribute"))?;
        let action = BlocklistAction::try_from(action_str)?;
        let jid = attrs.optional_jid("jid");
        if let Err(e) = attrs.finish() {
            return Err(anyhow!("{e}"));
        }
        let jid = jid.ok_or_else(|| anyhow!("missing jid attribute"))?;

        Ok(Self { jid, action })
    }
}
/// A single blocklist entry from the response.
///
/// Wire format: `<item jid="...@s.whatsapp.net" t="1234567890"/>`
#[derive(Debug, Clone)]
pub struct BlocklistEntry {
    pub jid: Jid,
    pub timestamp: Option<u64>,
}

impl ProtocolNode for BlocklistEntry {
    fn tag(&self) -> &'static str {
        "item"
    }

    fn into_node(self) -> Node {
        let mut builder = NodeBuilder::new("item").attr("jid", self.jid.to_string());
        if let Some(t) = self.timestamp {
            builder = builder.attr("t", t.to_string());
        }
        builder.build()
    }

    fn try_from_node(node: &Node) -> Result<Self> {
        if node.tag != "item" {
            return Err(anyhow!("expected <item>, got <{}>", node.tag));
        }

        let mut attrs = node.attrs();
        let jid = attrs.optional_jid("jid");
        if let Err(e) = attrs.finish() {
            return Err(anyhow!("{e}"));
        }
        let jid = jid.ok_or_else(|| anyhow!("missing jid attribute"))?;
        let timestamp = optional_u64(node, "t");

        Ok(Self { jid, timestamp })
    }
}

/// Response containing the blocklist entries.
///
/// Wire format: `<list><item .../><item .../></list>` or `<item .../><item .../>`
#[derive(Debug, Clone, Default)]
pub struct BlocklistResponse {
    pub entries: Vec<BlocklistEntry>,
}

impl ProtocolNode for BlocklistResponse {
    fn tag(&self) -> &'static str {
        "list"
    }

    fn into_node(self) -> Node {
        let children: Vec<Node> = self.entries.into_iter().map(|e| e.into_node()).collect();
        NodeBuilder::new("list").children(children).build()
    }

    fn try_from_node(node: &Node) -> Result<Self> {
        // Response can be either:
        // 1. <list><item .../></list>
        // 2. Direct <item .../> children in the response node
        let entries = if let Some(list) = optional_child(node, "list") {
            list.get_children_by_tag("item")
        } else {
            node.get_children_by_tag("item")
        }
        .filter_map(|item| match BlocklistEntry::try_from_node(item) {
            Ok(entry) => Some(entry),
            Err(e) => {
                warn!(
                    target: "blocklist",
                    "Failed to parse blocklist entry: {e}"
                );
                None
            }
        })
        .collect();

        Ok(Self { entries })
    }
}
/// Fetches the blocklist.
#[derive(Debug, Default, Clone, Copy)]
pub struct GetBlocklistSpec;

impl IqSpec for GetBlocklistSpec {
    type Response = Vec<BlocklistEntry>;

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::get(BLOCKLIST_IQ_NAMESPACE, Jid::new("", SERVER_JID), None)
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response> {
        let blocklist = BlocklistResponse::try_from_node(response)?;
        Ok(blocklist.entries)
    }
}

/// Updates the blocklist (block/unblock).
#[derive(Debug, Clone)]
pub struct UpdateBlocklistSpec {
    request: BlocklistItemRequest,
}

impl UpdateBlocklistSpec {
    pub fn new(jid: &Jid, action: BlocklistAction) -> Self {
        Self {
            request: BlocklistItemRequest::new(jid, action),
        }
    }

    pub fn block(jid: &Jid) -> Self {
        Self {
            request: BlocklistItemRequest::block(jid),
        }
    }

    pub fn unblock(jid: &Jid) -> Self {
        Self {
            request: BlocklistItemRequest::unblock(jid),
        }
    }
}

impl IqSpec for UpdateBlocklistSpec {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::set(
            BLOCKLIST_IQ_NAMESPACE,
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![self.request.clone().into_node()])),
        )
    }

    fn parse_response(&self, _response: &Node) -> Result<Self::Response> {
        Ok(())
    }
}
#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn test_blocklist_action_string_enum() {
        assert_eq!(BlocklistAction::Block.as_str(), "block");
        assert_eq!(BlocklistAction::Unblock.as_str(), "unblock");
        assert_eq!(
            BlocklistAction::try_from("block").unwrap(),
            BlocklistAction::Block
        );
        assert_eq!(
            BlocklistAction::try_from("unblock").unwrap(),
            BlocklistAction::Unblock
        );
    }

    #[test]
    fn test_blocklist_item_request_into_node() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let request = BlocklistItemRequest::block(&jid);
        let node = request.into_node();

        assert_eq!(node.tag, "item");
        assert_eq!(node.attrs().string("action"), "block");
        assert_eq!(node.attrs().string("jid"), "1234567890@s.whatsapp.net");
    }

    #[test]
    fn test_blocklist_entry_into_node() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let entry = BlocklistEntry {
            jid: jid.clone(),
            timestamp: Some(1234567890),
        };
        let node = entry.into_node();

        assert_eq!(node.tag, "item");
        assert_eq!(node.attrs().string("jid"), "1234567890@s.whatsapp.net");
        assert_eq!(node.attrs().string("t"), "1234567890");
    }

    #[test]
    fn test_blocklist_entry_try_from_node() {
        let node = NodeBuilder::new("item")
            .attr("jid", "1234567890@s.whatsapp.net")
            .attr("t", "1234567890")
            .build();

        let entry = BlocklistEntry::try_from_node(&node).unwrap();
        assert_eq!(entry.jid.user, "1234567890");
        assert_eq!(entry.timestamp, Some(1234567890));
    }

    #[test]
    fn test_blocklist_response_with_list_wrapper() {
        let list_node = NodeBuilder::new("list")
            .children([
                NodeBuilder::new("item")
                    .attr("jid", "111@s.whatsapp.net")
                    .build(),
                NodeBuilder::new("item")
                    .attr("jid", "222@s.whatsapp.net")
                    .build(),
            ])
            .build();
        let response_node = NodeBuilder::new("response").children([list_node]).build();

        let response = BlocklistResponse::try_from_node(&response_node).unwrap();
        assert_eq!(response.entries.len(), 2);
        assert_eq!(response.entries[0].jid.user, "111");
        assert_eq!(response.entries[1].jid.user, "222");
    }

    #[test]
    fn test_blocklist_response_direct_items() {
        let response_node = NodeBuilder::new("response")
            .children([
                NodeBuilder::new("item")
                    .attr("jid", "111@s.whatsapp.net")
                    .build(),
                NodeBuilder::new("item")
                    .attr("jid", "222@s.whatsapp.net")
                    .build(),
            ])
            .build();

        let response = BlocklistResponse::try_from_node(&response_node).unwrap();
        assert_eq!(response.entries.len(), 2);
    }

    #[test]
    fn test_update_blocklist_spec_convenience_methods() {
        let jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();

        let block_spec = UpdateBlocklistSpec::block(&jid);
        assert_eq!(block_spec.request.action, BlocklistAction::Block);

        let unblock_spec = UpdateBlocklistSpec::unblock(&jid);
        assert_eq!(unblock_spec.request.action, BlocklistAction::Unblock);
    }
}
