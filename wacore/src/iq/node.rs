//! Helper functions for parsing protocol nodes in IQ responses.
//!
//! These functions provide a consistent way to extract required and optional
//! children/attributes from protocol nodes with clear error messages.

use crate::protocol::ProtocolNode;
use anyhow::anyhow;
use wacore_binary::jid::Jid;
use wacore_binary::node::Node;

/// Get a required child node by tag, returning an error if not found.
pub fn required_child<'a>(node: &'a Node, tag: &str) -> Result<&'a Node, anyhow::Error> {
    node.get_optional_child(tag)
        .ok_or_else(|| anyhow!("<{tag}> child not found"))
}

/// Get an optional child node by tag.
pub fn optional_child<'a>(node: &'a Node, tag: &str) -> Option<&'a Node> {
    node.get_optional_child(tag)
}

/// Get a required string attribute, returning an error if not found.
pub fn required_attr(node: &Node, key: &str) -> Result<String, anyhow::Error> {
    node.attrs()
        .optional_string(key)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("missing required attribute {key}"))
}

/// Get an optional string attribute.
pub fn optional_attr<'a>(node: &'a Node, key: &str) -> Option<&'a str> {
    node.attrs().optional_string(key)
}

/// Get an optional u64 attribute.
pub fn optional_u64(node: &Node, key: &str) -> Option<u64> {
    node.attrs().optional_u64(key)
}

/// Get a required JID attribute, returning an error if not found or invalid.
pub fn required_jid(node: &Node, key: &str) -> Result<Jid, anyhow::Error> {
    let value = required_attr(node, key)?;
    value.parse().map_err(|err| anyhow!("{err}"))
}

/// Get an optional JID attribute, returning an error only if the value is invalid.
pub fn optional_jid(node: &Node, key: &str) -> Result<Option<Jid>, anyhow::Error> {
    match optional_attr(node, key) {
        Some(value) => Ok(Some(value.parse().map_err(|err| anyhow!("{err}"))?)),
        None => Ok(None),
    }
}

/// Get optional string content from a child node, skipping if an error child exists.
///
/// This is a common pattern in usync responses where a node may contain
/// an `<error>` child to indicate the data is unavailable.
pub fn optional_string_content(node: &Node, child_tag: &str) -> Option<String> {
    use wacore_binary::node::NodeContent;

    node.get_optional_child(child_tag).and_then(|child| {
        if child.get_optional_child("error").is_some() {
            return None;
        }
        match &child.content {
            Some(NodeContent::String(s)) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }
    })
}

/// Get optional JID from a child node's attribute (commonly "val").
///
/// Example: `<lid val="123@lid"/>` -> returns parsed JID
pub fn optional_jid_from_child(node: &Node, child_tag: &str, attr: &str) -> Option<Jid> {
    node.get_optional_child(child_tag)
        .and_then(|n| n.attrs().optional_string(attr))
        .and_then(|s| s.parse().ok())
}

/// Get optional string attribute from a child node, skipping if an error child exists.
pub fn optional_attr_skipping_error(node: &Node, child_tag: &str, attr: &str) -> Option<String> {
    node.get_optional_child(child_tag).and_then(|child| {
        if child.get_optional_child("error").is_some() {
            return None;
        }
        child.attrs().optional_string(attr).map(|s| s.to_string())
    })
}

/// Parse all children with a given tag into a Vec of ProtocolNodes.
///
/// Returns an error if any child fails to parse.
///
/// # Example
/// ```ignore
/// let participants = collect_children::<GroupParticipantResponse>(node, "participant")?;
/// ```
pub fn collect_children<T: ProtocolNode>(node: &Node, tag: &str) -> Result<Vec<T>, anyhow::Error> {
    node.get_children_by_tag(tag)
        .map(|child| T::try_from_node(child))
        .collect()
}

/// Parse all children with a given tag into a Vec of ProtocolNodes, skipping parse errors.
///
/// Logs a warning for each child that fails to parse.
///
/// # Example
/// ```ignore
/// let entries = collect_children_lenient::<BlocklistEntry>(node, "item");
/// ```
pub fn collect_children_lenient<T: ProtocolNode>(node: &Node, tag: &str) -> Vec<T> {
    node.get_children_by_tag(tag)
        .filter_map(|child| match T::try_from_node(child) {
            Ok(item) => Some(item),
            Err(e) => {
                log::warn!(
                    target: "iq::node",
                    "Failed to parse <{}>: {e}",
                    tag
                );
                None
            }
        })
        .collect()
}
