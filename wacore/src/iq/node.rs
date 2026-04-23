use std::borrow::Cow;

use crate::protocol::ProtocolNode;
use anyhow::anyhow;
use wacore_binary::{NodeContentRef, NodeRef};

/// Get a required child node by tag from a `NodeRef`.
pub(crate) fn required_child<'a>(
    node: &'a NodeRef<'_>,
    tag: &str,
) -> Result<&'a NodeRef<'a>, anyhow::Error> {
    node.get_optional_child(tag)
        .ok_or_else(|| anyhow!("<{tag}> child not found"))
}

/// Get an optional child node by tag from a `NodeRef`.
pub(crate) fn optional_child<'a>(node: &'a NodeRef<'_>, tag: &str) -> Option<&'a NodeRef<'a>> {
    node.get_optional_child(tag)
}

/// Get a required string attribute from a `NodeRef`.
pub(crate) fn required_attr(node: &NodeRef<'_>, key: &str) -> Result<String, anyhow::Error> {
    node.get_attr(key)
        .map(|v| v.to_string())
        .ok_or_else(|| anyhow!("missing required attribute {key}"))
}

/// Get an optional string attribute from a `NodeRef`.
pub(crate) fn optional_attr<'a>(node: &'a NodeRef<'_>, key: &str) -> Option<Cow<'a, str>> {
    node.attrs().optional_string(key)
}

/// Parse children with a given tag into a Vec using `ProtocolNode::try_from_node_ref`.
pub(crate) fn collect_children<T: ProtocolNode>(
    node: &NodeRef<'_>,
    tag: &str,
) -> Result<Vec<T>, anyhow::Error> {
    node.get_children_by_tag(tag)
        .map(|child| T::try_from_node_ref(child))
        .collect()
}

/// Extract binary content from an optional `NodeRef` as `Vec<u8>`.
/// Returns an empty vector if the node is `None` or does not hold byte content.
pub(crate) fn extract_content_bytes(node: Option<&NodeRef<'_>>) -> Vec<u8> {
    node.and_then(|n| match n.content.as_deref() {
        Some(NodeContentRef::Bytes(b)) => Some(b.to_vec()),
        _ => None,
    })
    .unwrap_or_default()
}

/// Extract binary content from an optional `NodeRef` as a big-endian `u32`.
/// Returns 0 if the node is missing or does not hold byte content. Truncates to 4 bytes.
pub(crate) fn extract_content_uint(node: Option<&NodeRef<'_>>) -> u32 {
    node.and_then(|n| match n.content.as_deref() {
        Some(NodeContentRef::Bytes(b)) => {
            let mut buf = [0u8; 4];
            let len = b.len().min(4);
            buf[4 - len..].copy_from_slice(&b[..len]);
            Some(u32::from_be_bytes(buf))
        }
        _ => None,
    })
    .unwrap_or(0)
}
