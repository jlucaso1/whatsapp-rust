use std::borrow::Cow;

use crate::protocol::ProtocolNode;
use anyhow::anyhow;
use wacore_binary::NodeRef;

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
