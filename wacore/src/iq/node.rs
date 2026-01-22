//! Helper functions for parsing protocol nodes in IQ responses.
//!
//! These functions provide a consistent way to extract required and optional
//! children/attributes from protocol nodes with clear error messages.

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
