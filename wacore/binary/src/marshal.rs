use std::io::Write;

use crate::{
    BinaryError, Node, NodeRef, Result,
    decoder::Decoder,
    encoder::{Encoder, build_marshaled_node_plan, build_marshaled_node_ref_plan},
    node::{NodeContent, NodeContentRef},
};

const DEFAULT_MARSHAL_CAPACITY: usize = 1024;
const AUTO_RESERVE_ATTRS_THRESHOLD: usize = 24;
const AUTO_RESERVE_CHILDREN_THRESHOLD: usize = 64;
const AUTO_RESERVE_SCALAR_THRESHOLD: usize = 8 * 1024;
const AUTO_CHILD_SAMPLE_LIMIT: usize = 32;
const AUTO_MAX_HINT_CAPACITY: usize = 512 * 1024;
const AUTO_ATTR_ESTIMATE: usize = 24;
const AUTO_CHILD_ESTIMATE: usize = 96;
const AUTO_GRANDCHILD_ESTIMATE: usize = 40;

pub fn unmarshal_ref(data: &[u8]) -> Result<NodeRef<'_>> {
    let mut decoder = Decoder::new(data);
    let node = decoder.read_node_ref()?;

    if decoder.is_finished() {
        Ok(node)
    } else {
        Err(BinaryError::LeftoverData(decoder.bytes_left()))
    }
}

pub fn marshal_to(node: &Node, writer: &mut impl Write) -> Result<()> {
    let mut encoder = Encoder::new(writer)?;
    encoder.write_node(node)?;
    Ok(())
}

/// Serialize an owned node directly into a `Vec<u8>` using the fast vec writer path.
pub fn marshal_to_vec(node: &Node, output: &mut Vec<u8>) -> Result<()> {
    let mut encoder = Encoder::new_vec(output)?;
    encoder.write_node(node)?;
    Ok(())
}

pub fn marshal(node: &Node) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(DEFAULT_MARSHAL_CAPACITY);
    marshal_to_vec(node, &mut payload)?;
    Ok(payload)
}

/// Serialize a `Node` using a conservative auto strategy.
///
/// This keeps the fast one-pass path for typical payloads and only uses
/// a lightweight preallocation hint for obviously larger payload shapes.
pub fn marshal_auto(node: &Node) -> Result<Vec<u8>> {
    if should_auto_reserve_node(node) {
        marshal_with_capacity(node, estimate_capacity_node(node))
    } else {
        marshal(node)
    }
}

/// Serialize a `Node` using a two-pass strategy:
/// 1) compute exact encoded size
/// 2) write directly into a fixed-size output buffer
///
/// This avoids output buffer growth/copies and can be beneficial for large/variable payloads.
pub fn marshal_exact(node: &Node) -> Result<Vec<u8>> {
    let plan = build_marshaled_node_plan(node);
    let mut payload = vec![0; plan.size];
    let mut encoder = Encoder::new_slice(payload.as_mut_slice(), Some(&plan.hints))?;
    encoder.write_node(node)?;
    let written = encoder.bytes_written();
    debug_assert_eq!(written, payload.len(), "plan size mismatch for Node");
    payload.truncate(written);
    Ok(payload)
}

/// Zero-copy serialization of a `NodeRef` directly into a writer.
/// This avoids the allocation overhead of converting to an owned `Node` first.
pub fn marshal_ref_to(node: &NodeRef<'_>, writer: &mut impl Write) -> Result<()> {
    let mut encoder = Encoder::new(writer)?;
    encoder.write_node(node)?;
    Ok(())
}

/// Serialize a borrowed node directly into a `Vec<u8>` using the fast vec writer path.
pub fn marshal_ref_to_vec(node: &NodeRef<'_>, output: &mut Vec<u8>) -> Result<()> {
    let mut encoder = Encoder::new_vec(output)?;
    encoder.write_node(node)?;
    Ok(())
}

/// Zero-copy serialization of a `NodeRef` to a new `Vec<u8>`.
/// Prefer `marshal_ref_to` with a reusable buffer for best performance.
pub fn marshal_ref(node: &NodeRef<'_>) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(DEFAULT_MARSHAL_CAPACITY);
    marshal_ref_to_vec(node, &mut payload)?;
    Ok(payload)
}

/// Serialize a `NodeRef` using the same conservative auto strategy as `marshal_auto`.
pub fn marshal_ref_auto(node: &NodeRef<'_>) -> Result<Vec<u8>> {
    if should_auto_reserve_node_ref(node) {
        marshal_ref_with_capacity(node, estimate_capacity_node_ref(node))
    } else {
        marshal_ref(node)
    }
}

/// Serialize a `NodeRef` using a two-pass exact-size strategy.
///
/// This avoids output buffer growth/copies and preserves zero-copy input semantics.
pub fn marshal_ref_exact(node: &NodeRef<'_>) -> Result<Vec<u8>> {
    let plan = build_marshaled_node_ref_plan(node);
    let mut payload = vec![0; plan.size];
    let mut encoder = Encoder::new_slice(payload.as_mut_slice(), Some(&plan.hints))?;
    encoder.write_node(node)?;
    let written = encoder.bytes_written();
    debug_assert_eq!(written, payload.len(), "plan size mismatch for NodeRef");
    payload.truncate(written);
    Ok(payload)
}

#[inline]
fn marshal_with_capacity(node: &Node, capacity: usize) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(capacity);
    marshal_to_vec(node, &mut payload)?;
    Ok(payload)
}

#[inline]
fn marshal_ref_with_capacity(node: &NodeRef<'_>, capacity: usize) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(capacity);
    marshal_ref_to_vec(node, &mut payload)?;
    Ok(payload)
}

#[inline]
fn should_auto_reserve_node(node: &Node) -> bool {
    if node.attrs.len() >= AUTO_RESERVE_ATTRS_THRESHOLD {
        return true;
    }

    match &node.content {
        Some(NodeContent::Bytes(bytes)) => bytes.len() >= AUTO_RESERVE_SCALAR_THRESHOLD,
        Some(NodeContent::String(text)) => text.len() >= AUTO_RESERVE_SCALAR_THRESHOLD,
        Some(NodeContent::Nodes(children)) => children.len() >= AUTO_RESERVE_CHILDREN_THRESHOLD,
        None => false,
    }
}

#[inline]
fn should_auto_reserve_node_ref(node: &NodeRef<'_>) -> bool {
    if node.attrs.len() >= AUTO_RESERVE_ATTRS_THRESHOLD {
        return true;
    }

    match node.content.as_deref() {
        Some(NodeContentRef::Bytes(bytes)) => bytes.len() >= AUTO_RESERVE_SCALAR_THRESHOLD,
        Some(NodeContentRef::String(text)) => text.len() >= AUTO_RESERVE_SCALAR_THRESHOLD,
        Some(NodeContentRef::Nodes(children)) => children.len() >= AUTO_RESERVE_CHILDREN_THRESHOLD,
        None => false,
    }
}

#[inline]
fn estimate_capacity_node(node: &Node) -> usize {
    let mut estimate = DEFAULT_MARSHAL_CAPACITY + 16;
    estimate += node.tag.len();
    estimate += node.attrs.len() * AUTO_ATTR_ESTIMATE;

    match &node.content {
        Some(NodeContent::Bytes(bytes)) => {
            estimate += bytes.len() + 8;
        }
        Some(NodeContent::String(text)) => {
            estimate += text.len() + 8;
        }
        Some(NodeContent::Nodes(children)) => {
            estimate += children.len() * AUTO_CHILD_ESTIMATE;
            for child in children.iter().take(AUTO_CHILD_SAMPLE_LIMIT) {
                estimate += child.tag.len() + child.attrs.len() * AUTO_ATTR_ESTIMATE;
                match &child.content {
                    Some(NodeContent::Bytes(bytes)) => estimate += bytes.len() + 8,
                    Some(NodeContent::String(text)) => estimate += text.len() + 8,
                    Some(NodeContent::Nodes(grand_children)) => {
                        estimate += grand_children.len() * AUTO_GRANDCHILD_ESTIMATE;
                    }
                    None => {}
                }
                if estimate >= AUTO_MAX_HINT_CAPACITY {
                    return AUTO_MAX_HINT_CAPACITY;
                }
            }
        }
        None => {}
    }

    estimate.clamp(DEFAULT_MARSHAL_CAPACITY, AUTO_MAX_HINT_CAPACITY)
}

#[inline]
fn estimate_capacity_node_ref(node: &NodeRef<'_>) -> usize {
    let mut estimate = DEFAULT_MARSHAL_CAPACITY + 16;
    estimate += node.tag.len();
    estimate += node.attrs.len() * AUTO_ATTR_ESTIMATE;

    match node.content.as_deref() {
        Some(NodeContentRef::Bytes(bytes)) => {
            estimate += bytes.len() + 8;
        }
        Some(NodeContentRef::String(text)) => {
            estimate += text.len() + 8;
        }
        Some(NodeContentRef::Nodes(children)) => {
            estimate += children.len() * AUTO_CHILD_ESTIMATE;
            for child in children.iter().take(AUTO_CHILD_SAMPLE_LIMIT) {
                estimate += child.tag.len() + child.attrs.len() * AUTO_ATTR_ESTIMATE;
                match child.content.as_deref() {
                    Some(NodeContentRef::Bytes(bytes)) => estimate += bytes.len() + 8,
                    Some(NodeContentRef::String(text)) => estimate += text.len() + 8,
                    Some(NodeContentRef::Nodes(grand_children)) => {
                        estimate += grand_children.len() * AUTO_GRANDCHILD_ESTIMATE;
                    }
                    None => {}
                }
                if estimate >= AUTO_MAX_HINT_CAPACITY {
                    return AUTO_MAX_HINT_CAPACITY;
                }
            }
        }
        None => {}
    }

    estimate.clamp(DEFAULT_MARSHAL_CAPACITY, AUTO_MAX_HINT_CAPACITY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jid::Jid;
    use crate::node::{Attrs, NodeContent, NodeValue};

    type TestResult = crate::error::Result<()>;

    fn fixture_node() -> Node {
        let mut attrs = Attrs::with_capacity(4);
        attrs.push("id".to_string(), "ABC123");
        attrs.push("to".to_string(), "123456789@s.whatsapp.net");
        attrs.push(
            "participant".to_string(),
            NodeValue::Jid("15551234567@s.whatsapp.net".parse::<Jid>().unwrap()),
        );
        attrs.push("hex".to_string(), "DEADBEEF");

        let child = Node::new(
            "item",
            Attrs::new(),
            Some(NodeContent::Bytes(vec![1, 2, 3, 4, 5, 6, 7, 8])),
        );

        Node::new(
            "message",
            attrs,
            Some(NodeContent::Nodes(vec![
                child,
                Node::new(
                    "text",
                    Attrs::new(),
                    Some(NodeContent::String("hello".repeat(40))),
                ),
            ])),
        )
    }

    fn large_binary_fixture() -> Node {
        Node::new(
            "message",
            Attrs::new(),
            Some(NodeContent::Bytes(vec![
                0xAB;
                AUTO_RESERVE_SCALAR_THRESHOLD + 2048
            ])),
        )
    }

    #[test]
    fn test_marshaled_node_size_matches_output() -> TestResult {
        let node = fixture_node();
        let plan = build_marshaled_node_plan(&node);
        let payload = marshal(&node)?;
        assert_eq!(payload.len(), plan.size);
        Ok(())
    }

    #[test]
    fn test_marshaled_node_ref_size_matches_output() -> TestResult {
        let node = fixture_node();
        let node_ref = node.as_node_ref();
        let plan = build_marshaled_node_ref_plan(&node_ref);
        let payload = marshal_ref(&node_ref)?;
        assert_eq!(payload.len(), plan.size);
        Ok(())
    }

    #[test]
    fn test_marshal_matches_marshal_to_bytes() -> TestResult {
        let node = fixture_node();

        let payload_alloc = marshal(&node)?;

        let mut payload_writer = Vec::new();
        marshal_to(&node, &mut payload_writer)?;

        assert_eq!(payload_alloc, payload_writer);
        Ok(())
    }

    #[test]
    fn test_marshal_ref_matches_marshal_ref_to_bytes() -> TestResult {
        let node = fixture_node();
        let node_ref = node.as_node_ref();

        let payload_alloc = marshal_ref(&node_ref)?;

        let mut payload_writer = Vec::new();
        marshal_ref_to(&node_ref, &mut payload_writer)?;

        assert_eq!(payload_alloc, payload_writer);
        Ok(())
    }

    #[test]
    fn test_marshal_to_vec_matches_marshal_to() -> TestResult {
        let node = fixture_node();

        let mut payload_vec_writer = Vec::new();
        marshal_to_vec(&node, &mut payload_vec_writer)?;

        let mut payload_writer = Vec::new();
        marshal_to(&node, &mut payload_writer)?;

        assert_eq!(payload_vec_writer, payload_writer);
        Ok(())
    }

    #[test]
    fn test_marshal_ref_to_vec_matches_marshal_ref_to() -> TestResult {
        let node = fixture_node();
        let node_ref = node.as_node_ref();

        let mut payload_vec_writer = Vec::new();
        marshal_ref_to_vec(&node_ref, &mut payload_vec_writer)?;

        let mut payload_writer = Vec::new();
        marshal_ref_to(&node_ref, &mut payload_writer)?;

        assert_eq!(payload_vec_writer, payload_writer);
        Ok(())
    }

    #[test]
    fn test_marshal_exact_matches_marshal_to_bytes() -> TestResult {
        let node = fixture_node();

        let payload_exact = marshal_exact(&node)?;

        let mut payload_writer = Vec::new();
        marshal_to(&node, &mut payload_writer)?;

        assert_eq!(payload_exact, payload_writer);
        Ok(())
    }

    #[test]
    fn test_marshal_ref_exact_matches_marshal_ref_to_bytes() -> TestResult {
        let node = fixture_node();
        let node_ref = node.as_node_ref();

        let payload_exact = marshal_ref_exact(&node_ref)?;

        let mut payload_writer = Vec::new();
        marshal_ref_to(&node_ref, &mut payload_writer)?;

        assert_eq!(payload_exact, payload_writer);
        Ok(())
    }

    #[test]
    fn test_marshal_auto_matches_marshal_to_bytes() -> TestResult {
        let node = fixture_node();
        let payload_auto = marshal_auto(&node)?;

        let mut payload_writer = Vec::new();
        marshal_to(&node, &mut payload_writer)?;

        assert_eq!(payload_auto, payload_writer);
        Ok(())
    }

    #[test]
    fn test_marshal_ref_auto_matches_marshal_ref_to_bytes() -> TestResult {
        let node = fixture_node();
        let node_ref = node.as_node_ref();
        let payload_auto = marshal_ref_auto(&node_ref)?;

        let mut payload_writer = Vec::new();
        marshal_ref_to(&node_ref, &mut payload_writer)?;

        assert_eq!(payload_auto, payload_writer);
        Ok(())
    }

    #[test]
    fn test_marshal_auto_large_binary_matches_marshal_to_bytes() -> TestResult {
        let node = large_binary_fixture();
        let payload_auto = marshal_auto(&node)?;

        let mut payload_writer = Vec::new();
        marshal_to(&node, &mut payload_writer)?;

        assert_eq!(payload_auto, payload_writer);
        Ok(())
    }

    #[test]
    fn test_marshal_ref_auto_large_binary_matches_marshal_ref_to_bytes() -> TestResult {
        let node = large_binary_fixture();
        let node_ref = node.as_node_ref();
        let payload_auto = marshal_ref_auto(&node_ref)?;

        let mut payload_writer = Vec::new();
        marshal_ref_to(&node_ref, &mut payload_writer)?;

        assert_eq!(payload_auto, payload_writer);
        Ok(())
    }
}
