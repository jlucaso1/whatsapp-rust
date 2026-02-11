use std::io::Write;

use crate::{
    BinaryError, Node, NodeRef, Result,
    decoder::Decoder,
    encoder::{Encoder, build_marshaled_node_plan, build_marshaled_node_ref_plan},
};

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

pub fn marshal(node: &Node) -> Result<Vec<u8>> {
    let plan = build_marshaled_node_plan(node);
    let mut payload = vec![0; plan.size];
    let mut encoder = Encoder::new_slice(payload.as_mut_slice(), Some(&plan.hints))?;
    encoder.write_node(node)?;
    debug_assert_eq!(encoder.bytes_written(), payload.len());
    Ok(payload)
}

/// Zero-copy serialization of a `NodeRef` directly into a writer.
/// This avoids the allocation overhead of converting to an owned `Node` first.
pub fn marshal_ref_to(node: &NodeRef<'_>, writer: &mut impl Write) -> Result<()> {
    let mut encoder = Encoder::new(writer)?;
    encoder.write_node(node)?;
    Ok(())
}

/// Zero-copy serialization of a `NodeRef` to a new `Vec<u8>`.
/// Prefer `marshal_ref_to` with a reusable buffer for best performance.
pub fn marshal_ref(node: &NodeRef<'_>) -> Result<Vec<u8>> {
    let plan = build_marshaled_node_ref_plan(node);
    let mut payload = vec![0; plan.size];
    let mut encoder = Encoder::new_slice(payload.as_mut_slice(), Some(&plan.hints))?;
    encoder.write_node(node)?;
    debug_assert_eq!(encoder.bytes_written(), payload.len());
    Ok(payload)
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
}
