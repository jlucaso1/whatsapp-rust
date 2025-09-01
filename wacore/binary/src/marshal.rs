use std::io::Write;

use crate::{BinaryError, Node, NodeRef, Result, decoder::Decoder, encoder::Encoder};

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
    writer.write_all(&[0])?;
    let mut encoder = Encoder::new(writer);
    encoder.write_node(node)?;
    Ok(())
}

pub fn marshal(node: &Node) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(1024);
    marshal_to(node, &mut payload)?;
    Ok(payload)
}
