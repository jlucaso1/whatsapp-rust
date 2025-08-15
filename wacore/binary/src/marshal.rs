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

pub fn marshal(node: &Node) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new();
    encoder.write_node(node)?;
    let node_data = encoder.into_data();

    let mut payload = Vec::with_capacity(node_data.len() + 1);
    payload.push(0);
    payload.extend_from_slice(&node_data);

    Ok(payload)
}
