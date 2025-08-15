use crate::binary::decoder::Decoder;
use crate::binary::encoder::Encoder;

pub mod attrs;
pub mod builder;
pub mod consts;
mod decoder;
mod encoder;
pub mod error;
pub mod node;
pub mod token;
pub mod util;
mod xml;

pub use error::{BinaryError, Result};
pub use node::{Node, NodeRef};

/// Parses the binary data into a reference-based, zero-copy structure.
/// The returned `NodeRef` borrows from the input `data` slice.
pub fn unmarshal_ref(data: &[u8]) -> Result<NodeRef<'_>> {
    let mut decoder = Decoder::new(data);
    let node = decoder.read_node_ref()?;

    if decoder.is_finished() {
        Ok(node)
    } else {
        Err(BinaryError::LeftoverData(decoder.bytes_left()))
    }
}

/// Encodes a `Node` into a `Vec<u8>`.
/// This is the Rust equivalent of `waBinary.Marshal`.
pub fn marshal(node: &Node) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new();
    encoder.write_node(node)?;
    let node_data = encoder.into_data();

    // Prepend the uncompressed flag byte (0) as required by the protocol
    let mut payload = Vec::with_capacity(node_data.len() + 1);
    payload.push(0);
    payload.extend_from_slice(&node_data);

    Ok(payload)
}
