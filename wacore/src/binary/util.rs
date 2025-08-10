use crate::binary::error::{BinaryError, Result};
use crate::binary::node::{Node, NodeContent};
use flate2::read::ZlibDecoder;
use std::borrow::Cow;
use std::fmt;
use std::io::Read;

/// Unpacks the potentially compressed frame data.
pub fn unpack(data: &[u8]) -> Result<Cow<'_, [u8]>> {
    if data.is_empty() {
        return Err(BinaryError::Eof);
    }
    let data_type = data[0];
    let data = &data[1..];

    if (data_type & 2) > 0 {
        let mut decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| BinaryError::Zlib(e.to_string()))?;
        Ok(Cow::Owned(decompressed))
    } else {
        Ok(Cow::Borrowed(data))
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = vec![format!("<{}", self.tag)];

        if let Some(id) = self.attrs.get("id") {
            parts.push(format!("id=\"{}\"", id));
        }
        if let Some(from) = self.attrs.get("from") {
            parts.push(format!("from=\"{}\"", from));
        }
        if let Some(to) = self.attrs.get("to") {
            parts.push(format!("to=\"{}\"", to));
        }
        if let Some(node_type) = self.attrs.get("type") {
            parts.push(format!("type=\"{}\"", node_type));
        }
        if let Some(namespace) = self.attrs.get("xmlns") {
            parts.push(format!("xmlns=\"{}\"", namespace));
        }

        let content_summary = match &self.content {
            Some(NodeContent::Nodes(nodes)) => format!("[{} children]", nodes.len()),
            Some(NodeContent::Bytes(bytes)) => format!("[{} bytes]", bytes.len()),
            None => "".to_string(),
        };

        if content_summary.is_empty() {
            write!(f, "{} />", parts.join(" "))
        } else {
            write!(f, "{} {}/>", parts.join(" "), content_summary)
        }
    }
}
