use crate::binary::error::{BinaryError, Result};
use crate::binary::node::{Node, NodeContent};
use flate2::read::ZlibDecoder;
use std::borrow::Cow;
use std::fmt;
use std::io::Read;

/// Unpacks the potentially compressed frame data.
pub fn unpack(data: &[u8]) -> Result<Cow<[u8]>> {
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

// Implement Display for Node to generate an XML string for debugging.
fn fmt_node(node: &Node, f: &mut fmt::Formatter<'_>, indent: usize) -> fmt::Result {
    let indentation = "  ".repeat(indent);
    write!(
        f,
        "{}{}<{}",
        indentation,
        if indent > 0 { "\n" } else { "" },
        node.tag
    )?;

    let mut sorted_attrs: Vec<_> = node.attrs.iter().collect();
    sorted_attrs.sort_by_key(|(k, _)| *k);
    for (k, v) in sorted_attrs {
        write!(f, " {}=\"{}\"", k, v)?;
    }

    match &node.content {
        Some(content) => {
            write!(f, ">")?;
            match content {
                NodeContent::Nodes(nodes) => {
                    for child in nodes {
                        fmt_node(child, f, indent + 1)?;
                    }
                    write!(f, "\n{}</{}>", indentation, node.tag)?;
                }
                NodeContent::Bytes(bytes) => {
                    if let Ok(s) = std::str::from_utf8(bytes) {
                        if s.len() > 512 {
                            write!(f, "[{} bytes]", bytes.len())?;
                        } else {
                            write!(f, "{}", s)?;
                        }
                    } else {
                        write!(f, "{}", hex::encode(bytes))?;
                    }
                    write!(f, "</{}>", node.tag)?;
                }
            }
        }
        None => {
            write!(f, "/>")?;
        }
    }
    if indent == 0 {
        writeln!(f)?;
    }
    Ok(())
}

// Implement Display for Node using the above fmt_node function.
impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_node(self, f, 0)
    }
}
