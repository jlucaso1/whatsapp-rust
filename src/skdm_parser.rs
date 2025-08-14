/// Fast zero-copy parser for SenderKeyDistributionMessage to avoid prost allocations
/// This optimizes the hot path in handle_sender_key_distribution_message
use std::io::{Cursor, Read};

/// Lightweight SKDM parser result that avoids Vec allocations for small messages
#[derive(Debug)]
pub struct SkdmFields<'a> {
    pub id: Option<u32>,
    pub iteration: Option<u32>,
    pub chain_key: Option<&'a [u8]>,
    pub signing_key: Option<&'a [u8]>,
}

impl<'a> SkdmFields<'a> {
    /// Fast protobuf parser for SKDM that avoids allocations
    pub fn parse_zero_copy(data: &'a [u8]) -> Result<Self, &'static str> {
        let mut cursor = Cursor::new(data);
        let mut result = SkdmFields {
            id: None,
            iteration: None,
            chain_key: None,
            signing_key: None,
        };

        while cursor.position() < data.len() as u64 {
            let tag_byte = read_varint32(&mut cursor).map_err(|_| "Invalid varint")?;
            let field_num = tag_byte >> 3;
            let wire_type = tag_byte & 0x07;

            match (field_num, wire_type) {
                (1, 0) => {
                    // id: uint32
                    result.id = Some(read_varint32(&mut cursor).map_err(|_| "Invalid id varint")?);
                }
                (2, 0) => {
                    // iteration: uint32  
                    result.iteration = Some(read_varint32(&mut cursor).map_err(|_| "Invalid iteration varint")?);
                }
                (3, 2) => {
                    // chainKey: bytes
                    let len = read_varint32(&mut cursor).map_err(|_| "Invalid chainKey length")?;
                    let start = cursor.position() as usize;
                    let end = start + len as usize;
                    if end > data.len() {
                        return Err("ChainKey length exceeds data");
                    }
                    result.chain_key = Some(&data[start..end]);
                    cursor.set_position(end as u64);
                }
                (4, 2) => {
                    // signingKey: bytes
                    let len = read_varint32(&mut cursor).map_err(|_| "Invalid signingKey length")?;
                    let start = cursor.position() as usize;
                    let end = start + len as usize;
                    if end > data.len() {
                        return Err("SigningKey length exceeds data");
                    }
                    result.signing_key = Some(&data[start..end]);
                    cursor.set_position(end as u64);
                }
                _ => {
                    // Skip unknown fields
                    skip_field(&mut cursor, wire_type).map_err(|_| "Failed to skip unknown field")?;
                }
            }
        }

        Ok(result)
    }
}

fn read_varint32(cursor: &mut Cursor<&[u8]>) -> std::io::Result<u32> {
    let mut result = 0u32;
    let mut shift = 0;
    
    loop {
        if shift >= 32 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Varint too large"));
        }
        
        let mut byte = [0u8; 1];
        cursor.read_exact(&mut byte)?;
        let b = byte[0];
        
        result |= ((b & 0x7F) as u32) << shift;
        
        if (b & 0x80) == 0 {
            break;
        }
        
        shift += 7;
    }
    
    Ok(result)
}

fn skip_field(cursor: &mut Cursor<&[u8]>, wire_type: u32) -> std::io::Result<()> {
    match wire_type {
        0 => {
            // Varint
            read_varint32(cursor)?;
        }
        2 => {
            // Length-delimited
            let len = read_varint32(cursor)?;
            cursor.set_position(cursor.position() + len as u64);
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unsupported wire type",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use waproto::whatsapp as wa;
    use prost::Message;

    #[test]
    fn test_skdm_zero_copy_parser() {
        // Create a test SKDM using prost
        let test_msg = wa::SenderKeyDistributionMessage {
            id: Some(12345),
            iteration: Some(67890),
            chain_key: Some(vec![1, 2, 3, 4, 5]),
            signing_key: Some(vec![6, 7, 8, 9, 10]),
        };
        
        let encoded = test_msg.encode_to_vec();
        
        // Parse with our zero-copy parser
        let parsed = SkdmFields::parse_zero_copy(&encoded).unwrap();
        
        // Verify fields match
        assert_eq!(parsed.id, Some(12345));
        assert_eq!(parsed.iteration, Some(67890));
        assert_eq!(parsed.chain_key, Some(&[1, 2, 3, 4, 5][..]));
        assert_eq!(parsed.signing_key, Some(&[6, 7, 8, 9, 10][..]));
    }
}