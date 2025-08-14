use std::io::{Cursor, Read};

/// Zero-copy parser for SenderKeyDistributionMessage (SKDM) protobuf blobs.
///
/// This parser is performance-focused and returns slices directly
/// referencing the input buffer where possible (i.e. zero-copy).
#[derive(Debug)]
pub struct SkdmFields<'a> {
    pub id: Option<u32>,
    pub iteration: Option<u32>,
    pub chain_key: Option<&'a [u8]>,
    pub signing_key: Option<&'a [u8]>,
}

impl<'a> SkdmFields<'a> {
    /// Parse a SKDM protobuf message in a zero-copy manner.
    ///
    /// Returns `SkdmFields` where `chain_key` and `signing_key` (if present)
    /// are slices pointing into the original `data` buffer.
    ///
    /// Note: This is a minimal parser tailored to the expected SKDM fields:
    /// - field 1 (varint): id
    /// - field 2 (varint): iteration
    /// - field 3 (length-delimited): chain_key (bytes)
    /// - field 4 (length-delimited): signing_key (bytes)
    ///
    /// Unknown fields are skipped according to their wire type.
    pub fn parse_zero_copy(data: &'a [u8]) -> Result<Self, &'static str> {
        let mut cursor = Cursor::new(data);
        let mut result = SkdmFields {
            id: None,
            iteration: None,
            chain_key: None,
            signing_key: None,
        };

        while (cursor.position() as usize) < data.len() {
            let tag_byte = read_varint32(&mut cursor).map_err(|_| "Invalid varint")?;
            let field_num = tag_byte >> 3;
            let wire_type = tag_byte & 0x07;

            match (field_num, wire_type) {
                (1, 0) => {
                    result.id = Some(read_varint32(&mut cursor).map_err(|_| "Invalid id varint")?);
                }
                (2, 0) => {
                    result.iteration =
                        Some(read_varint32(&mut cursor).map_err(|_| "Invalid iteration varint")?);
                }
                (3, 2) => {
                    let len = read_varint32(&mut cursor).map_err(|_| "Invalid chainKey length")?;
                    let start = cursor.position() as usize;
                    let end = start
                        .checked_add(len as usize)
                        .ok_or("ChainKey length overflow")?;
                    if end > data.len() {
                        return Err("ChainKey length exceeds data");
                    }
                    result.chain_key = Some(&data[start..end]);
                    cursor.set_position(end as u64);
                }
                (4, 2) => {
                    let len =
                        read_varint32(&mut cursor).map_err(|_| "Invalid signingKey length")?;
                    let start = cursor.position() as usize;
                    let end = start
                        .checked_add(len as usize)
                        .ok_or("SigningKey length overflow")?;
                    if end > data.len() {
                        return Err("SigningKey length exceeds data");
                    }
                    result.signing_key = Some(&data[start..end]);
                    cursor.set_position(end as u64);
                }
                _ => {
                    skip_field(&mut cursor, wire_type)
                        .map_err(|_| "Failed to skip unknown field")?;
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
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Varint too large",
            ));
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
            // varint
            read_varint32(cursor)?;
        }
        2 => {
            // length-delimited
            let len = read_varint32(cursor)?;
            // advance position by len bytes, ensuring we don't overflow
            let new_pos = cursor.position().checked_add(len as u64).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Skip overflow")
            })?;
            if new_pos > cursor.get_ref().len() as u64 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Skip length exceeds buffer",
                ));
            }
            cursor.set_position(new_pos);
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
