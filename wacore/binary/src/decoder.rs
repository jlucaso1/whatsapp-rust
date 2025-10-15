use crate::error::{BinaryError, Result};
use crate::jid::JidRef;
use crate::node::{AttrsRef, NodeContentRef, NodeRef, NodeVec};
use crate::token;
use std::borrow::Cow;
use std::simd::{Simd, prelude::*, u8x16};

pub(crate) struct Decoder<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.position >= self.data.len()
    }

    pub(crate) fn bytes_left(&self) -> usize {
        self.data.len() - self.position
    }

    fn check_eos(&self, len: usize) -> Result<()> {
        if self.bytes_left() >= len {
            Ok(())
        } else {
            Err(BinaryError::UnexpectedEof)
        }
    }

    fn read_u8(&mut self) -> Result<u8> {
        self.check_eos(1)?;
        let value = self.data[self.position];
        self.position += 1;
        Ok(value)
    }

    fn read_u16_be(&mut self) -> Result<u16> {
        self.check_eos(2)?;
        let value = u16::from_be_bytes([self.data[self.position], self.data[self.position + 1]]);
        self.position += 2;
        Ok(value)
    }

    fn read_u20_be(&mut self) -> Result<u32> {
        self.check_eos(3)?;
        let bytes = [
            self.data[self.position],
            self.data[self.position + 1],
            self.data[self.position + 2],
        ];
        self.position += 3;
        Ok(((bytes[0] as u32 & 0x0F) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32))
    }

    fn read_u32_be(&mut self) -> Result<u32> {
        self.check_eos(4)?;
        let value = u32::from_be_bytes([
            self.data[self.position],
            self.data[self.position + 1],
            self.data[self.position + 2],
            self.data[self.position + 3],
        ]);
        self.position += 4;
        Ok(value)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        self.check_eos(len)?;
        let slice = &self.data[self.position..self.position + len];
        self.position += len;
        Ok(slice)
    }

    fn read_string(&mut self, len: usize) -> Result<Cow<'a, str>> {
        let bytes = self.read_bytes(len)?;
        match std::str::from_utf8(bytes) {
            Ok(s) => Ok(Cow::Borrowed(s)),
            Err(_) => String::from_utf8(bytes.to_vec())
                .map(Cow::Owned)
                .map_err(|e| BinaryError::InvalidUtf8(e.utf8_error())),
        }
    }

    fn read_list_size(&mut self, tag: u8) -> Result<usize> {
        match tag {
            token::LIST_EMPTY => Ok(0),
            248 => self.read_u8().map(|v| v as usize),
            249 => self.read_u16_be().map(|v| v as usize),
            _ => Err(BinaryError::InvalidToken(tag)),
        }
    }

    fn read_jid_pair(&mut self) -> Result<JidRef<'a>> {
        let user_val = self.read_value_as_string()?;
        let server = self.read_value_as_string()?.unwrap_or(Cow::Borrowed(""));
        let user = user_val.unwrap_or(Cow::Borrowed(""));
        Ok(JidRef {
            user,
            server,
            agent: 0,
            device: 0,
            integrator: 0,
        })
    }

    fn read_ad_jid(&mut self) -> Result<JidRef<'a>> {
        let agent = self.read_u8()?;
        let device = self.read_u8()? as u16;
        let user = self
            .read_value_as_string()?
            .ok_or(BinaryError::InvalidNode)?;

        let server = match agent {
            0 => Cow::Borrowed(crate::jid::DEFAULT_USER_SERVER),
            1 => Cow::Borrowed(crate::jid::HIDDEN_USER_SERVER),
            _ => Cow::Borrowed(crate::jid::HOSTED_SERVER),
        };

        Ok(JidRef {
            user,
            server,
            agent,
            device,
            integrator: 0,
        })
    }

    fn read_interop_jid(&mut self) -> Result<JidRef<'a>> {
        let user = self
            .read_value_as_string()?
            .ok_or(BinaryError::InvalidNode)?;
        let device = self.read_u16_be()?;
        let integrator = self.read_u16_be()?;
        let server = self.read_value_as_string()?.unwrap_or(Cow::Borrowed(""));
        if server != crate::jid::INTEROP_SERVER {
            return Err(BinaryError::InvalidNode);
        }
        Ok(JidRef {
            user,
            server,
            device,
            integrator,
            agent: 0,
        })
    }

    fn read_fb_jid(&mut self) -> Result<JidRef<'a>> {
        let user = self
            .read_value_as_string()?
            .ok_or(BinaryError::InvalidNode)?;
        let device = self.read_u16_be()?;
        let server = self.read_value_as_string()?.unwrap_or(Cow::Borrowed(""));
        if server != crate::jid::MESSENGER_SERVER {
            return Err(BinaryError::InvalidNode);
        }
        Ok(JidRef {
            user,
            server,
            device,
            agent: 0,
            integrator: 0,
        })
    }

    fn read_value_as_string(&mut self) -> Result<Option<Cow<'a, str>>> {
        let tag = self.read_u8()?;
        match tag {
            token::LIST_EMPTY => Ok(None),
            token::BINARY_8 => {
                let size = self.read_u8()? as usize;
                self.read_string(size).map(Some)
            }
            token::BINARY_20 => {
                let size = self.read_u20_be()? as usize;
                self.read_string(size).map(Some)
            }
            token::BINARY_32 => {
                let size = self.read_u32_be()? as usize;
                self.read_string(size).map(Some)
            }
            token::JID_PAIR => self
                .read_jid_pair()
                .map(|j| Some(Cow::Owned(j.to_string()))),
            token::AD_JID => self.read_ad_jid().map(|j| Some(Cow::Owned(j.to_string()))),
            token::INTEROP_JID => self
                .read_interop_jid()
                .map(|j| Some(Cow::Owned(j.to_string()))),
            token::FB_JID => self.read_fb_jid().map(|j| Some(Cow::Owned(j.to_string()))),
            token::NIBBLE_8 | token::HEX_8 => self.read_packed(tag).map(|s| Some(Cow::Owned(s))),
            tag @ token::DICTIONARY_0..=token::DICTIONARY_3 => {
                let index = self.read_u8()?;
                token::get_double_token(tag - token::DICTIONARY_0, index)
                    .map(|s| Some(Cow::Borrowed(s)))
                    .ok_or(BinaryError::InvalidToken(tag))
            }
            _ => token::get_single_token(tag)
                .map(|s| Some(Cow::Borrowed(s)))
                .ok_or(BinaryError::InvalidToken(tag)),
        }
    }

    fn read_packed(&mut self, tag: u8) -> Result<String> {
        let packed_len_byte = self.read_u8()?;
        let is_half_byte = (packed_len_byte & 0x80) != 0;
        let len = (packed_len_byte & 0x7F) as usize;

        if len == 0 {
            return Ok(String::new());
        }

        let raw_len = if is_half_byte { (len * 2) - 1 } else { len * 2 };
        let packed_data = self.read_bytes(len)?;
        let mut unpacked_bytes = Vec::with_capacity(raw_len);

        const NIBBLE_LOOKUP: [u8; 16] = *b"0123456789-.\x00\x00\x00\x00";
        const HEX_LOOKUP: [u8; 16] = *b"0123456789ABCDEF";
        let lookup_table = Simd::from_array(if tag == token::NIBBLE_8 {
            NIBBLE_LOOKUP
        } else {
            HEX_LOOKUP
        });
        let low_mask = Simd::splat(0x0F);

        let (chunks, remainder) = packed_data.as_chunks::<16>();
        for chunk in chunks {
            let data = u8x16::from_array(*chunk);

            let high_nibbles = (data >> 4) & low_mask;
            let low_nibbles = data & low_mask;

            if tag == token::NIBBLE_8 {
                let le11 = Simd::splat(11);
                let f15 = Simd::splat(15);
                let hi_valid = high_nibbles.simd_le(le11) | high_nibbles.simd_eq(f15);
                let lo_valid = low_nibbles.simd_le(le11) | low_nibbles.simd_eq(f15);
                if !(hi_valid & lo_valid).all() {
                    return Err(BinaryError::InvalidToken(tag));
                }
            }

            let high_chars = lookup_table.swizzle_dyn(high_nibbles);
            let low_chars = lookup_table.swizzle_dyn(low_nibbles);

            let (lo, hi) = Simd::interleave(high_chars, low_chars);
            unpacked_bytes.extend_from_slice(lo.as_array());
            unpacked_bytes.extend_from_slice(hi.as_array());
        }

        for &byte in remainder {
            let high = (byte & 0xF0) >> 4;
            let low = byte & 0x0F;
            unpacked_bytes.push(Self::unpack_byte(tag, high)? as u8);
            unpacked_bytes.push(Self::unpack_byte(tag, low)? as u8);
        }

        if is_half_byte {
            unpacked_bytes.pop();
        }

        String::from_utf8(unpacked_bytes).map_err(|e| BinaryError::InvalidUtf8(e.utf8_error()))
    }

    fn unpack_byte(tag: u8, value: u8) -> Result<char> {
        match tag {
            token::NIBBLE_8 => match value {
                0..=9 => Ok((b'0' + value) as char),
                10 => Ok('-'),
                11 => Ok('.'),
                15 => Ok('\x00'),
                _ => Err(BinaryError::InvalidToken(value)),
            },
            token::HEX_8 => match value {
                0..=9 => Ok((b'0' + value) as char),
                10..=15 => Ok((b'A' + value - 10) as char),
                _ => Err(BinaryError::InvalidToken(value)),
            },
            _ => Err(BinaryError::InvalidToken(tag)),
        }
    }

    fn read_attributes(&mut self, size: usize) -> Result<AttrsRef<'a>> {
        let mut attrs = AttrsRef::with_capacity(size);
        for _ in 0..size {
            let key = self
                .read_value_as_string()?
                .ok_or(BinaryError::NonStringKey)?;
            let value = self.read_value_as_string()?.unwrap_or(Cow::Borrowed(""));
            attrs.push((key, value));
        }
        Ok(attrs)
    }

    fn read_content(&mut self) -> Result<Option<NodeContentRef<'a>>> {
        let tag = self.read_u8()?;
        match tag {
            token::LIST_EMPTY => Ok(None),

            token::LIST_8 | token::LIST_16 => {
                let size = self.read_list_size(tag)?;
                let mut nodes = NodeVec::with_capacity(size);
                for _ in 0..size {
                    nodes.push(self.read_node_ref()?);
                }
                Ok(Some(NodeContentRef::Nodes(Box::new(nodes))))
            }

            token::BINARY_8 => {
                let len = self.read_u8()? as usize;
                let bytes = self.read_bytes(len)?;
                Ok(Some(NodeContentRef::Bytes(Cow::Borrowed(bytes))))
            }
            token::BINARY_20 => {
                let len = self.read_u20_be()? as usize;
                let bytes = self.read_bytes(len)?;
                Ok(Some(NodeContentRef::Bytes(Cow::Borrowed(bytes))))
            }
            token::BINARY_32 => {
                let len = self.read_u32_be()? as usize;
                let bytes = self.read_bytes(len)?;
                Ok(Some(NodeContentRef::Bytes(Cow::Borrowed(bytes))))
            }

            _ => {
                self.position -= 1;
                let string_content = self.read_value_as_string()?;

                match string_content {
                    Some(s) => Ok(Some(NodeContentRef::String(s))),
                    None => Ok(None),
                }
            }
        }
    }

    pub(crate) fn read_node_ref(&mut self) -> Result<NodeRef<'a>> {
        let tag = self.read_u8()?;
        let list_size = self.read_list_size(tag)?;
        if list_size == 0 {
            return Err(BinaryError::InvalidNode);
        }

        let tag = self
            .read_value_as_string()?
            .ok_or(BinaryError::InvalidNode)?;

        let attr_count = (list_size - 1) / 2;
        let has_content = list_size.is_multiple_of(2);

        let attrs = self.read_attributes(attr_count)?;
        let content = if has_content {
            self.read_content()?.map(Box::new)
        } else {
            None
        };

        Ok(NodeRef {
            tag,
            attrs,
            content,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Node;

    #[test]
    fn test_decode_node() {
        let node = Node::new(
            "message",
            std::collections::HashMap::new(),
            Some(crate::node::NodeContent::String("receipt".to_string())),
        );

        let mut buffer = Vec::new();
        {
            let mut encoder = crate::encoder::Encoder::new(std::io::Cursor::new(&mut buffer));
            encoder.write_node(&node).unwrap();
        }

        let mut decoder = Decoder::new(&buffer[1..]);
        let decoded = decoder.read_node_ref().unwrap();

        assert_eq!(decoded.tag, "message");
        assert!(decoded.attrs.is_empty());
        match &decoded.content {
            Some(content) => match &**content {
                crate::node::NodeContentRef::String(s) => assert_eq!(s, "receipt"),
                _ => panic!("Expected string content"),
            },
            None => panic!("Expected content"),
        }
    }

    #[test]
    fn test_decode_nibble_packing() {
        let test_str = "-.0123456789";
        let node = Node::new(
            "test",
            std::collections::HashMap::new(),
            Some(crate::node::NodeContent::String(test_str.to_string())),
        );

        let mut buffer = Vec::new();
        {
            let mut encoder = crate::encoder::Encoder::new(std::io::Cursor::new(&mut buffer));
            encoder.write_node(&node).unwrap();
        }

        let mut decoder = Decoder::new(&buffer[1..]);
        let decoded = decoder.read_node_ref().unwrap();

        assert_eq!(decoded.tag, "test");
        assert!(decoded.attrs.is_empty());
        match &decoded.content {
            Some(content) => match &**content {
                crate::node::NodeContentRef::String(s) => assert_eq!(s, test_str),
                _ => panic!("Expected string content"),
            },
            None => panic!("Expected content"),
        }
    }

    #[test]
    fn test_invalid_nibble_rejection() {
        let invalid_data = vec![1, 0xC0];

        let mut decoder = Decoder::new(&invalid_data);
        let result = decoder.read_packed(token::NIBBLE_8);
        assert!(
            result.is_err(),
            "Expected error for invalid nibble 12, got: {:?}",
            result
        );

        if let Err(BinaryError::InvalidToken(invalid_nibble)) = result {
            assert_eq!(invalid_nibble, 12, "Expected invalid nibble 12");
        } else {
            panic!("Expected InvalidToken error, got: {:?}", result);
        }
    }
}
