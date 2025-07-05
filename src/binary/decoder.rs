use crate::binary::error::{BinaryError, Result};
use crate::binary::node::{Attrs, Node, NodeContent};
use crate::binary::token;
use crate::types::jid::Jid;
use bytes::Buf;
use std::io::Cursor;

pub(crate) struct Decoder<'a> {
    reader: Cursor<&'a [u8]>,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self {
            reader: Cursor::new(data),
        }
    }

    pub(crate) fn is_finished(&self) -> bool {
        !self.reader.has_remaining()
    }

    pub(crate) fn bytes_left(&self) -> usize {
        self.reader.remaining()
    }

    fn check_eos(&self, len: usize) -> Result<()> {
        if self.reader.remaining() >= len {
            Ok(())
        } else {
            Err(BinaryError::Eof)
        }
    }

    fn read_u8(&mut self) -> Result<u8> {
        self.check_eos(1)?;
        Ok(self.reader.get_u8())
    }

    fn read_u16_be(&mut self) -> Result<u16> {
        self.check_eos(2)?;
        Ok(self.reader.get_u16())
    }

    fn read_u20_be(&mut self) -> Result<u32> {
        self.check_eos(3)?;
        let mut bytes = [0u8; 3];
        bytes.copy_from_slice(&self.reader.chunk()[..3]);
        self.reader.advance(3);
        Ok(((bytes[0] as u32 & 0x0F) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32))
    }

    fn read_u32_be(&mut self) -> Result<u32> {
        self.check_eos(4)?;
        Ok(self.reader.get_u32())
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        self.check_eos(len)?;
        let start = self.reader.position() as usize;
        self.reader.advance(len);
        Ok(&self.reader.get_ref()[start..start + len])
    }

    fn read_string(&mut self, len: usize) -> Result<String> {
        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|e| BinaryError::InvalidUtf8(e.utf8_error()))
    }

    fn read_list_size(&mut self, tag: u8) -> Result<usize> {
        match tag {
            token::LIST_EMPTY => Ok(0),
            248 => self.read_u8().map(|v| v as usize),
            249 => self.read_u16_be().map(|v| v as usize),
            _ => Err(BinaryError::InvalidToken(tag)),
        }
    }

    fn read_jid_pair(&mut self) -> Result<Jid> {
        let user_val = self.read_value_as_string()?;
        let server = self.read_value_as_string()?.unwrap_or_default();
        Ok(Jid::new(user_val.as_deref().unwrap_or(""), &server))
    }

    fn read_ad_jid(&mut self) -> Result<Jid> {
        let agent = self.read_u8()?;
        let device = self.read_u8()? as u16;
        let user = self
            .read_value_as_string()?
            .ok_or(BinaryError::InvalidNode)?;
        let server = match agent {
            0 => crate::types::jid::DEFAULT_USER_SERVER,
            1 => crate::types::jid::HIDDEN_USER_SERVER,
            _ => crate::types::jid::HOSTED_SERVER,
        }
        .to_string();

        Ok(Jid {
            user,
            server,
            agent,
            device,
            ..Default::default()
        })
    }

    fn read_interop_jid(&mut self) -> Result<Jid> {
        let user = self
            .read_value_as_string()?
            .ok_or(BinaryError::InvalidNode)?;
        let device = self.read_u16_be()?;
        let integrator = self.read_u16_be()?;
        let server = self.read_value_as_string()?.unwrap_or_default();
        if server != crate::types::jid::INTEROP_SERVER {
            return Err(BinaryError::InvalidNode);
        }
        Ok(Jid {
            user,
            server,
            device,
            integrator,
            ..Default::default()
        })
    }

    fn read_fb_jid(&mut self) -> Result<Jid> {
        let user = self
            .read_value_as_string()?
            .ok_or(BinaryError::InvalidNode)?;
        let device = self.read_u16_be()?;
        let server = self.read_value_as_string()?.unwrap_or_default();
        if server != crate::types::jid::MESSENGER_SERVER {
            return Err(BinaryError::InvalidNode);
        }
        Ok(Jid {
            user,
            server,
            device,
            ..Default::default()
        })
    }

    // Simplified read_value that only handles string-like things for now
    fn read_value_as_string(&mut self) -> Result<Option<String>> {
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
            token::JID_PAIR => self.read_jid_pair().map(|j| Some(j.to_string())),
            token::AD_JID => self.read_ad_jid().map(|j| Some(j.to_string())),
            token::INTEROP_JID => self.read_interop_jid().map(|j| Some(j.to_string())),
            token::FB_JID => self.read_fb_jid().map(|j| Some(j.to_string())),
            token::NIBBLE_8 | token::HEX_8 => self.read_packed(tag).map(Some),
            tag @ token::DICTIONARY_0..=token::DICTIONARY_3 => {
                let index = self.read_u8()?;
                token::get_double_token(tag - token::DICTIONARY_0, index)
                    .map(|s| s.to_string())
                    .map(Some)
                    .ok_or(BinaryError::InvalidToken(tag))
            }
            // All other single-byte tokens
            _ => token::get_single_token(tag)
                .map(|s| s.to_string())
                .map(Some)
                .ok_or(BinaryError::InvalidToken(tag)),
        }
    }

    fn read_packed(&mut self, tag: u8) -> Result<String> {
        let packed_len_byte = self.read_u8()?;
        let is_half_byte = (packed_len_byte & 0x80) != 0;
        let len = (packed_len_byte & 0x7F) as usize;
        let raw_len = if is_half_byte { len * 2 - 1 } else { len * 2 };

        let mut result = String::with_capacity(raw_len);
        let packed_data = self.read_bytes(len)?;

        for &byte in packed_data {
            let high = (byte & 0xF0) >> 4;
            let low = byte & 0x0F;
            result.push(Self::unpack_byte(tag, high)?);
            result.push(Self::unpack_byte(tag, low)?);
        }

        if is_half_byte {
            result.pop();
        }

        Ok(result)
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

    fn read_attributes(&mut self, size: usize) -> Result<Attrs> {
        let mut attrs = std::collections::HashMap::new();
        for _ in 0..size {
            let key = self
                .read_value_as_string()?
                .ok_or(BinaryError::NonStringKey)?;
            let value = self.read_value_as_string()?.unwrap_or_default();
            attrs.insert(key, value);
        }
        Ok(attrs)
    }

    fn read_content(&mut self) -> Result<Option<NodeContent>> {
        let tag = self.read_u8()?;
        match tag {
            token::LIST_EMPTY => Ok(None),
            token::BINARY_8 => {
                let len = self.read_u8()? as usize;
                self.read_bytes(len)
                    .map(|b| Some(NodeContent::Bytes(b.to_vec())))
            }
            token::BINARY_20 => {
                let len = self.read_u20_be()? as usize;
                self.read_bytes(len)
                    .map(|b| Some(NodeContent::Bytes(b.to_vec())))
            }
            token::BINARY_32 => {
                let len = self.read_u32_be()? as usize;
                self.read_bytes(len)
                    .map(|b| Some(NodeContent::Bytes(b.to_vec())))
            }
            // It's a list of child nodes
            _ => {
                let size = self.read_list_size(tag)?;
                let mut nodes = Vec::with_capacity(size);
                for _ in 0..size {
                    nodes.push(self.read_node()?);
                }
                Ok(Some(NodeContent::Nodes(nodes)))
            }
        }
    }

    pub(crate) fn read_node(&mut self) -> Result<Node> {
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
            self.read_content()?
        } else {
            None
        };

        Ok(Node {
            tag,
            attrs,
            content,
        })
    }
}
