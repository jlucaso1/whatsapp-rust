use crate::error::{BinaryError, Result};
use crate::jid::JidRef;
use crate::node::{AttrsRef, NodeContentRef, NodeRef, NodeVec};
use crate::token;
use std::borrow::Cow;

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
            Err(BinaryError::Eof)
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
            Err(_) => {
                // Fallback to owned string if not valid UTF-8
                String::from_utf8(bytes.to_vec())
                    .map(Cow::Owned)
                    .map_err(|e| BinaryError::InvalidUtf8(e.utf8_error()))
            }
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

    // Zero-copy string parsing that returns Cow
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
            // All other single-byte tokens - these are from static dictionaries
            _ => token::get_single_token(tag)
                .map(|s| Some(Cow::Borrowed(s)))
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
            // It's a list of child nodes
            _ => {
                let size = self.read_list_size(tag)?;
                let mut nodes = NodeVec::with_capacity(size);
                for _ in 0..size {
                    nodes.push(self.read_node_ref()?);
                }
                Ok(Some(NodeContentRef::Nodes(Box::new(nodes))))
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
