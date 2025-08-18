use crate::error::Result;
use crate::node::{Attrs, Node, NodeContent};
use crate::token;

pub(crate) struct Encoder {
    writer: Vec<u8>,
}

impl Encoder {
    pub(crate) fn new() -> Self {
        Self {
            writer: Vec::with_capacity(1024),
        }
    }

    pub(crate) fn into_data(self) -> Vec<u8> {
        self.writer
    }

    fn write_u8(&mut self, val: u8) {
        self.writer.push(val);
    }

    fn write_u16_be(&mut self, val: u16) {
        self.writer.extend_from_slice(&val.to_be_bytes());
    }

    fn write_u32_be(&mut self, val: u32) {
        self.writer.extend_from_slice(&val.to_be_bytes());
    }

    fn write_u20_be(&mut self, value: u32) {
        self.writer.push(((value >> 16) & 0x0F) as u8);
        self.writer.push(((value >> 8) & 0xFF) as u8);
        self.writer.push((value & 0xFF) as u8);
    }

    fn write_raw_bytes(&mut self, bytes: &[u8]) {
        self.writer.extend_from_slice(bytes);
    }

    fn write_bytes_with_len(&mut self, bytes: &[u8]) {
        let len = bytes.len();
        if len < 256 {
            self.write_u8(token::BINARY_8);
            self.write_u8(len as u8);
        } else if len < (1 << 20) {
            self.write_u8(token::BINARY_20);
            self.write_u20_be(len as u32);
        } else {
            self.write_u8(token::BINARY_32);
            self.write_u32_be(len as u32);
        }
        self.write_raw_bytes(bytes);
    }

    fn write_string(&mut self, s: &str) {
        if let Some(token) = token::index_of_single_token(s) {
            self.write_u8(token);
        } else if let Some((dict, token)) = token::index_of_double_byte_token(s) {
            self.write_u8(token::DICTIONARY_0 + dict);
            self.write_u8(token);
        } else if Self::validate_nibble(s) {
            self.write_packed_bytes(s, token::NIBBLE_8);
        } else if Self::validate_hex(s) {
            self.write_packed_bytes(s, token::HEX_8);
        } else {
            self.write_bytes_with_len(s.as_bytes());
        }
    }

    fn validate_nibble(value: &str) -> bool {
        if value.len() > token::PACKED_MAX as usize {
            return false;
        }
        value
            .chars()
            .all(|c| c.is_ascii_digit() || c == '-' || c == '.')
    }

    fn pack_nibble(value: char) -> u8 {
        match value {
            '-' => 10,
            '.' => 11,
            '\x00' => 15,
            c if c.is_ascii_digit() => c as u8 - b'0',
            _ => panic!("Invalid char for nibble packing: {value}"),
        }
    }

    fn validate_hex(value: &str) -> bool {
        if value.len() > token::PACKED_MAX as usize {
            return false;
        }
        value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_uppercase() || c.is_ascii_digit()))
    }

    fn pack_hex(value: char) -> u8 {
        match value {
            c if c.is_ascii_digit() => c as u8 - b'0',
            c if ('A'..='F').contains(&c) => 10 + (c as u8 - b'A'),
            '\x00' => 15,
            _ => panic!("Invalid char for hex packing: {value}"),
        }
    }

    fn pack_byte_pair(&self, packer: fn(char) -> u8, part1: char, part2: char) -> u8 {
        (packer(part1) << 4) | packer(part2)
    }

    fn write_packed_bytes(&mut self, value: &str, data_type: u8) {
        if value.len() > token::PACKED_MAX as usize {
            panic!("String too long to be packed: {}", value.len());
        }

        self.write_u8(data_type);

        let mut rounded_len = ((value.len() as f64) / 2.0).ceil() as u8;
        if !value.len().is_multiple_of(2) {
            rounded_len |= 0x80;
        }
        self.write_u8(rounded_len);

        let packer: fn(char) -> u8 = if data_type == token::NIBBLE_8 {
            Self::pack_nibble
        } else {
            Self::pack_hex
        };

        let mut chars = value.chars();
        while let Some(part1) = chars.next() {
            let part2 = chars.next().unwrap_or('\x00');
            self.write_u8(self.pack_byte_pair(packer, part1, part2));
        }
    }

    fn write_list_start(&mut self, len: usize) {
        if len == 0 {
            self.write_u8(token::LIST_EMPTY);
        } else if len < 256 {
            self.write_u8(248);
            self.write_u8(len as u8);
        } else {
            self.write_u8(249);
            self.write_u16_be(len as u16);
        }
    }

    fn write_attributes(&mut self, attrs: &Attrs) -> Result<()> {
        let mut sorted_attrs: Vec<_> = attrs.iter().collect();
        sorted_attrs.sort_by_key(|(k, _)| *k);

        for (key, value) in sorted_attrs {
            self.write_string(key);
            self.write_string(value);
        }
        Ok(())
    }

    fn write_content(&mut self, content: &NodeContent) -> Result<()> {
        match content {
            NodeContent::Bytes(bytes) => self.write_bytes_with_len(bytes),
            NodeContent::Nodes(nodes) => {
                self.write_list_start(nodes.len());
                for node in nodes {
                    self.write_node(node)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn write_node(&mut self, node: &Node) -> Result<()> {
        let content_len = if node.content.is_some() { 1 } else { 0 };
        let list_len = 1 + (node.attrs.len() * 2) + content_len;

        self.write_list_start(list_len);
        self.write_string(&node.tag);
        self.write_attributes(&node.attrs)?;

        if let Some(content) = &node.content {
            self.write_content(content)?;
        }
        Ok(())
    }
}
