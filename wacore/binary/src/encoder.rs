use std::io::Write;

#[cfg(feature = "simd")]
use core::simd::Select;
#[cfg(feature = "simd")]
use core::simd::prelude::*;
#[cfg(feature = "simd")]
use core::simd::{Simd, u8x16};

use crate::error::{BinaryError, Result};
use crate::jid::{self, Jid, JidRef};
use crate::node::{Node, NodeContent, NodeContentRef, NodeRef, NodeValue, ValueRef};
use crate::token;

pub trait ByteWriter {
    fn write_u8(&mut self, value: u8) -> Result<()>;
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()>;
}

pub(crate) struct IoByteWriter<W: Write> {
    writer: W,
}

impl<W: Write> IoByteWriter<W> {
    fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W: Write> ByteWriter for IoByteWriter<W> {
    #[inline]
    fn write_u8(&mut self, value: u8) -> Result<()> {
        self.writer.write_all(&[value])?;
        Ok(())
    }

    #[inline]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.write_all(bytes)?;
        Ok(())
    }
}

pub struct VecByteWriter<'a> {
    buffer: &'a mut Vec<u8>,
}

impl<'a> VecByteWriter<'a> {
    fn new(buffer: &'a mut Vec<u8>) -> Self {
        Self { buffer }
    }
}

impl ByteWriter for VecByteWriter<'_> {
    #[inline]
    fn write_u8(&mut self, value: u8) -> Result<()> {
        self.buffer.push(value);
        Ok(())
    }

    #[inline]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }
}

pub(crate) struct SliceByteWriter<'a> {
    buffer: &'a mut [u8],
    position: usize,
}

impl<'a> SliceByteWriter<'a> {
    fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            position: 0,
        }
    }

    #[inline]
    fn bytes_written(&self) -> usize {
        self.position
    }
}

impl ByteWriter for SliceByteWriter<'_> {
    #[inline]
    fn write_u8(&mut self, value: u8) -> Result<()> {
        if self.position >= self.buffer.len() {
            return Err(BinaryError::UnexpectedEof);
        }
        self.buffer[self.position] = value;
        self.position += 1;
        Ok(())
    }

    #[inline]
    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.position + bytes.len();
        if end > self.buffer.len() {
            return Err(BinaryError::UnexpectedEof);
        }
        self.buffer[self.position..end].copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }
}

/// Trait for encoding node structures (both owned Node and borrowed NodeRef).
/// All encoding logic lives in the trait implementation, keeping
/// the Encoder simple and focused on low-level byte writing.
pub trait EncodeNode {
    fn tag(&self) -> &str;
    fn attrs_len(&self) -> usize;
    fn has_content(&self) -> bool;

    /// Encode all attributes to the encoder
    fn encode_attrs<'a, W: ByteWriter>(&self, encoder: &mut Encoder<'a, W>) -> Result<()>;

    /// Encode content (string, bytes, or child nodes) to the encoder
    fn encode_content<'a, W: ByteWriter>(&self, encoder: &mut Encoder<'a, W>) -> Result<()>;
}

impl EncodeNode for Node {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn attrs_len(&self) -> usize {
        self.attrs.len()
    }

    fn has_content(&self) -> bool {
        self.content.is_some()
    }

    fn encode_attrs<'a, W: ByteWriter>(&self, encoder: &mut Encoder<'a, W>) -> Result<()> {
        for (k, v) in &self.attrs {
            encoder.write_string(k)?;
            match v {
                NodeValue::String(s) => encoder.write_string(s)?,
                NodeValue::Jid(jid) => encoder.write_jid_owned(jid)?,
            }
        }
        Ok(())
    }

    fn encode_content<'a, W: ByteWriter>(&self, encoder: &mut Encoder<'a, W>) -> Result<()> {
        if let Some(content) = &self.content {
            match content {
                NodeContent::String(s) => encoder.write_string(s)?,
                NodeContent::Bytes(b) => encoder.write_bytes_with_len(b)?,
                NodeContent::Nodes(nodes) => {
                    encoder.write_list_start(nodes.len())?;
                    for node in nodes {
                        encoder.write_node(node)?;
                    }
                }
            }
        }
        Ok(())
    }
}

impl EncodeNode for NodeRef<'_> {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn attrs_len(&self) -> usize {
        self.attrs.len()
    }

    fn has_content(&self) -> bool {
        self.content.is_some()
    }

    fn encode_attrs<'a, W: ByteWriter>(&self, encoder: &mut Encoder<'a, W>) -> Result<()> {
        for (k, v) in self.attrs.iter() {
            encoder.write_string(k)?;
            match v {
                ValueRef::String(s) => encoder.write_string(s)?,
                ValueRef::Jid(jid) => encoder.write_jid_ref(jid)?,
            }
        }
        Ok(())
    }

    fn encode_content<'a, W: ByteWriter>(&self, encoder: &mut Encoder<'a, W>) -> Result<()> {
        if let Some(content) = self.content.as_deref() {
            match content {
                NodeContentRef::String(s) => encoder.write_string(s)?,
                NodeContentRef::Bytes(b) => encoder.write_bytes_with_len(b)?,
                NodeContentRef::Nodes(nodes) => {
                    encoder.write_list_start(nodes.len())?;
                    for node in nodes.iter() {
                        encoder.write_node(node)?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedJidMeta {
    user_end: usize,
    server_start: usize,
    domain_type: u8,
    device: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StrKey {
    ptr: usize,
    len: usize,
}

impl StrKey {
    #[inline]
    fn from_str(s: &str) -> Self {
        Self {
            ptr: s.as_ptr() as usize,
            len: s.len(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StringHint {
    Empty,
    SingleToken(u8),
    DoubleToken { dict: u8, token: u8 },
    PackedNibble,
    PackedHex,
    Jid(ParsedJidMeta),
    RawBytes,
}

#[derive(Debug)]
pub(crate) struct StringHintCache {
    // Keys use (ptr, len) identity, so this cache is only valid while encoding
    // the same immutable node/strings it was built from.
    hints: Vec<(StrKey, StringHint)>,
}

impl Default for StringHintCache {
    fn default() -> Self {
        Self {
            hints: Vec::with_capacity(32),
        }
    }
}

impl StringHintCache {
    const MAX_HINT_ENTRIES: usize = 96;

    #[inline]
    fn hint_for(&self, s: &str) -> Option<StringHint> {
        let key = StrKey::from_str(s);
        self.hints
            .iter()
            .find_map(|(cached_key, hint)| (*cached_key == key).then_some(*hint))
    }

    #[inline]
    fn hint_or_insert(&mut self, s: &str) -> StringHint {
        if s.len() > token::PACKED_MAX as usize {
            return StringHint::RawBytes;
        }
        let key = StrKey::from_str(s);
        if let Some(existing) = self
            .hints
            .iter()
            .find_map(|(cached_key, hint)| (*cached_key == key).then_some(*hint))
        {
            existing
        } else {
            let hint = classify_string_hint(s);
            if self.hints.len() < Self::MAX_HINT_ENTRIES {
                self.hints.push((key, hint));
            }
            hint
        }
    }
}

#[derive(Debug)]
pub(crate) struct MarshaledSizePlan {
    pub(crate) size: usize,
    pub(crate) hints: StringHintCache,
}

fn parse_jid_meta(input: &str) -> Option<ParsedJidMeta> {
    let sep_idx = input.find('@')?;
    let server_start = sep_idx + 1;
    let server = &input[server_start..];
    let user_combined = &input[..sep_idx];

    let (user_agent, device) = if let Some(colon_idx) = user_combined.find(':') {
        let device_part = &user_combined[colon_idx + 1..];
        if let Ok(parsed_device) = device_part.parse::<u8>() {
            (&user_combined[..colon_idx], Some(parsed_device))
        } else {
            (user_combined, None)
        }
    } else {
        (user_combined, None)
    };

    let (user_end, agent_override) = if let Some(underscore_idx) = user_agent.find('_') {
        let agent_part = &user_agent[underscore_idx + 1..];
        if let Ok(parsed_agent) = agent_part.parse::<u8>() {
            (underscore_idx, Some(parsed_agent))
        } else {
            (user_agent.len(), None)
        }
    } else {
        (user_agent.len(), None)
    };

    let agent_byte = agent_override.unwrap_or(0);
    let domain_type = if server == jid::HIDDEN_USER_SERVER {
        1
    } else if server == jid::HOSTED_SERVER {
        128
    } else if server == jid::HOSTED_LID_SERVER {
        129
    } else {
        agent_byte
    };

    Some(ParsedJidMeta {
        user_end,
        server_start,
        domain_type,
        device,
    })
}

#[inline]
fn split_jid_from_meta(input: &str, meta: ParsedJidMeta) -> (&str, &str) {
    (&input[..meta.user_end], &input[meta.server_start..])
}

/// Map a JID server string to the AD_JID domain_type byte.
///
/// The AD_JID binary encoding uses a single byte to identify the server:
///   0 = s.whatsapp.net (default)
///   1 = lid
///   128 = hosted
///   129 = hosted.lid
///
/// For unmapped servers, falls back to `agent` to match the string-path
/// behavior in `parse_jid_meta` (which uses `agent_byte` as the default).
///
/// WARNING: This must stay in sync with the string-path mapping in
/// `classify_string_hint` / `parse_jid_meta` and the inverse mapping in
/// `decoder.rs read_ad_jid`. Writing `jid.agent` unconditionally here
/// (instead of only as a fallback) was the root cause of a regression
/// where LID group messages were silently rejected by the server (error 421).
#[inline]
fn server_to_domain_type(server: jid::Server, agent: u8) -> u8 {
    match server {
        jid::Server::Lid => 1,
        jid::Server::Hosted => 128,
        jid::Server::HostedLid => 129,
        _ => agent,
    }
}

#[inline]
fn classify_string_hint(s: &str) -> StringHint {
    if s.is_empty() {
        return StringHint::Empty;
    }

    let is_likely_jid = s.len() <= 48;

    if let Some(kind) = token::index_of_token(s) {
        return match kind {
            token::TokenKind::Single(token) => StringHint::SingleToken(token),
            token::TokenKind::Double(dict, token) => StringHint::DoubleToken { dict, token },
        };
    }

    if validate_nibble(s) {
        StringHint::PackedNibble
    } else if validate_hex(s) {
        StringHint::PackedHex
    } else if is_likely_jid {
        parse_jid_meta(s).map_or(StringHint::RawBytes, StringHint::Jid)
    } else {
        StringHint::RawBytes
    }
}

pub(crate) fn build_marshaled_node_plan(node: &Node) -> MarshaledSizePlan {
    let mut hints = StringHintCache::default();
    let size = 1 + node_encoded_size_with_cache(node, &mut hints);
    MarshaledSizePlan { size, hints }
}

pub(crate) fn build_marshaled_node_ref_plan(node: &NodeRef<'_>) -> MarshaledSizePlan {
    let mut hints = StringHintCache::default();
    let size = 1 + node_ref_encoded_size_with_cache(node, &mut hints);
    MarshaledSizePlan { size, hints }
}

#[inline]
fn list_start_encoded_size(len: usize) -> usize {
    if len == 0 {
        1
    } else if len < 256 {
        2
    } else {
        3
    }
}

#[inline]
fn binary_len_prefix_size(len: usize) -> usize {
    if len < 256 {
        2
    } else if len < (1 << 20) {
        4
    } else {
        5
    }
}

#[inline]
fn bytes_with_len_encoded_size(len: usize) -> usize {
    binary_len_prefix_size(len) + len
}

#[inline]
fn packed_encoded_size(value_len: usize) -> usize {
    2 + value_len.div_ceil(2)
}

fn node_encoded_size_with_cache(node: &Node, hints: &mut StringHintCache) -> usize {
    let content_len = usize::from(node.content.is_some());
    let list_len = 1 + (node.attrs.len() * 2) + content_len;

    let attrs_size: usize = node
        .attrs
        .iter()
        .map(|(k, v)| {
            let value_size = match v {
                NodeValue::String(s) => string_encoded_size_with_cache(s, hints),
                NodeValue::Jid(jid) => owned_jid_encoded_size_with_cache(jid, hints),
            };
            string_encoded_size_with_cache(k, hints) + value_size
        })
        .sum();

    let content_size = match &node.content {
        Some(NodeContent::String(s)) => string_encoded_size_with_cache(s, hints),
        Some(NodeContent::Bytes(b)) => bytes_with_len_encoded_size(b.len()),
        Some(NodeContent::Nodes(nodes)) => {
            list_start_encoded_size(nodes.len())
                + nodes
                    .iter()
                    .map(|child| node_encoded_size_with_cache(child, hints))
                    .sum::<usize>()
        }
        None => 0,
    };

    list_start_encoded_size(list_len)
        + string_encoded_size_with_cache(&node.tag, hints)
        + attrs_size
        + content_size
}

fn node_ref_encoded_size_with_cache(node: &NodeRef<'_>, hints: &mut StringHintCache) -> usize {
    let content_len = usize::from(node.content.is_some());
    let list_len = 1 + (node.attrs.len() * 2) + content_len;

    let attrs_size: usize = node
        .attrs
        .iter()
        .map(|(k, v)| {
            let value_size = match v {
                ValueRef::String(s) => string_encoded_size_with_cache(s, hints),
                ValueRef::Jid(jid) => jid_ref_encoded_size_with_cache(jid, hints),
            };
            string_encoded_size_with_cache(k, hints) + value_size
        })
        .sum();

    let content_size = match node.content.as_deref() {
        Some(NodeContentRef::String(s)) => string_encoded_size_with_cache(s, hints),
        Some(NodeContentRef::Bytes(b)) => bytes_with_len_encoded_size(b.len()),
        Some(NodeContentRef::Nodes(nodes)) => {
            list_start_encoded_size(nodes.len())
                + nodes
                    .iter()
                    .map(|child| node_ref_encoded_size_with_cache(child, hints))
                    .sum::<usize>()
        }
        None => 0,
    };

    list_start_encoded_size(list_len)
        + string_encoded_size_with_cache(node.tag.as_ref(), hints)
        + attrs_size
        + content_size
}

#[inline]
fn string_encoded_size_with_cache(s: &str, hints: &mut StringHintCache) -> usize {
    let hint = hints.hint_or_insert(s);
    string_encoded_size_from_hint_with_cache(s, hint, hints)
}

#[inline]
fn string_encoded_size_from_hint_with_cache(
    s: &str,
    hint: StringHint,
    hints: &mut StringHintCache,
) -> usize {
    match hint {
        StringHint::Empty => 2,
        StringHint::SingleToken(_) => 1,
        StringHint::DoubleToken { .. } => 2,
        StringHint::PackedNibble | StringHint::PackedHex => packed_encoded_size(s.len()),
        StringHint::RawBytes => bytes_with_len_encoded_size(s.len()),
        StringHint::Jid(meta) => parsed_jid_encoded_size_with_cache(s, meta, hints),
    }
}

#[inline]
fn parsed_jid_encoded_size_with_cache(
    jid: &str,
    meta: ParsedJidMeta,
    hints: &mut StringHintCache,
) -> usize {
    let (user, server) = split_jid_from_meta(jid, meta);
    if meta.device.is_some() {
        3 + string_encoded_size_with_cache(user, hints)
    } else {
        let user_size = if user.is_empty() {
            1
        } else {
            string_encoded_size_with_cache(user, hints)
        };
        1 + user_size + string_encoded_size_with_cache(server, hints)
    }
}

#[inline]
fn owned_jid_encoded_size_with_cache(jid: &Jid, hints: &mut StringHintCache) -> usize {
    if jid.device > 0 {
        3 + string_encoded_size_with_cache(&jid.user, hints)
    } else {
        let user_size = if jid.user.is_empty() {
            1
        } else {
            string_encoded_size_with_cache(&jid.user, hints)
        };
        1 + user_size + string_encoded_size_with_cache(jid.server.as_str(), hints)
    }
}

#[inline]
fn jid_ref_encoded_size_with_cache(jid: &JidRef<'_>, hints: &mut StringHintCache) -> usize {
    if jid.device > 0 {
        3 + string_encoded_size_with_cache(&jid.user, hints)
    } else {
        let user_size = if jid.user.is_empty() {
            1
        } else {
            string_encoded_size_with_cache(&jid.user, hints)
        };
        1 + user_size + string_encoded_size_with_cache(jid.server.as_str(), hints)
    }
}

#[inline]
fn validate_nibble(value: &str) -> bool {
    if value.len() > token::PACKED_MAX as usize {
        return false;
    }
    value
        .as_bytes()
        .iter()
        .all(|&b| b.is_ascii_digit() || b == b'-' || b == b'.')
}

#[inline]
fn validate_hex(value: &str) -> bool {
    if value.len() > token::PACKED_MAX as usize {
        return false;
    }
    value
        .as_bytes()
        .iter()
        .all(|&b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

pub struct Encoder<'a, W: ByteWriter> {
    writer: W,
    string_hints: Option<&'a StringHintCache>,
}

impl<W: Write> Encoder<'static, IoByteWriter<W>> {
    pub fn new(writer: W) -> Result<Self> {
        let mut enc = Self {
            writer: IoByteWriter::new(writer),
            string_hints: None,
        };
        enc.write_u8(0)?;
        Ok(enc)
    }
}

impl<'v> Encoder<'static, VecByteWriter<'v>> {
    pub fn new_vec(buffer: &'v mut Vec<u8>) -> Result<Self> {
        buffer.clear();
        let mut enc = Self {
            writer: VecByteWriter::new(buffer),
            string_hints: None,
        };
        enc.write_u8(0)?;
        Ok(enc)
    }
}

impl<'a> Encoder<'a, SliceByteWriter<'a>> {
    pub(crate) fn new_slice(
        buffer: &'a mut [u8],
        string_hints: Option<&'a StringHintCache>,
    ) -> Result<Self> {
        let mut enc = Self {
            writer: SliceByteWriter::new(buffer),
            string_hints,
        };
        enc.write_u8(0)?;
        Ok(enc)
    }

    #[inline]
    pub(crate) fn bytes_written(&self) -> usize {
        self.writer.bytes_written()
    }
}

impl<'a, W: ByteWriter> Encoder<'a, W> {
    #[inline(always)]
    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.writer.write_u8(val)
    }

    #[inline(always)]
    fn write_u16_be(&mut self, val: u16) -> Result<()> {
        self.writer.write_bytes(&val.to_be_bytes())
    }

    #[inline(always)]
    fn write_u32_be(&mut self, val: u32) -> Result<()> {
        self.writer.write_bytes(&val.to_be_bytes())
    }

    #[inline(always)]
    fn write_u20_be(&mut self, value: u32) -> Result<()> {
        let bytes = [
            ((value >> 16) & 0x0F) as u8,
            ((value >> 8) & 0xFF) as u8,
            (value & 0xFF) as u8,
        ];
        self.writer.write_bytes(&bytes)
    }

    #[inline(always)]
    fn write_raw_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer.write_bytes(bytes)
    }

    #[inline(always)]
    pub fn write_bytes_with_len(&mut self, bytes: &[u8]) -> Result<()> {
        let len = bytes.len();
        if len < 256 {
            self.write_u8(token::BINARY_8)?;
            self.write_u8(len as u8)?;
        } else if len < (1 << 20) {
            self.write_u8(token::BINARY_20)?;
            self.write_u20_be(len as u32)?;
        } else {
            self.write_u8(token::BINARY_32)?;
            self.write_u32_be(len as u32)?;
        }
        self.write_raw_bytes(bytes)
    }

    #[inline(always)]
    pub fn write_string(&mut self, s: &str) -> Result<()> {
        if let Some(string_hints) = self.string_hints
            && let Some(hint) = string_hints.hint_for(s)
        {
            return self.write_string_with_hint(s, hint);
        }
        self.write_string_uncached(s)
    }

    #[inline(always)]
    fn write_string_uncached(&mut self, s: &str) -> Result<()> {
        // Strings longer than PACKED_MAX (127) can't be protocol tokens (max 48),
        // packed nibble/hex, or JIDs — emit as raw bytes without classification.
        if s.len() > token::PACKED_MAX as usize {
            return self.write_bytes_with_len(s.as_bytes());
        }
        self.write_string_with_hint(s, classify_string_hint(s))
    }

    #[inline(always)]
    fn write_string_with_hint(&mut self, s: &str, hint: StringHint) -> Result<()> {
        match hint {
            StringHint::Empty => {
                self.write_u8(token::BINARY_8)?;
                self.write_u8(0)?;
            }
            StringHint::SingleToken(token) => self.write_u8(token)?,
            StringHint::DoubleToken { dict, token } => {
                self.write_u8(token::DICTIONARY_0 + dict)?;
                self.write_u8(token)?;
            }
            StringHint::PackedNibble => self.write_packed_bytes(s, token::NIBBLE_8)?,
            StringHint::PackedHex => self.write_packed_bytes(s, token::HEX_8)?,
            StringHint::Jid(meta) => self.write_jid_from_meta(s, meta)?,
            StringHint::RawBytes => self.write_bytes_with_len(s.as_bytes())?,
        }
        Ok(())
    }

    #[inline(always)]
    fn write_jid_from_meta(&mut self, jid: &str, meta: ParsedJidMeta) -> Result<()> {
        let (user, server) = split_jid_from_meta(jid, meta);
        if let Some(device) = meta.device {
            self.write_u8(token::AD_JID)?;
            self.write_u8(meta.domain_type)?;
            self.write_u8(device)?;
            self.write_string(user)?;
        } else {
            self.write_u8(token::JID_PAIR)?;
            if user.is_empty() {
                self.write_u8(token::LIST_EMPTY)?;
            } else {
                self.write_string(user)?;
            }
            self.write_string(server)?;
        }
        Ok(())
    }

    /// Write a JidRef directly without converting to string first.
    /// This avoids the allocation that would occur with `jid.to_string()`.
    fn write_jid_ref(&mut self, jid: &JidRef<'_>) -> Result<()> {
        if jid.device > 0 {
            // AD_JID format: domain_type, device, user
            let device = u8::try_from(jid.device).map_err(|_| {
                BinaryError::AttrParse(format!("AD_JID device id out of range: {}", jid.device))
            })?;
            self.write_u8(token::AD_JID)?;
            self.write_u8(server_to_domain_type(jid.server, jid.agent))?;
            self.write_u8(device)?;
            self.write_string(&jid.user)?;
        } else {
            // JID_PAIR format: user, server
            self.write_u8(token::JID_PAIR)?;
            if jid.user.is_empty() {
                self.write_u8(token::LIST_EMPTY)?;
            } else {
                self.write_string(&jid.user)?;
            }
            self.write_string(jid.server.as_str())?;
        }
        Ok(())
    }

    /// Write an owned Jid directly without converting to string first.
    /// This avoids the allocation that would occur with `jid.to_string()`.
    pub fn write_jid_owned(&mut self, jid: &Jid) -> Result<()> {
        if jid.device > 0 {
            // AD_JID format: domain_type, device, user
            let device = u8::try_from(jid.device).map_err(|_| {
                BinaryError::AttrParse(format!("AD_JID device id out of range: {}", jid.device))
            })?;
            self.write_u8(token::AD_JID)?;
            self.write_u8(server_to_domain_type(jid.server, jid.agent))?;
            self.write_u8(device)?;
            self.write_string(&jid.user)?;
        } else {
            // JID_PAIR format: user, server
            self.write_u8(token::JID_PAIR)?;
            if jid.user.is_empty() {
                self.write_u8(token::LIST_EMPTY)?;
            } else {
                self.write_string(&jid.user)?;
            }
            self.write_string(jid.server.as_str())?;
        }
        Ok(())
    }

    #[inline(always)]
    fn pack_nibble(value: u8) -> u8 {
        match value {
            b'-' => 10,
            b'.' => 11,
            0 => 15,
            c if c.is_ascii_digit() => c - b'0',
            _ => panic!("Invalid char for nibble packing: {value}"),
        }
    }

    #[inline(always)]
    fn pack_hex(value: u8) -> u8 {
        match value {
            c if c.is_ascii_digit() => c - b'0',
            c if (b'A'..=b'F').contains(&c) => 10 + (c - b'A'),
            0 => 15,
            _ => panic!("Invalid char for hex packing: {value}"),
        }
    }

    #[inline(always)]
    fn pack_byte_pair(packer: fn(u8) -> u8, part1: u8, part2: u8) -> u8 {
        (packer(part1) << 4) | packer(part2)
    }

    fn write_packed_bytes(&mut self, value: &str, data_type: u8) -> Result<()> {
        if value.len() > token::PACKED_MAX as usize {
            panic!("String too long to be packed: {}", value.len());
        }

        self.write_u8(data_type)?;

        let mut rounded_len = value.len().div_ceil(2) as u8;
        if !value.len().is_multiple_of(2) {
            rounded_len |= 0x80;
        }
        self.write_u8(rounded_len)?;

        #[allow(unused_mut)]
        let mut input_bytes = value.as_bytes();

        if data_type == token::NIBBLE_8 {
            #[cfg(feature = "simd")]
            {
                const NIBBLE_LOOKUP: [u8; 16] =
                    [10, 11, 255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 255, 255];
                let lookup = Simd::from_array(NIBBLE_LOOKUP);
                let nibble_base = Simd::splat(b'-');

                while input_bytes.len() >= 16 {
                    let (chunk, rest) = input_bytes.split_at(16);
                    let input = u8x16::from_slice(chunk);
                    let indices = input.saturating_sub(nibble_base);
                    let nibbles = lookup.swizzle_dyn(indices);

                    let (evens, odds) = nibbles.deinterleave(nibbles.rotate_elements_left::<1>());
                    let packed: Simd<u8, 16> = (evens << Simd::splat(4)) | odds;
                    let packed_bytes = packed.to_array();
                    self.write_raw_bytes(&packed_bytes[..8])?;

                    input_bytes = rest;
                }
            }

            let mut bytes_iter = input_bytes.iter().copied();
            while let Some(part1) = bytes_iter.next() {
                let part2 = bytes_iter.next().unwrap_or(0);
                self.write_u8(Self::pack_byte_pair(Self::pack_nibble, part1, part2))?;
            }
        } else {
            #[cfg(feature = "simd")]
            {
                let ascii_0 = Simd::splat(b'0');
                let ascii_a = Simd::splat(b'A');
                let ten = Simd::splat(10);

                while input_bytes.len() >= 16 {
                    let (chunk, rest) = input_bytes.split_at(16);
                    let input = u8x16::from_slice(chunk);

                    let digit_vals = input - ascii_0;
                    let letter_vals = input - ascii_a + ten;
                    let is_letter = input.simd_ge(ascii_a);
                    let nibbles = is_letter.select(letter_vals, digit_vals);

                    let (evens, odds) = nibbles.deinterleave(nibbles.rotate_elements_left::<1>());
                    let packed: Simd<u8, 16> = (evens << Simd::splat(4)) | odds;
                    let packed_bytes = packed.to_array();
                    self.write_raw_bytes(&packed_bytes[..8])?;

                    input_bytes = rest;
                }
            }

            let mut bytes_iter = input_bytes.iter().copied();
            while let Some(part1) = bytes_iter.next() {
                let part2 = bytes_iter.next().unwrap_or(0);
                self.write_u8(Self::pack_byte_pair(Self::pack_hex, part1, part2))?;
            }
        }
        Ok(())
    }

    pub fn write_list_start(&mut self, len: usize) -> Result<()> {
        if len == 0 {
            self.write_u8(token::LIST_EMPTY)?;
        } else if len < 256 {
            self.write_u8(248)?;
            self.write_u8(len as u8)?;
        } else if len <= u16::MAX as usize {
            self.write_u8(249)?;
            self.write_u16_be(len as u16)?;
        } else {
            return Err(BinaryError::InvalidNode);
        }
        Ok(())
    }

    /// Write any node type (owned or borrowed) using the EncodeNode trait.
    pub fn write_node<N: EncodeNode>(&mut self, node: &N) -> Result<()> {
        let content_len = if node.has_content() { 1 } else { 0 };
        let list_len = 1 + (node.attrs_len() * 2) + content_len;

        self.write_list_start(list_len)?;
        self.write_string(node.tag())?;
        node.encode_attrs(self)?;
        node.encode_content(self)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::NodeBuilder;
    use crate::node::Attrs;
    use std::io::Cursor;

    type TestResult = crate::error::Result<()>;

    #[test]
    fn test_encode_node() -> TestResult {
        let node = Node::new(
            "message",
            Attrs::new(),
            Some(NodeContent::String("receipt".into())),
        );

        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;
        encoder.write_node(&node)?;

        let expected = vec![0, 248, 2, 19, 7];
        assert_eq!(buffer, expected);
        assert_eq!(buffer.len(), 5);
        Ok(())
    }

    #[test]
    fn test_nibble_packing() -> TestResult {
        // Test string with nibble characters: '-', '.', '0'-'9'
        let test_str = "-.0123456789";
        let node = Node::new(
            "test",
            Attrs::new(),
            Some(NodeContent::String(test_str.into())),
        );

        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;
        encoder.write_node(&node)?;

        let expected = vec![
            0, 248, 2, 252, 4, 116, 101, 115, 116, 255, 6, 171, 1, 35, 69, 103, 137,
        ];
        assert_eq!(buffer, expected);
        assert_eq!(buffer.len(), 17);
        Ok(())
    }

    /// Test LIST_8 boundary (length 255)
    #[test]
    fn test_list_size_list8_boundary() -> TestResult {
        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;

        // LIST_8 should be used for lengths 1-255
        encoder.write_list_start(255)?;

        // Expected: LIST_8 (248), then length 255
        assert_eq!(buffer[1], token::LIST_8);
        assert_eq!(buffer[2], 255);
        Ok(())
    }

    /// Test LIST_16 boundary (length 256)
    #[test]
    fn test_list_size_list16_boundary() -> TestResult {
        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;

        // LIST_16 should be used for lengths 256+
        encoder.write_list_start(256)?;

        // Expected: LIST_16 (249), then length as u16 big-endian
        assert_eq!(buffer[1], token::LIST_16);
        assert_eq!(buffer[2], 0x01); // 256 >> 8
        assert_eq!(buffer[3], 0x00); // 256 & 0xFF
        Ok(())
    }

    /// Test empty list encoding
    #[test]
    fn test_list_size_empty() -> TestResult {
        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;

        encoder.write_list_start(0)?;

        // Empty list uses LIST_EMPTY token
        assert_eq!(buffer[1], token::LIST_EMPTY);
        Ok(())
    }

    /// Test hex packing validation
    #[test]
    fn test_hex_validation() {
        // Valid hex strings (uppercase A-F, digits 0-9)
        assert!(validate_hex("0123456789ABCDEF"));
        assert!(validate_hex("DEADBEEF"));
        assert!(validate_hex("1234"));

        // Invalid: lowercase letters
        assert!(!validate_hex("abcdef"));
        assert!(!validate_hex("DeadBeef"));

        // Invalid: special characters
        assert!(!validate_hex("-"));
        assert!(!validate_hex("."));
        assert!(!validate_hex(" "));

        // Empty string is valid (but will be encoded as regular string)
        assert!(validate_hex(""));
    }

    /// Test nibble packing validation
    #[test]
    fn test_nibble_validation() {
        // Valid nibble strings: digits, dash, dot
        assert!(validate_nibble("0123456789"));
        assert!(validate_nibble("-"));
        assert!(validate_nibble("."));
        assert!(validate_nibble("123-456.789"));

        // Invalid: letters
        assert!(!validate_nibble("abc"));
        assert!(!validate_nibble("123abc"));

        // Invalid: uppercase letters
        assert!(!validate_nibble("ABC"));

        // Invalid: special characters other than - and .
        assert!(!validate_nibble("123!456"));
        assert!(!validate_nibble("@"));
    }

    /// Test BINARY_8, BINARY_20, BINARY_32 boundary transitions
    #[test]
    fn test_binary_length_boundaries() -> TestResult {
        // BINARY_8: length < 256
        let short_data = vec![0x42; 255];
        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;
        encoder.write_bytes_with_len(&short_data)?;
        assert_eq!(buffer[1], token::BINARY_8);
        assert_eq!(buffer[2], 255);

        // BINARY_20: 256 <= length < 2^20
        let medium_data = vec![0x42; 256];
        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;
        encoder.write_bytes_with_len(&medium_data)?;
        assert_eq!(buffer[1], token::BINARY_20);
        // 256 in u20 big-endian: 0x00, 0x01, 0x00
        assert_eq!(buffer[2], 0x00);
        assert_eq!(buffer[3], 0x01);
        assert_eq!(buffer[4], 0x00);

        Ok(())
    }

    /// Test node with many children uses correct list encoding
    #[test]
    fn test_node_with_255_children() -> TestResult {
        let children: Vec<Node> = (0..255)
            .map(|_| Node::new("child", Attrs::new(), None))
            .collect();

        let parent = Node::new("parent", Attrs::new(), Some(NodeContent::Nodes(children)));

        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;
        encoder.write_node(&parent)?;

        // Should encode successfully with LIST_8 for children
        assert!(!buffer.is_empty());
        Ok(())
    }

    /// Test node with 256 children uses LIST_16
    #[test]
    fn test_node_with_256_children() -> TestResult {
        let children: Vec<Node> = (0..256)
            .map(|_| Node::new("x", Attrs::new(), None))
            .collect();

        let parent = Node::new("parent", Attrs::new(), Some(NodeContent::Nodes(children)));

        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;
        encoder.write_node(&parent)?;

        // Should encode successfully with LIST_16 for children
        assert!(!buffer.is_empty());
        Ok(())
    }

    /// Test string at PACKED_MAX boundary (127 chars)
    #[test]
    fn test_packed_max_boundary() {
        // Exactly PACKED_MAX characters should be valid for packing
        let max_nibble = "0".repeat(token::PACKED_MAX as usize);
        assert!(validate_nibble(&max_nibble));

        // One more than PACKED_MAX should NOT be packed
        let over_max = "0".repeat(token::PACKED_MAX as usize + 1);
        assert!(!validate_nibble(&over_max));
    }

    /// Test empty string encoding - should be BINARY_8 + 0, not just 0
    #[test]
    fn test_empty_string_encoding() -> TestResult {
        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;
        encoder.write_string("")?;

        // According to WhatsApp web protocol:
        // Empty string should be encoded as BINARY_8 (252) + 0
        // NOT as token 0 (LIST_EMPTY)
        println!("Empty string encoding: {:?}", &buffer[1..]);
        assert_eq!(
            buffer.len(),
            3,
            "Empty string should encode to 2 bytes (plus leading 0)"
        );
        assert_eq!(
            buffer[1],
            token::BINARY_8,
            "First byte should be BINARY_8 (252)"
        );
        assert_eq!(buffer[2], 0, "Second byte should be 0 (length)");
        Ok(())
    }

    /// Test encode/decode round-trip for empty string in node attributes
    #[test]
    fn test_empty_string_roundtrip() -> TestResult {
        use crate::decoder::Decoder;

        let mut attrs = Attrs::new();
        attrs.insert("key", ""); // Empty value
        attrs.insert("", "value"); // Empty key

        let node = Node::new("test", attrs, Some(NodeContent::String("".into())));

        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;
        encoder.write_node(&node)?;

        let mut decoder = Decoder::new(&buffer[1..]);
        let decoded = decoder.read_node_ref()?.to_owned();

        assert_eq!(decoded.tag, "test");
        assert_eq!(
            decoded.attrs.get("key"),
            Some(&NodeValue::String("".into()))
        );
        assert_eq!(
            decoded.attrs.get(""),
            Some(&NodeValue::String("value".into()))
        );

        // Empty strings are encoded as BINARY_8 + 0, which decodes as empty bytes
        match &decoded.content {
            Some(NodeContent::Bytes(b)) => assert!(b.is_empty(), "Content should be empty bytes"),
            other => panic!("Expected empty bytes, got {:?}", other),
        }
        Ok(())
    }

    /// Test the JID parsing optimization: short JIDs should still be parsed,
    /// while long strings should be encoded as raw bytes.
    #[test]
    fn test_jid_length_heuristic() -> TestResult {
        use crate::decoder::Decoder;
        use crate::token;

        // Short JID: should be encoded as a JID token (48 bytes or less)
        let short_jid = "user@s.whatsapp.net";
        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;
        encoder.write_string(short_jid)?;

        // JID_PAIR token indicates JID encoding was used
        assert_eq!(
            buffer[1],
            token::JID_PAIR,
            "Short JID should be encoded as JID_PAIR token"
        );

        // Long string (> 48 chars): should be encoded as raw bytes, not as JID
        let long_text = "x".repeat(300) + "@s.whatsapp.net";
        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;
        encoder.write_string(&long_text)?;

        // BINARY_20 token indicates raw bytes encoding (length > 255)
        assert_eq!(
            buffer[1],
            token::BINARY_20,
            "Long string should be encoded as BINARY_20, not as JID"
        );

        // Verify round-trip for long string
        let node = Node::new(
            "msg",
            Attrs::new(),
            Some(NodeContent::String(long_text.as_str().into())),
        );
        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;
        encoder.write_node(&node)?;

        let mut decoder = Decoder::new(&buffer[1..]);
        let decoded = decoder.read_node_ref()?.to_owned();
        match &decoded.content {
            Some(NodeContent::Bytes(b)) => {
                assert_eq!(
                    String::from_utf8_lossy(b),
                    long_text,
                    "Long string should round-trip correctly"
                );
            }
            other => panic!("Expected bytes content, got {:?}", other),
        }

        Ok(())
    }

    #[test]
    fn test_jid_parser_preserves_non_numeric_device_suffix() -> TestResult {
        use crate::decoder::Decoder;

        let value = "foo:bar@s.whatsapp.net";
        let node = Node::new("msg", Attrs::new(), Some(NodeContent::String(value.into())));

        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;
        encoder.write_node(&node)?;

        let mut decoder = Decoder::new(&buffer[1..]);
        let decoded = decoder.read_node_ref()?.to_owned();
        match decoded.content {
            Some(NodeContent::String(s)) => assert_eq!(s, value),
            other => panic!("Expected string content, got {:?}", other),
        }
        Ok(())
    }

    #[test]
    fn test_jid_parser_preserves_non_numeric_agent_suffix() -> TestResult {
        use crate::decoder::Decoder;

        let value = "hello_world@s.whatsapp.net";
        let node = Node::new("msg", Attrs::new(), Some(NodeContent::String(value.into())));

        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;
        encoder.write_node(&node)?;

        let mut decoder = Decoder::new(&buffer[1..]);
        let decoded = decoder.read_node_ref()?.to_owned();
        match decoded.content {
            Some(NodeContent::String(s)) => assert_eq!(s, value),
            other => panic!("Expected string content, got {:?}", other),
        }
        Ok(())
    }

    /// Regression test: AD_JID domain_type must be derived from the server field,
    /// not from jid.agent.
    ///
    /// The binary AD_JID format is: [0xF7] [domain_type] [device] [user_string]
    /// where domain_type encodes the server: 0=s.whatsapp.net, 1=lid, 128=hosted.
    ///
    /// A previous bug wrote `jid.agent` (always 0) instead of the domain_type,
    /// causing LID JIDs to be encoded as s.whatsapp.net JIDs. The real WhatsApp
    /// server rejected these with error 421, while our mock server accepted them
    /// because it doesn't validate domain_type — hence e2e tests didn't catch it.
    #[test]
    fn test_ad_jid_domain_type_lid() -> TestResult {
        // Encode a LID device JID as a node attribute
        let lid_jid = Jid::lid_device("236395184570386", 39);
        let node = NodeBuilder::new("to").attr("jid", lid_jid).build();

        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;
        encoder.write_node(&node)?;

        // Find the AD_JID marker (0xF7 = 247) in the encoded bytes
        let ad_jid_pos = buffer
            .iter()
            .position(|&b| b == token::AD_JID)
            .expect("AD_JID token (0xF7) must be present for device JID");

        // Byte after AD_JID is domain_type: must be 1 for "lid"
        let domain_type = buffer[ad_jid_pos + 1];
        assert_eq!(
            domain_type, 1,
            "LID JID must encode domain_type=1 (lid), got {domain_type} (0=whatsapp, 128=hosted)"
        );

        // Byte after domain_type is device
        let device = buffer[ad_jid_pos + 2];
        assert_eq!(device, 39, "Device byte must be 39");

        Ok(())
    }

    #[test]
    fn test_ad_jid_domain_type_whatsapp() -> TestResult {
        let pn_jid = Jid::pn_device("551199887766", 33);
        let node = NodeBuilder::new("to").attr("jid", pn_jid).build();

        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(Cursor::new(&mut buffer))?;
        encoder.write_node(&node)?;

        let ad_jid_pos = buffer
            .iter()
            .position(|&b| b == token::AD_JID)
            .expect("AD_JID token must be present for device JID");

        let domain_type = buffer[ad_jid_pos + 1];
        assert_eq!(
            domain_type, 0,
            "s.whatsapp.net JID must encode domain_type=0, got {domain_type}"
        );

        Ok(())
    }

    /// Verify that string-encoded JIDs and direct Jid-encoded JIDs produce
    /// identical bytes AND decode back to the same JID. This catches any
    /// divergence between the two encoding paths (root cause of the domain_type
    /// bug) and ensures encode→decode round-trip fidelity for all server types.
    #[test]
    fn test_jid_string_vs_direct_encoding_matches() -> TestResult {
        use crate::decoder::Decoder;

        let test_cases: Vec<Jid> = vec![
            Jid::lid_device("236395184570386", 39),     // LID with device
            Jid::pn_device("551199887766", 33),         // PN with device
            Jid::lid("236395184570386"),                // LID primary (device 0)
            Jid::pn("551199887766"),                    // PN primary (device 0)
            "5511999887766:99@hosted".parse().unwrap(), // HOSTED device
            "100000012345678:99@hosted.lid".parse().unwrap(), // HOSTED_LID device
        ];

        for jid in test_cases {
            // Path 1: string encoding (known correct — uses parse_jid_meta)
            let node_str = NodeBuilder::new("to").attr("jid", jid.to_string()).build();

            // Path 2: direct Jid encoding (uses write_jid_owned)
            let node_jid = NodeBuilder::new("to").attr("jid", jid.clone()).build();

            let mut buf_str = Vec::new();
            Encoder::new(Cursor::new(&mut buf_str))?.write_node(&node_str)?;

            let mut buf_jid = Vec::new();
            Encoder::new(Cursor::new(&mut buf_jid))?.write_node(&node_jid)?;

            assert_eq!(
                buf_str, buf_jid,
                "String vs direct Jid encoding must produce identical bytes for {jid}"
            );

            // Round-trip: decode the encoded bytes and verify the JID is preserved.
            // Skip version byte (first byte) then decode.
            let mut decoder = Decoder::new(&buf_jid[1..]);
            let decoded_node = decoder.read_node_ref()?.to_owned();
            let decoded_jid: Jid = decoded_node
                .attrs()
                .optional_jid("jid")
                .expect("jid attr must round-trip as JID");

            assert_eq!(
                jid.user, decoded_jid.user,
                "Round-trip user mismatch for {jid}"
            );
            assert_eq!(
                jid.device, decoded_jid.device,
                "Round-trip device mismatch for {jid}"
            );
            assert_eq!(
                jid.server, decoded_jid.server,
                "Round-trip server mismatch for {jid}"
            );
        }

        Ok(())
    }

    /// Regression test: strings at the PACKED_MAX boundary must be classified
    /// normally, while strings above it must be emitted as raw bytes (skipping
    /// SipHash/PHF classification entirely).
    #[test]
    fn test_long_string_skips_classification() -> TestResult {
        use crate::decoder::Decoder;
        use crate::marshal::marshal;

        let at_boundary = "0".repeat(token::PACKED_MAX as usize); // 127 nibble chars
        let over_boundary = "0".repeat(token::PACKED_MAX as usize + 1); // 128 chars

        // 127-char all-digit string is nibble-packable
        let node_at = Node::new(
            "test",
            Attrs::new(),
            Some(NodeContent::String(at_boundary.as_str().into())),
        );
        let encoded_at = marshal(&node_at)?;

        // 128-char string must be emitted as raw bytes (BINARY_8 + length)
        let node_over = Node::new(
            "test",
            Attrs::new(),
            Some(NodeContent::String(over_boundary.as_str().into())),
        );
        let encoded_over = marshal(&node_over)?;

        // The 127-char string should be packed (shorter encoding than raw)
        assert!(
            encoded_at.len() < encoded_over.len(),
            "127-char nibble string should pack smaller than 128-char raw: {} vs {}",
            encoded_at.len(),
            encoded_over.len(),
        );

        // The 128-char content must be encoded as BINARY_8 + 128 (raw bytes).
        // Find the [BINARY_8, 128] pair — the first BINARY_8 is for the tag "test".
        let has_raw_128 = encoded_over
            .windows(2)
            .any(|w| w[0] == token::BINARY_8 && w[1] == 128);
        assert!(
            has_raw_128,
            "128-char string must contain BINARY_8 + length=128 sequence"
        );

        // Both must round-trip correctly (skip version byte at [0])
        let decoded_at = Decoder::new(&encoded_at[1..]).read_node_ref()?.to_owned();
        let decoded_over = Decoder::new(&encoded_over[1..]).read_node_ref()?.to_owned();

        match &decoded_at.content {
            Some(NodeContent::String(s)) => assert_eq!(s.as_str(), at_boundary),
            Some(NodeContent::Bytes(b)) => {
                assert_eq!(std::str::from_utf8(b).unwrap(), at_boundary)
            }
            other => panic!("Expected string/bytes content, got {:?}", other),
        }
        match &decoded_over.content {
            Some(NodeContent::Bytes(b)) => {
                assert_eq!(std::str::from_utf8(b).unwrap(), over_boundary)
            }
            other => panic!(
                "Expected bytes content for 128-char string, got {:?}",
                other
            ),
        }

        Ok(())
    }
}
