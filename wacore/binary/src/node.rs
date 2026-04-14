use crate::attrs::{AttrParser, AttrParserRef};
use crate::jid::{Jid, JidRef};
use crate::token;
use bytes::Bytes;
use compact_str::CompactString;
use stable_deref_trait::StableDeref;
use std::borrow::Cow;

/// Borrowed-or-inline string for decoded nodes. Short owned values (≤24 bytes)
/// are stored inline via `CompactString`, avoiding heap allocation.
#[derive(Clone, yoke::Yokeable)]
pub enum NodeStr<'a> {
    Borrowed(&'a str),
    Owned(CompactString),
}

impl NodeStr<'_> {
    /// Clone-preserving conversion. Avoids re-parsing the inner CompactString
    /// when converting owned NodeStr values in `to_owned()` paths.
    #[inline]
    pub fn to_compact_string(&self) -> CompactString {
        match self {
            NodeStr::Borrowed(s) => CompactString::from(*s),
            NodeStr::Owned(cs) => cs.clone(),
        }
    }
}

impl Default for NodeStr<'_> {
    #[inline]
    fn default() -> Self {
        NodeStr::Borrowed("")
    }
}

impl std::ops::Deref for NodeStr<'_> {
    type Target = str;
    #[inline(always)]
    fn deref(&self) -> &str {
        match self {
            NodeStr::Borrowed(s) => s,
            NodeStr::Owned(cs) => cs.as_str(),
        }
    }
}

impl AsRef<str> for NodeStr<'_> {
    #[inline(always)]
    fn as_ref(&self) -> &str {
        self
    }
}

impl std::fmt::Debug for NodeStr<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, f)
    }
}

impl std::fmt::Display for NodeStr<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for NodeStr<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self)
    }
}

impl PartialEq for NodeStr<'_> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl Eq for NodeStr<'_> {}

impl std::hash::Hash for NodeStr<'_> {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (**self).hash(state)
    }
}

impl PartialEq<str> for NodeStr<'_> {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        &**self == other
    }
}

impl PartialEq<&str> for NodeStr<'_> {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        &**self == *other
    }
}

impl<'a> From<&'a str> for NodeStr<'a> {
    #[inline]
    fn from(s: &'a str) -> Self {
        NodeStr::Borrowed(s)
    }
}

impl From<CompactString> for NodeStr<'_> {
    #[inline]
    fn from(s: CompactString) -> Self {
        NodeStr::Owned(s)
    }
}

/// Intern a string as a `Cow::Borrowed(&'static str)` if it matches a known token,
/// otherwise allocate a `Cow::Owned(String)`. This avoids heap allocations for the
/// vast majority of tag names and attribute keys which are protocol tokens.
#[inline]
fn intern_cow(s: &str) -> Cow<'static, str> {
    if let Some(kind) = token::index_of_token(s) {
        let interned = match kind {
            token::TokenKind::Single(idx) => token::get_single_token(idx),
            token::TokenKind::Double(dict, idx) => token::get_double_token(dict, idx),
        };
        if let Some(token) = interned {
            return Cow::Borrowed(token);
        }
    }
    Cow::Owned(s.to_string())
}

/// An owned attribute value that can be either a string or a structured JID.
/// This avoids string allocation for JID attributes by storing the JID directly,
/// eliminating format/parse overhead when routing logic needs the JID.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub enum NodeValue {
    String(CompactString),
    Jid(Jid),
}

impl Default for NodeValue {
    fn default() -> Self {
        NodeValue::String(CompactString::default())
    }
}

impl NodeValue {
    /// String view of the value. Works for both variants.
    /// - String variant: Cow::Borrowed(&str) — zero copy
    /// - Jid variant: Cow::Owned(formatted) — allocates only when needed
    #[inline]
    pub fn as_str(&self) -> Cow<'_, str> {
        match self {
            NodeValue::String(s) => Cow::Borrowed(s.as_str()),
            NodeValue::Jid(j) => Cow::Owned(j.to_string()),
        }
    }

    /// Convert to an owned Jid, parsing from string if necessary.
    #[inline]
    pub fn to_jid(&self) -> Option<Jid> {
        match self {
            NodeValue::Jid(j) => Some(j.clone()),
            NodeValue::String(s) => s.parse().ok(),
        }
    }
}

use std::fmt;

impl fmt::Display for NodeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeValue::String(s) => write!(f, "{}", s),
            NodeValue::Jid(j) => write!(f, "{}", j),
        }
    }
}

impl PartialEq<str> for NodeValue {
    fn eq(&self, other: &str) -> bool {
        match self {
            NodeValue::String(s) => s == other,
            // Compare JID to string without heap allocation by streaming the
            // Display output through a writer that checks byte-by-byte.
            NodeValue::Jid(j) => {
                use std::fmt::Write;
                struct EqCheck<'a> {
                    target: &'a [u8],
                    pos: usize,
                    matches: bool,
                }
                impl fmt::Write for EqCheck<'_> {
                    fn write_str(&mut self, s: &str) -> fmt::Result {
                        if !self.matches {
                            return Ok(());
                        }
                        let bytes = s.as_bytes();
                        let end = self.pos + bytes.len();
                        if end > self.target.len() || self.target[self.pos..end] != *bytes {
                            self.matches = false;
                        }
                        self.pos = end;
                        Ok(())
                    }
                }
                let mut check = EqCheck {
                    target: other.as_bytes(),
                    pos: 0,
                    matches: true,
                };
                let _ = write!(check, "{}", j);
                check.matches && check.pos == other.len()
            }
        }
    }
}

impl PartialEq<&str> for NodeValue {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}

impl PartialEq<String> for NodeValue {
    fn eq(&self, other: &String) -> bool {
        self == other.as_str()
    }
}

impl From<String> for NodeValue {
    #[inline]
    fn from(s: String) -> Self {
        NodeValue::String(CompactString::from(s))
    }
}

impl From<&str> for NodeValue {
    #[inline]
    fn from(s: &str) -> Self {
        NodeValue::String(CompactString::from(s))
    }
}

impl From<&String> for NodeValue {
    #[inline]
    fn from(s: &String) -> Self {
        NodeValue::String(CompactString::from(s.as_str()))
    }
}

impl From<CompactString> for NodeValue {
    #[inline]
    fn from(s: CompactString) -> Self {
        NodeValue::String(s)
    }
}

impl From<Jid> for NodeValue {
    #[inline]
    fn from(jid: Jid) -> Self {
        NodeValue::Jid(jid)
    }
}

impl From<&Jid> for NodeValue {
    #[inline]
    fn from(jid: &Jid) -> Self {
        NodeValue::Jid(jid.clone())
    }
}

/// A collection of node attributes stored as key-value pairs.
/// Uses a Vec internally for better cache locality with small attribute counts (typically 3-6).
/// Values can be either strings or JIDs, avoiding stringification overhead for JID attributes.
/// Keys use `Cow<'static, str>` to avoid heap allocation for compile-time-known strings
/// (e.g., "type", "id", "to") which are the vast majority of attribute keys.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Attrs(pub Vec<(Cow<'static, str>, NodeValue)>);

impl Attrs {
    #[inline]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// Get a reference to the NodeValue for a key, or None if not found.
    /// Uses linear search which is efficient for small attribute counts.
    #[inline]
    pub fn get(&self, key: &str) -> Option<&NodeValue> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Check if a key exists.
    #[inline]
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.iter().any(|(k, _)| k == key)
    }

    /// Insert a key-value pair. If the key already exists, update the value.
    #[inline]
    pub fn insert(&mut self, key: impl Into<Cow<'static, str>>, value: impl Into<NodeValue>) {
        let key = key.into();
        let value = value.into();
        if let Some(pos) = self.0.iter().position(|(k, _)| k == &key) {
            self.0[pos].1 = value;
        } else {
            self.0.push((key, value));
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over key-value pairs.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&Cow<'static, str>, &NodeValue)> {
        self.0.iter().map(|(k, v)| (k, v))
    }

    /// Push a key-value pair without checking for duplicates.
    /// Use this when building from a known-unique source (e.g., decoding).
    #[inline]
    pub fn push(&mut self, key: impl Into<Cow<'static, str>>, value: impl Into<NodeValue>) {
        self.0.push((key.into(), value.into()));
    }

    /// Push a NodeValue directly without conversion.
    /// Slightly more efficient when you already have a NodeValue.
    #[inline]
    pub fn push_value(&mut self, key: impl Into<Cow<'static, str>>, value: NodeValue) {
        self.0.push((key.into(), value));
    }

    /// Iterate over keys only.
    #[inline]
    pub fn keys(&self) -> impl Iterator<Item = &Cow<'static, str>> {
        self.0.iter().map(|(k, _)| k)
    }
}

/// Owned iterator implementation (consuming).
impl IntoIterator for Attrs {
    type Item = (Cow<'static, str>, NodeValue);
    type IntoIter = std::vec::IntoIter<(Cow<'static, str>, NodeValue)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Borrowed iterator implementation.
impl<'a> IntoIterator for &'a Attrs {
    type Item = (&'a Cow<'static, str>, &'a NodeValue);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'a, (Cow<'static, str>, NodeValue)>,
        fn(&'a (Cow<'static, str>, NodeValue)) -> (&'a Cow<'static, str>, &'a NodeValue),
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter().map(|(k, v)| (k, v))
    }
}

impl FromIterator<(Cow<'static, str>, NodeValue)> for Attrs {
    fn from_iter<I: IntoIterator<Item = (Cow<'static, str>, NodeValue)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}
pub type AttrsRef<'a> = Vec<(NodeStr<'a>, ValueRef<'a>)>;

/// A decoded attribute value that can be either a string or a structured JID.
/// This avoids string allocation when decoding JID tokens - the JidRef is returned
/// directly and only converted to a string when actually needed.
#[derive(Debug, Clone, PartialEq, yoke::Yokeable)]
pub enum ValueRef<'a> {
    String(NodeStr<'a>),
    Jid(JidRef<'a>),
}

#[cfg(feature = "serde")]
impl serde::Serialize for ValueRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            ValueRef::String(s) => {
                serializer.serialize_newtype_variant("NodeValue", 0, "String", &**s)
            }
            ValueRef::Jid(j) => serializer.serialize_newtype_variant("NodeValue", 1, "Jid", j),
        }
    }
}

impl<'a> ValueRef<'a> {
    /// String view of the value. Borrows from `self`.
    /// - String variant: borrows the inner str — zero copy
    /// - Jid variant: Cow::Owned — allocates only when needed
    pub fn as_str(&self) -> Cow<'_, str> {
        match self {
            ValueRef::String(s) => Cow::Borrowed(s),
            ValueRef::Jid(j) => Cow::Owned(j.to_string()),
        }
    }

    /// Get the value as a JidRef, if it's a JID variant.
    pub fn as_jid(&self) -> Option<&JidRef<'a>> {
        match self {
            ValueRef::Jid(j) => Some(j),
            ValueRef::String(_) => None,
        }
    }

    /// Convert to an owned Jid, parsing from string if necessary.
    pub fn to_jid(&self) -> Option<Jid> {
        match self {
            ValueRef::Jid(j) => Some(j.to_owned()),
            ValueRef::String(s) => Jid::from_str(s.as_ref()).ok(),
        }
    }

    /// Convert to an owned NodeValue, preserving the variant (JID stays JID).
    pub fn to_node_value(&self) -> NodeValue {
        match self {
            ValueRef::String(s) => NodeValue::String(s.to_compact_string()),
            ValueRef::Jid(j) => NodeValue::Jid(j.to_owned()),
        }
    }
}

use std::str::FromStr;

impl<'a> fmt::Display for ValueRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValueRef::String(s) => write!(f, "{}", s),
            ValueRef::Jid(j) => write!(f, "{}", j),
        }
    }
}

pub type NodeVec<'a> = Vec<NodeRef<'a>>;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub enum NodeContent {
    Bytes(Vec<u8>),
    String(CompactString),
    Nodes(Vec<Node>),
}

#[derive(Debug, Clone, PartialEq, yoke::Yokeable)]
pub enum NodeContentRef<'a> {
    Bytes(Cow<'a, [u8]>),
    String(NodeStr<'a>),
    Nodes(Box<NodeVec<'a>>),
}

#[cfg(feature = "serde")]
impl serde::Serialize for NodeContentRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            NodeContentRef::Bytes(b) => {
                serializer.serialize_newtype_variant("NodeContent", 0, "Bytes", b.as_ref())
            }
            NodeContentRef::String(s) => {
                serializer.serialize_newtype_variant("NodeContent", 1, "String", &**s)
            }
            NodeContentRef::Nodes(nodes) => {
                serializer.serialize_newtype_variant("NodeContent", 2, "Nodes", nodes.as_slice())
            }
        }
    }
}

impl NodeContent {
    /// Convert an owned NodeContent to a borrowed NodeContentRef.
    pub fn as_content_ref(&self) -> NodeContentRef<'_> {
        match self {
            NodeContent::Bytes(b) => NodeContentRef::Bytes(Cow::Borrowed(b)),
            NodeContent::String(s) => NodeContentRef::String(NodeStr::Borrowed(s.as_str())),
            NodeContent::Nodes(nodes) => {
                NodeContentRef::Nodes(Box::new(nodes.iter().map(|n| n.as_node_ref()).collect()))
            }
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Node {
    pub tag: Cow<'static, str>,
    pub attrs: Attrs,
    pub content: Option<NodeContent>,
}

#[derive(Debug, Clone, PartialEq, yoke::Yokeable)]
pub struct NodeRef<'a> {
    pub tag: NodeStr<'a>,
    pub attrs: AttrsRef<'a>,
    pub content: Option<Box<NodeContentRef<'a>>>,
}

impl Node {
    pub fn new(
        tag: impl Into<Cow<'static, str>>,
        attrs: Attrs,
        content: Option<NodeContent>,
    ) -> Self {
        Self {
            tag: tag.into(),
            attrs,
            content,
        }
    }

    /// Convert an owned Node to a borrowed NodeRef.
    /// The returned NodeRef borrows from self.
    pub fn as_node_ref(&self) -> NodeRef<'_> {
        NodeRef {
            tag: NodeStr::Borrowed(self.tag.as_ref()),
            attrs: self
                .attrs
                .iter()
                .map(|(k, v)| {
                    let value_ref = match v {
                        NodeValue::String(s) => ValueRef::String(NodeStr::Borrowed(s.as_str())),
                        NodeValue::Jid(j) => ValueRef::Jid(JidRef {
                            user: NodeStr::Borrowed(&j.user),
                            server: j.server,
                            agent: j.agent,
                            device: j.device,
                            integrator: j.integrator,
                        }),
                    };
                    (NodeStr::Borrowed(k.as_ref()), value_ref)
                })
                .collect(),
            content: self.content.as_ref().map(|c| Box::new(c.as_content_ref())),
        }
    }

    pub fn children(&self) -> Option<&[Node]> {
        match &self.content {
            Some(NodeContent::Nodes(nodes)) => Some(nodes),
            _ => None,
        }
    }

    pub fn attrs(&self) -> AttrParser<'_> {
        AttrParser::new(self)
    }

    pub fn get_optional_child_by_tag<'a>(&'a self, tags: &[&str]) -> Option<&'a Node> {
        let mut current_node = self;
        for &tag in tags {
            if let Some(children) = current_node.children() {
                if let Some(found) = children.iter().find(|c| c.tag == tag) {
                    current_node = found;
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }
        Some(current_node)
    }

    pub fn get_children_by_tag<'a>(&'a self, tag: &'a str) -> impl Iterator<Item = &'a Node> {
        self.children()
            .into_iter()
            .flatten()
            .filter(move |c| c.tag == tag)
    }

    pub fn get_optional_child(&self, tag: &str) -> Option<&Node> {
        self.children()
            .and_then(|nodes| nodes.iter().find(|node| node.tag == tag))
    }

    /// Extract text content, handling both String and Bytes (lossy UTF-8).
    pub fn content_as_string(&self) -> Option<CompactString> {
        match &self.content {
            Some(NodeContent::String(s)) => Some(s.clone()),
            Some(NodeContent::Bytes(b)) => {
                Some(CompactString::from(String::from_utf8_lossy(b).as_ref()))
            }
            _ => None,
        }
    }
}

/// Wrapper that serializes `AttrsRef` with the same newtype-struct framing
/// that serde's derive produces for `Attrs(Vec<...>)`. Without this, binary
/// formats (bincode, postcard, etc.) would see a bare sequence instead of a
/// newtype struct wrapper.
#[cfg(feature = "serde")]
struct AttrsRefWrapper<'a, 'b>(&'b AttrsRef<'a>);

#[cfg(feature = "serde")]
impl serde::Serialize for AttrsRefWrapper<'_, '_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_newtype_struct("Attrs", self.0)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for NodeRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("Node", 3)?;
        s.serialize_field("tag", &*self.tag)?;
        s.serialize_field("attrs", &AttrsRefWrapper(&self.attrs))?;
        s.serialize_field("content", &self.content)?;
        s.end()
    }
}

impl<'a> NodeRef<'a> {
    pub fn new(tag: NodeStr<'a>, attrs: AttrsRef<'a>, content: Option<NodeContentRef<'a>>) -> Self {
        Self {
            tag,
            attrs,
            content: content.map(Box::new),
        }
    }

    pub fn attrs(&self) -> AttrParserRef<'_> {
        AttrParserRef::new(self)
    }

    pub fn children(&self) -> Option<&[NodeRef<'a>]> {
        match self.content.as_deref() {
            Some(NodeContentRef::Nodes(nodes)) => Some(nodes.as_slice()),
            _ => None,
        }
    }

    pub fn get_attr(&self, key: &str) -> Option<&ValueRef<'a>> {
        self.attrs.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    pub fn attrs_iter(&self) -> impl Iterator<Item = (&NodeStr<'a>, &ValueRef<'a>)> {
        self.attrs.iter().map(|(k, v)| (k, v))
    }

    pub fn get_optional_child_by_tag(&self, tags: &[&str]) -> Option<&NodeRef<'a>> {
        let mut current_node = self;
        for &tag in tags {
            if let Some(children) = current_node.children() {
                if let Some(found) = children.iter().find(|c| c.tag == tag) {
                    current_node = found;
                } else {
                    return None;
                }
            } else {
                return None;
            }
        }
        Some(current_node)
    }

    pub fn get_children_by_tag<'b>(&'b self, tag: &'b str) -> impl Iterator<Item = &'b NodeRef<'a>>
    where
        'a: 'b,
    {
        self.children()
            .into_iter()
            .flatten()
            .filter(move |c| c.tag == tag)
    }

    pub fn get_optional_child(&self, tag: &str) -> Option<&NodeRef<'a>> {
        self.children()
            .and_then(|nodes| nodes.iter().find(|node| node.tag == tag))
    }

    /// Extract text content, handling both String and Bytes (lossy UTF-8).
    pub fn content_as_string(&self) -> Option<CompactString> {
        match self.content.as_deref() {
            Some(NodeContentRef::String(s)) => Some(s.to_compact_string()),
            Some(NodeContentRef::Bytes(b)) => Some(CompactString::from(
                String::from_utf8_lossy(b.as_ref()).as_ref(),
            )),
            _ => None,
        }
    }

    /// Zero-copy byte content, if this node has Bytes content.
    pub fn content_bytes(&self) -> Option<&[u8]> {
        match self.content.as_deref() {
            Some(NodeContentRef::Bytes(b)) => Some(b.as_ref()),
            _ => None,
        }
    }

    /// Zero-copy string content, if this node has String content.
    pub fn content_str(&self) -> Option<&str> {
        match self.content.as_deref() {
            Some(NodeContentRef::String(s)) => Some(s.as_ref()),
            _ => None,
        }
    }

    /// Child nodes from content, if this node has Nodes content.
    /// Alias for `children()`.
    #[inline]
    pub fn content_nodes(&self) -> Option<&[NodeRef<'a>]> {
        self.children()
    }

    pub fn to_owned(&self) -> Node {
        Node {
            tag: intern_cow(&self.tag),
            attrs: self
                .attrs
                .iter()
                .map(|(k, v)| {
                    let value = match v {
                        ValueRef::String(s) => NodeValue::String(s.to_compact_string()),
                        ValueRef::Jid(j) => NodeValue::Jid(j.to_owned()),
                    };
                    (intern_cow(k), value)
                })
                .collect::<Attrs>(),
            content: self.content.as_deref().map(|c| match c {
                NodeContentRef::Bytes(b) => NodeContent::Bytes(b.to_vec()),
                NodeContentRef::String(s) => NodeContent::String(s.to_compact_string()),
                NodeContentRef::Nodes(nodes) => {
                    NodeContent::Nodes(nodes.iter().map(|n| n.to_owned()).collect())
                }
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// OwnedNodeRef — self-referential zero-copy node via yoke
// ---------------------------------------------------------------------------

use yoke::Yoke;

#[derive(Clone)]
struct BytesCart(Bytes);

impl std::ops::Deref for BytesCart {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

// Safety: `Bytes` points to immutable backing storage whose deref target
// remains stable for the lifetime of the value, even when the wrapper moves.
unsafe impl StableDeref for BytesCart {}

/// A decoded node that owns its decompressed buffer. The inner `NodeRef`
/// borrows string/byte payloads directly from the buffer, avoiding copies.
/// Container allocations (attribute Vec, child Vec) still occur during decode.
///
/// Wrap in `Arc<OwnedNodeRef>` for cheap sharing across handlers.
pub struct OwnedNodeRef {
    inner: Yoke<NodeRef<'static>, BytesCart>,
}

impl OwnedNodeRef {
    /// Decode a node from an owned buffer. The buffer should be the raw
    /// binary-protocol bytes (after decompression, without the leading
    /// format byte which `unpack` already strips).
    pub fn new(buffer: impl Into<Bytes>) -> crate::error::Result<Self> {
        let inner = Yoke::try_attach_to_cart(BytesCart(buffer.into()), |buf| {
            crate::marshal::unmarshal_ref(buf)
        })?;
        Ok(Self { inner })
    }

    /// Access the borrowed node.
    #[inline]
    pub fn get(&self) -> &NodeRef<'_> {
        self.inner.get()
    }

    /// Convert to an owned `Node`, cloning all data out of the buffer.
    /// Use sparingly — this is the allocation path that yoke is designed to avoid.
    pub fn to_owned_node(&self) -> Node {
        self.inner.get().to_owned()
    }

    /// The tag name of this node.
    #[inline]
    pub fn tag(&self) -> &str {
        &self.get().tag
    }

    /// Get an attribute parser for this node.
    #[inline]
    pub fn attrs(&self) -> AttrParserRef<'_> {
        self.get().attrs()
    }

    /// Look up a single attribute by key.
    #[inline]
    pub fn get_attr(&self, key: &str) -> Option<&ValueRef<'_>> {
        self.get().get_attr(key)
    }

    /// Get child nodes, if content is a node list.
    #[inline]
    pub fn children(&self) -> Option<&[NodeRef<'_>]> {
        self.get().children()
    }

    /// Find a child node by tag.
    #[inline]
    pub fn get_optional_child(&self, tag: &str) -> Option<&NodeRef<'_>> {
        self.get().get_optional_child(tag)
    }

    /// Find a child by traversing a path of tags.
    #[inline]
    pub fn get_optional_child_by_tag(&self, tags: &[&str]) -> Option<&NodeRef<'_>> {
        self.get().get_optional_child_by_tag(tags)
    }

    /// Get children matching a tag.
    #[inline]
    pub fn get_children_by_tag<'b>(
        &'b self,
        tag: &'b str,
    ) -> impl Iterator<Item = &'b NodeRef<'b>> {
        self.get().get_children_by_tag(tag)
    }

    /// Zero-copy byte content, if this node has Bytes content.
    #[inline]
    pub fn content_bytes(&self) -> Option<&[u8]> {
        self.get().content_bytes()
    }

    /// Zero-copy string content, if this node has String content.
    #[inline]
    pub fn content_str(&self) -> Option<&str> {
        self.get().content_str()
    }

    /// Child nodes from content, if this node has Nodes content.
    #[inline]
    pub fn content_nodes(&self) -> Option<&[NodeRef<'_>]> {
        self.get().content_nodes()
    }

    /// Extract text content, handling both String and Bytes (lossy UTF-8).
    #[inline]
    pub fn content_as_string(&self) -> Option<CompactString> {
        self.get().content_as_string()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for OwnedNodeRef {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.get().serialize(serializer)
    }
}

impl std::fmt::Debug for OwnedNodeRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.get().fmt(f)
    }
}

#[cfg(test)]
#[cfg(feature = "serde")]
mod serde_tests {
    use super::*;
    use crate::jid::{Jid, Server};

    #[test]
    fn node_ref_serializes_same_as_node() {
        let node = Node::new(
            Cow::Borrowed("message"),
            Attrs(vec![
                (Cow::Borrowed("type"), NodeValue::String("text".into())),
                (Cow::Borrowed("from"), NodeValue::Jid(Jid::pn("5550199999"))),
            ]),
            Some(NodeContent::String("hello".into())),
        );
        let node_ref = node.as_node_ref();

        let owned_json = serde_json::to_value(&node).unwrap();
        let ref_json = serde_json::to_value(&node_ref).unwrap();
        assert_eq!(owned_json, ref_json);
    }

    #[test]
    fn nested_nodes_serialize_same() {
        let child = Node::new(Cow::Borrowed("item"), Attrs::new(), None);
        let parent = Node::new(
            Cow::Borrowed("list"),
            Attrs::new(),
            Some(NodeContent::Nodes(vec![child])),
        );
        let parent_ref = parent.as_node_ref();

        assert_eq!(
            serde_json::to_value(&parent).unwrap(),
            serde_json::to_value(&parent_ref).unwrap(),
        );
    }

    #[test]
    fn bytes_content_serializes_same() {
        let node = Node::new(
            Cow::Borrowed("iq"),
            Attrs(vec![(Cow::Borrowed("id"), NodeValue::String("1".into()))]),
            Some(NodeContent::Bytes(vec![0xDE, 0xAD])),
        );
        let node_ref = node.as_node_ref();

        let owned_json = serde_json::to_value(&node).unwrap();
        let ref_json = serde_json::to_value(&node_ref).unwrap();
        assert_eq!(owned_json, ref_json);
    }

    #[test]
    fn value_ref_matches_node_value() {
        let string_val = NodeValue::String("hello".into());
        let string_ref = ValueRef::String(NodeStr::Borrowed("hello"));
        assert_eq!(
            serde_json::to_value(&string_val).unwrap(),
            serde_json::to_value(&string_ref).unwrap(),
        );

        let jid = Jid {
            user: "5550199999".into(),
            server: Server::Group,
            agent: 1,
            device: 2,
            integrator: 3,
        };
        let jid_val = NodeValue::Jid(jid.clone());
        let jid_ref_val = ValueRef::Jid(JidRef {
            user: NodeStr::Borrowed("5550199999"),
            server: Server::Group,
            agent: 1,
            device: 2,
            integrator: 3,
        });
        assert_eq!(
            serde_json::to_value(&jid_val).unwrap(),
            serde_json::to_value(&jid_ref_val).unwrap(),
        );
    }

    #[test]
    fn owned_node_ref_serializes_same_as_owned() {
        let node = Node::new(
            Cow::Borrowed("iq"),
            Attrs(vec![(Cow::Borrowed("id"), NodeValue::String("abc".into()))]),
            Some(NodeContent::String("payload".into())),
        );

        let bytes = crate::marshal::marshal(&node).unwrap();
        // marshal writes a leading format byte that unmarshal_ref doesn't expect
        let owned_ref = OwnedNodeRef::new(Bytes::from(bytes[1..].to_vec())).unwrap();

        let from_ref = serde_json::to_value(&owned_ref).unwrap();
        let from_owned = serde_json::to_value(owned_ref.to_owned_node()).unwrap();
        assert_eq!(from_ref, from_owned);
    }
}
