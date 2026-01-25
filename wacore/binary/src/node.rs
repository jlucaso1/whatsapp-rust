use crate::attrs::{AttrParser, AttrParserRef};
use crate::jid::{Jid, JidRef};
use std::borrow::Cow;

/// An owned attribute value that can be either a string or a structured JID.
/// This avoids string allocation for JID attributes by storing the JID directly,
/// eliminating format/parse overhead when routing logic needs the JID.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub enum NodeValue {
    String(String),
    Jid(Jid),
}

impl Default for NodeValue {
    fn default() -> Self {
        NodeValue::String(String::new())
    }
}

impl NodeValue {
    /// Get the value as a string slice, if it's a string variant.
    #[inline]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            NodeValue::String(s) => Some(s.as_ref()),
            NodeValue::Jid(_) => None,
        }
    }

    /// Get the value as a Jid reference, if it's a JID variant.
    #[inline]
    pub fn as_jid(&self) -> Option<&Jid> {
        match self {
            NodeValue::Jid(j) => Some(j),
            NodeValue::String(_) => None,
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

    /// Convert to a string, formatting the JID if necessary.
    #[inline]
    pub fn to_string_value(&self) -> String {
        match self {
            NodeValue::String(s) => s.clone(),
            NodeValue::Jid(j) => j.to_string(),
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
            // For JID, format and compare. This is rare since JIDs are typically
            // accessed via optional_jid() or to_jid(), not string comparison.
            NodeValue::Jid(j) => j.to_string() == other,
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
        NodeValue::String(s)
    }
}

impl From<&str> for NodeValue {
    #[inline]
    fn from(s: &str) -> Self {
        NodeValue::String(s.to_string())
    }
}

impl From<Jid> for NodeValue {
    #[inline]
    fn from(jid: Jid) -> Self {
        NodeValue::Jid(jid)
    }
}

/// A collection of node attributes stored as key-value pairs.
/// Uses a Vec internally for better cache locality with small attribute counts (typically 3-6).
/// Values can be either strings or JIDs, avoiding stringification overhead for JID attributes.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Attrs(pub Vec<(String, NodeValue)>);

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
    pub fn insert(&mut self, key: String, value: impl Into<NodeValue>) {
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
    pub fn iter(&self) -> impl Iterator<Item = (&String, &NodeValue)> {
        self.0.iter().map(|(k, v)| (k, v))
    }

    /// Push a key-value pair without checking for duplicates.
    /// Use this when building from a known-unique source (e.g., decoding).
    #[inline]
    pub fn push(&mut self, key: String, value: impl Into<NodeValue>) {
        self.0.push((key, value.into()));
    }

    /// Push a NodeValue directly without conversion.
    /// Slightly more efficient when you already have a NodeValue.
    #[inline]
    pub fn push_value(&mut self, key: String, value: NodeValue) {
        self.0.push((key, value));
    }

    /// Iterate over keys only.
    #[inline]
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.0.iter().map(|(k, _)| k)
    }
}

/// Owned iterator implementation (consuming).
impl IntoIterator for Attrs {
    type Item = (String, NodeValue);
    type IntoIter = std::vec::IntoIter<(String, NodeValue)>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Borrowed iterator implementation.
impl<'a> IntoIterator for &'a Attrs {
    type Item = (&'a String, &'a NodeValue);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'a, (String, NodeValue)>,
        fn(&'a (String, NodeValue)) -> (&'a String, &'a NodeValue),
    >;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter().map(|(k, v)| (k, v))
    }
}

impl FromIterator<(String, NodeValue)> for Attrs {
    fn from_iter<I: IntoIterator<Item = (String, NodeValue)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}
pub type AttrsRef<'a> = Vec<(Cow<'a, str>, ValueRef<'a>)>;

/// A decoded attribute value that can be either a string or a structured JID.
/// This avoids string allocation when decoding JID tokens - the JidRef is returned
/// directly and only converted to a string when actually needed.
#[derive(Debug, Clone, PartialEq)]
pub enum ValueRef<'a> {
    String(Cow<'a, str>),
    Jid(JidRef<'a>),
}

impl<'a> ValueRef<'a> {
    /// Get the value as a string slice, if it's a string variant.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ValueRef::String(s) => Some(s.as_ref()),
            ValueRef::Jid(_) => None,
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

    /// Convert to a string, formatting the JID if necessary.
    /// Returns a Cow to avoid allocation when the value is already a string.
    pub fn to_string_cow(&self) -> Cow<'a, str> {
        match self {
            ValueRef::String(s) => s.clone(),
            ValueRef::Jid(j) => Cow::Owned(j.to_string()),
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
    String(String),
    Nodes(Vec<Node>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum NodeContentRef<'a> {
    Bytes(Cow<'a, [u8]>),
    String(Cow<'a, str>),
    Nodes(Box<NodeVec<'a>>),
}

impl NodeContent {
    /// Convert an owned NodeContent to a borrowed NodeContentRef.
    pub fn as_content_ref(&self) -> NodeContentRef<'_> {
        match self {
            NodeContent::Bytes(b) => NodeContentRef::Bytes(Cow::Borrowed(b)),
            NodeContent::String(s) => NodeContentRef::String(Cow::Borrowed(s)),
            NodeContent::Nodes(nodes) => {
                NodeContentRef::Nodes(Box::new(nodes.iter().map(|n| n.as_node_ref()).collect()))
            }
        }
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Node {
    pub tag: String,
    pub attrs: Attrs,
    pub content: Option<NodeContent>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NodeRef<'a> {
    pub tag: Cow<'a, str>,
    pub attrs: AttrsRef<'a>,
    pub content: Option<Box<NodeContentRef<'a>>>,
}

impl Node {
    pub fn new(tag: &str, attrs: Attrs, content: Option<NodeContent>) -> Self {
        Self {
            tag: tag.to_string(),
            attrs,
            content,
        }
    }

    /// Convert an owned Node to a borrowed NodeRef.
    /// The returned NodeRef borrows from self.
    pub fn as_node_ref(&self) -> NodeRef<'_> {
        NodeRef {
            tag: Cow::Borrowed(&self.tag),
            attrs: self
                .attrs
                .iter()
                .map(|(k, v)| {
                    let value_ref = match v {
                        NodeValue::String(s) => ValueRef::String(Cow::Borrowed(s.as_str())),
                        NodeValue::Jid(j) => ValueRef::Jid(JidRef {
                            user: Cow::Borrowed(&j.user),
                            server: Cow::Borrowed(&j.server),
                            agent: j.agent,
                            device: j.device,
                            integrator: j.integrator,
                        }),
                    };
                    (Cow::Borrowed(k.as_str()), value_ref)
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
}

impl<'a> NodeRef<'a> {
    pub fn new(
        tag: Cow<'a, str>,
        attrs: AttrsRef<'a>,
        content: Option<NodeContentRef<'a>>,
    ) -> Self {
        Self {
            tag,
            attrs,
            content: content.map(Box::new),
        }
    }

    pub fn attr_parser(&'a self) -> AttrParserRef<'a> {
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

    pub fn attrs_iter(&self) -> impl Iterator<Item = (&Cow<'a, str>, &ValueRef<'a>)> {
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

    pub fn to_owned(&self) -> Node {
        Node {
            tag: self.tag.to_string(),
            attrs: self
                .attrs
                .iter()
                .map(|(k, v)| {
                    let value = match v {
                        ValueRef::String(s) => NodeValue::String(s.to_string()),
                        ValueRef::Jid(j) => NodeValue::Jid(j.to_owned()),
                    };
                    (k.to_string(), value)
                })
                .collect::<Attrs>(),
            content: self.content.as_deref().map(|c| match c {
                NodeContentRef::Bytes(b) => NodeContent::Bytes(b.to_vec()),
                NodeContentRef::String(s) => NodeContent::String(s.to_string()),
                NodeContentRef::Nodes(nodes) => {
                    NodeContent::Nodes(nodes.iter().map(|n| n.to_owned()).collect())
                }
            }),
        }
    }
}
