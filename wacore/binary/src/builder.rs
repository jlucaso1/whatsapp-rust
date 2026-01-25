use crate::jid::Jid;
use crate::node::{Attrs, Node, NodeContent, NodeValue};

#[derive(Debug, Default)]
pub struct NodeBuilder {
    tag: String,
    attrs: Attrs,
    content: Option<NodeContent>,
}

impl NodeBuilder {
    pub fn new(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            ..Default::default()
        }
    }

    pub fn attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attrs.insert(key.into(), value.into());
        self
    }

    /// Add a JID attribute directly without stringifying.
    /// This is more efficient than `attr(key, jid.to_string())`.
    pub fn jid_attr(mut self, key: impl Into<String>, jid: Jid) -> Self {
        self.attrs.insert(key.into(), NodeValue::Jid(jid));
        self
    }

    pub fn attrs<I, K, V>(mut self, attrs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<NodeValue>,
    {
        for (key, value) in attrs.into_iter() {
            self.attrs.insert(key.into(), value.into());
        }
        self
    }

    pub fn children(mut self, children: impl IntoIterator<Item = Node>) -> Self {
        self.content = Some(NodeContent::Nodes(children.into_iter().collect()));
        self
    }

    pub fn bytes(mut self, bytes: impl Into<Vec<u8>>) -> Self {
        self.content = Some(NodeContent::Bytes(bytes.into()));
        self
    }

    pub fn string_content(mut self, s: impl Into<String>) -> Self {
        self.content = Some(NodeContent::String(s.into()));
        self
    }

    pub fn build(self) -> Node {
        Node {
            tag: self.tag,
            attrs: self.attrs,
            content: self.content,
        }
    }

    pub fn apply_content(mut self, content: Option<NodeContent>) -> Self {
        self.content = content;
        self
    }
}
