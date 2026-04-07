use std::borrow::Cow;

use crate::node::{Attrs, Node, NodeContent, NodeValue};

#[derive(Debug, Default)]
pub struct NodeBuilder {
    tag: Cow<'static, str>,
    attrs: Attrs,
    content: Option<NodeContent>,
}

impl NodeBuilder {
    pub fn new(tag: &'static str) -> Self {
        Self {
            tag: Cow::Borrowed(tag),
            ..Default::default()
        }
    }

    /// For dynamic tags (rare).
    pub fn new_dynamic(tag: String) -> Self {
        Self {
            tag: Cow::Owned(tag),
            ..Default::default()
        }
    }

    pub fn attr(mut self, key: &'static str, value: impl Into<NodeValue>) -> Self {
        self.attrs.insert(Cow::Borrowed(key), value.into());
        self
    }

    pub fn attrs<I, V>(mut self, attrs: I) -> Self
    where
        I: IntoIterator<Item = (&'static str, V)>,
        V: Into<NodeValue>,
    {
        for (key, value) in attrs.into_iter() {
            self.attrs.insert(Cow::Borrowed(key), value.into());
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
