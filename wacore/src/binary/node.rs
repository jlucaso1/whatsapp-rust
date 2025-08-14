use crate::binary::attrs::AttrParser;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::collections::HashMap;

pub type Attrs = HashMap<String, String>;
pub type AttrsRef<'a> = HashMap<Cow<'a, str>, Cow<'a, str>>;

// SmallVec with inline storage for 4 nodes - most nodes have ≤4 children
pub type NodeVec<'a> = SmallVec<[NodeRef<'a>; 4]>;

#[derive(Debug, Clone, PartialEq)]
pub enum NodeContent {
    Bytes(Vec<u8>),
    Nodes(Vec<Node>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum NodeContentRef<'a> {
    Bytes(Cow<'a, [u8]>),
    Nodes(NodeVec<'a>), // Use SmallVec for stack allocation optimization
}

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

    /// Returns a slice of direct children that have the specified tag.
    pub fn get_children_by_tag(&self, tag: &str) -> Vec<&Node> {
        if let Some(children) = self.children() {
            children.iter().filter(|c| c.tag == tag).collect()
        } else {
            Vec::new()
        }
    }

    /// Finds the first direct child with the given tag and returns it.
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

    pub fn children(&self) -> Option<&[NodeRef<'a>]> {
        match self.content.as_deref() {
            Some(NodeContentRef::Nodes(nodes)) => Some(nodes.as_slice()),
            _ => None,
        }
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

    /// Returns a slice of direct children that have the specified tag.
    pub fn get_children_by_tag(&self, tag: &str) -> Vec<&NodeRef<'a>> {
        if let Some(children) = self.children() {
            children.iter().filter(|c| c.tag == tag).collect()
        } else {
            Vec::new()
        }
    }

    /// Finds the first direct child with the given tag and returns it.
    pub fn get_optional_child(&self, tag: &str) -> Option<&NodeRef<'a>> {
        self.children()
            .and_then(|nodes| nodes.iter().find(|node| node.tag == tag))
    }

    /// Convert to owned Node
    pub fn to_owned(&self) -> Node {
        Node {
            tag: self.tag.to_string(),
            attrs: self
                .attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            content: self.content.as_deref().map(|c| match c {
                NodeContentRef::Bytes(b) => NodeContent::Bytes(b.to_vec()),
                NodeContentRef::Nodes(nodes) => {
                    NodeContent::Nodes(nodes.iter().map(|n| n.to_owned()).collect())
                }
            }),
        }
    }
}
