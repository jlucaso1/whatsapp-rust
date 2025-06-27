use crate::binary::attrs::AttrParser;
use std::collections::HashMap;

pub type Attrs = HashMap<String, String>;

#[derive(Debug, Clone, PartialEq)]
pub enum NodeContent {
    Bytes(Vec<u8>),
    Nodes(Vec<Node>),
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Node {
    pub tag: String,
    pub attrs: Attrs,
    pub content: Option<NodeContent>,
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

    pub fn attrs(&self) -> AttrParser {
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

// See util.rs for the Display trait implementation (for XML string)
