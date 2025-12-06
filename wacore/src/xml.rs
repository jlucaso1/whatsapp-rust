use std::fmt::{self, Write as _};
use wacore_binary::node::{Node, NodeContent, NodeContentRef, NodeRef};

pub struct DisplayableNode<'a>(pub &'a Node);

pub struct DisplayableNodeRef<'a, 'b>(pub &'a NodeRef<'b>);

fn get_printable_str(data: &[u8]) -> Option<&str> {
    let s = std::str::from_utf8(data).ok()?;
    if s.chars().all(|c| !c.is_control()) {
        Some(s)
    } else {
        None
    }
}

/// Trait for formatting XML nodes generically.
trait XmlFormattable {
    fn tag(&self) -> &str;
    fn format_attributes(&self, out: &mut String);
    fn format_content_lines(&self, indent: bool) -> Vec<String>;
}

impl XmlFormattable for Node {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn format_attributes(&self, out: &mut String) {
        if self.attrs.is_empty() {
            return;
        }
        let mut keys: Vec<_> = self.attrs.keys().collect();
        keys.sort_unstable();

        for key in keys {
            if let Some(value) = self.attrs.get(key) {
                let _ = write!(out, " {}=\"{}\"", key, value);
            }
        }
    }

    fn format_content_lines(&self, indent: bool) -> Vec<String> {
        match &self.content {
            Some(NodeContent::Nodes(nodes)) => nodes
                .iter()
                .flat_map(|n| {
                    DisplayableNode(n)
                        .to_string()
                        .lines()
                        .map(String::from)
                        .collect::<Vec<_>>()
                })
                .collect(),
            Some(NodeContent::Bytes(bytes)) => format_bytes_content(bytes, indent),
            Some(NodeContent::String(s)) => format_string_content(s, indent),
            None => vec![],
        }
    }
}

impl<'a> XmlFormattable for NodeRef<'a> {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn format_attributes(&self, out: &mut String) {
        if self.attrs.is_empty() {
            return;
        }
        for (key, value) in self.attrs.iter() {
            let _ = write!(out, " {}=\"{}\"", key, value);
        }
    }

    fn format_content_lines(&self, indent: bool) -> Vec<String> {
        match self.content.as_deref() {
            Some(NodeContentRef::Nodes(nodes)) => nodes
                .iter()
                .flat_map(|n| {
                    DisplayableNodeRef(n)
                        .to_string()
                        .lines()
                        .map(String::from)
                        .collect::<Vec<_>>()
                })
                .collect(),
            Some(NodeContentRef::Bytes(bytes)) => format_bytes_content(bytes.as_ref(), indent),
            Some(NodeContentRef::String(s)) => format_string_content(s, indent),
            None => vec![],
        }
    }
}

fn format_bytes_content(bytes: &[u8], indent: bool) -> Vec<String> {
    if let Some(s) = get_printable_str(bytes) {
        format_string_content(s, indent)
    } else {
        vec![format!("<!-- {} bytes -->", bytes.len())]
    }
}

fn format_string_content(s: &str, indent: bool) -> Vec<String> {
    if indent {
        s.lines().map(String::from).collect()
    } else {
        vec![s.replace('\n', "\\n")]
    }
}

fn format_node<T: XmlFormattable>(node: &T, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let indent_xml = false;
    let mut attrs = String::new();
    node.format_attributes(&mut attrs);
    let mut content_lines = node.format_content_lines(indent_xml);

    if content_lines.is_empty() {
        write!(f, "<{}{}/>", node.tag(), attrs)
    } else {
        let newline = "";
        let indent = if indent_xml { "  " } else { "" };

        for line in content_lines.iter_mut() {
            *line = format!("{}{}", indent, line);
        }
        let final_content = content_lines.join(newline);

        write!(
            f,
            "<{}{}>{}{}{}</{}>",
            node.tag(),
            attrs,
            newline,
            final_content,
            newline,
            node.tag()
        )
    }
}

impl fmt::Display for DisplayableNode<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_node(self.0, f)
    }
}

impl fmt::Display for DisplayableNodeRef<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_node(self.0, f)
    }
}
