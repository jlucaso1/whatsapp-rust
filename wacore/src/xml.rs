use std::fmt;
use wacore_binary::node::{Attrs, AttrsRef, Node, NodeContent, NodeContentRef, NodeRef};

pub struct DisplayableNode<'a>(pub &'a Node);

pub struct DisplayableNodeRef<'a>(pub &'a NodeRef<'a>);

fn get_printable_str(data: &[u8]) -> Option<&str> {
    let s = std::str::from_utf8(data).ok()?;
    if s.chars().all(|c| !c.is_control()) {
        Some(s)
    } else {
        None
    }
}

fn format_attributes(attrs: &Attrs) -> String {
    if attrs.is_empty() {
        return String::new();
    }
    let mut keys: Vec<_> = attrs.keys().collect();
    keys.sort_unstable();

    let mut result = String::new();
    for key in keys {
        if let Some(value) = attrs.get(key) {
            result.push_str(&format!(" {}=\"{}\"", key, value));
        }
    }
    result
}

fn format_content_lines(content: &Option<NodeContent>, indent: bool) -> Vec<String> {
    match content {
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
        Some(NodeContent::Bytes(bytes)) => {
            if let Some(s) = get_printable_str(bytes) {
                if indent {
                    s.lines().map(String::from).collect()
                } else {
                    vec![s.replace('\n', "\\n")]
                }
            } else {
                vec![format!("<!-- {} bytes -->", bytes.len())]
            }
        }
        Some(NodeContent::String(s)) => {
            if indent {
                s.lines().map(String::from).collect()
            } else {
                vec![s.replace('\n', "\\n")]
            }
        }
        None => vec![],
    }
}

fn format_attributes_ref(attrs: &AttrsRef<'_>) -> String {
    if attrs.is_empty() {
        return String::new();
    }
    let mut result = String::new();
    for (key, value) in attrs.iter() {
        result.push_str(&format!(" {}=\"{}\"", key, value));
    }
    result
}

fn format_content_lines_ref(content: &Option<Box<NodeContentRef<'_>>>, indent: bool) -> Vec<String> {
    match content.as_deref() {
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
        Some(NodeContentRef::Bytes(bytes)) => {
            if let Some(s) = get_printable_str(bytes.as_ref()) {
                if indent {
                    s.lines().map(String::from).collect()
                } else {
                    vec![s.replace('\n', "\\n")]
                }
            } else {
                vec![format!("<!-- {} bytes -->", bytes.len())]
            }
        }
        Some(NodeContentRef::String(s)) => {
            if indent {
                s.lines().map(String::from).collect()
            } else {
                vec![s.replace('\n', "\\n")]
            }
        }
        None => vec![],
    }
}

impl<'a> fmt::Display for DisplayableNode<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let node = self.0;
        let indent_xml = false;
        let attrs = format_attributes(&node.attrs);
        let mut content_lines = format_content_lines(&node.content, indent_xml);

        if content_lines.is_empty() {
            write!(f, "<{}{}/>", node.tag, attrs)
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
                node.tag, attrs, newline, final_content, newline, node.tag
            )
        }
    }
}

impl<'a> fmt::Display for DisplayableNodeRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let node = self.0;
        let indent_xml = false;
        let attrs = format_attributes_ref(&node.attrs);
        let mut content_lines = format_content_lines_ref(&node.content, indent_xml);

        if content_lines.is_empty() {
            write!(f, "<{}{}/>", node.tag, attrs)
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
                node.tag, attrs, newline, final_content, newline, node.tag
            )
        }
    }
}
