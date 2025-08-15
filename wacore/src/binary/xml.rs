use crate::binary::node::{Attrs, Node, NodeContent};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static INDENT_XML: AtomicBool = AtomicBool::new(false);
static MAX_BYTES_TO_PRINT_AS_HEX: AtomicUsize = AtomicUsize::new(128);

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
    let max_bytes = MAX_BYTES_TO_PRINT_AS_HEX.load(Ordering::Relaxed);

    match content {
        Some(NodeContent::Nodes(nodes)) => nodes
            .iter()
            .flat_map(|n| n.to_string().lines().map(String::from).collect::<Vec<_>>())
            .collect(),
        Some(NodeContent::Bytes(bytes)) => {
            if let Some(s) = get_printable_str(bytes) {
                if indent {
                    s.lines().map(String::from).collect()
                } else {
                    vec![s.replace('\n', "\\n")]
                }
            } else if bytes.len() > max_bytes {
                vec![format!("")]
            } else {
                let hex_data = hex::encode(bytes);
                if indent {
                    hex_data
                        .as_bytes()
                        .chunks(80)
                        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                        .collect()
                } else {
                    vec![hex_data]
                }
            }
        }
        None => vec![],
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let indent_xml = INDENT_XML.load(Ordering::Relaxed);
        let attrs = format_attributes(&self.attrs);
        let mut content_lines = format_content_lines(&self.content, indent_xml);

        if content_lines.is_empty() {
            write!(f, "<{}{}/>", self.tag, attrs)
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
                self.tag, attrs, newline, final_content, newline, self.tag
            )
        }
    }
}
