use anyhow::Result;
use wacore_binary::node::Node;

/// Represents a type that maps to a WhatsApp Protocol node.
pub trait ProtocolNode: Sized {
    /// The XML tag name (e.g., "create", "iq", "participant").
    fn tag(&self) -> &'static str;

    /// Convert the struct into a protocol `Node`.
    fn into_node(self) -> Node;

    /// Parse a protocol `Node` into the struct.
    fn try_from_node(node: &Node) -> Result<Self>;
}

/// Macro for defining simple protocol nodes with only attributes (no children).
///
/// This macro generates a struct with the specified fields as attributes,
/// and implements the `ProtocolNode` trait for it.
///
/// # Example
///
/// ```ignore
/// define_simple_node! {
///     /// A query request node.
///     /// Wire format: `<query request="interactive"/>`
///     pub struct QueryRequest("query") {
///         /// The request type attribute.
///         #[attr("request")]
///         pub request_type: String = "interactive",
///     }
/// }
/// ```
///
/// This generates:
/// - A struct `QueryRequest` with field `request_type`
/// - `ProtocolNode` implementation with tag "query"
/// - `into_node()` that creates `<query request="..."/>`
/// - `try_from_node()` that parses the node
#[macro_export]
macro_rules! define_simple_node {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident($tag:literal) {
            $(
                $(#[$field_meta:meta])*
                #[attr($attr_name:literal)]
                $field_vis:vis $field:ident : $field_type:ty $(= $default:expr)?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        $vis struct $name {
            $(
                $(#[$field_meta])*
                $field_vis $field: $field_type,
            )*
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    $(
                        $field: $crate::define_simple_node!(@default $($default)?),
                    )*
                }
            }
        }

        impl $crate::protocol::ProtocolNode for $name {
            fn tag(&self) -> &'static str {
                $tag
            }

            fn into_node(self) -> wacore_binary::node::Node {
                wacore_binary::builder::NodeBuilder::new($tag)
                    $(.attr($attr_name, self.$field.to_string()))*
                    .build()
            }

            fn try_from_node(node: &wacore_binary::node::Node) -> anyhow::Result<Self> {
                if node.tag != $tag {
                    return Err(anyhow::anyhow!("expected <{}>, got <{}>", $tag, node.tag));
                }
                Ok(Self {
                    $(
                        $field: node.attrs().optional_string($attr_name)
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| $crate::define_simple_node!(@default $($default)?)),
                    )*
                })
            }
        }
    };

    // Helper to handle default values
    (@default $default:expr) => { $default.to_string() };
    (@default) => { String::new() };
}

/// Macro for defining an empty protocol node (tag only, no attributes or children).
///
/// # Example
///
/// ```ignore
/// define_empty_node!(
///     /// An empty participants request node.
///     /// Wire format: `<participants/>`
///     pub struct ParticipantsRequest("participants")
/// );
/// ```
#[macro_export]
macro_rules! define_empty_node {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident($tag:literal)
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        $vis struct $name;

        impl $crate::protocol::ProtocolNode for $name {
            fn tag(&self) -> &'static str {
                $tag
            }

            fn into_node(self) -> wacore_binary::node::Node {
                wacore_binary::builder::NodeBuilder::new($tag).build()
            }

            fn try_from_node(node: &wacore_binary::node::Node) -> anyhow::Result<Self> {
                if node.tag != $tag {
                    return Err(anyhow::anyhow!("expected <{}>, got <{}>", $tag, node.tag));
                }
                Ok(Self)
            }
        }
    };
}
