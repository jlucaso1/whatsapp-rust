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

/// Macro for defining validated string newtypes with a maximum length constraint.
///
/// This generates a newtype wrapper around `String` that validates length on construction.
///
/// # Example
///
/// ```ignore
/// define_validated_string! {
///     /// A validated group subject with 100 character limit.
///     pub struct GroupSubject(max_len = GROUP_SUBJECT_MAX_LENGTH, name = "Group subject");
/// }
/// ```
///
/// This generates:
/// - A tuple struct wrapping `String`
/// - `new(s: impl Into<String>) -> Result<Self>` that validates length
/// - `new_unchecked(s: impl Into<String>) -> Self` for parsing responses
/// - `as_str() -> &str`
/// - `into_string() -> String`
/// - Derives: `Debug, Clone, PartialEq, Eq, Hash`
#[macro_export]
macro_rules! define_validated_string {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident(max_len = $max_len:expr, name = $display_name:literal)
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        $vis struct $name(String);

        impl $name {
            /// Create a new validated string, returning an error if it exceeds the maximum length.
            pub fn new(value: impl Into<String>) -> anyhow::Result<Self> {
                let s = value.into();
                if s.chars().count() > $max_len {
                    return Err(anyhow::anyhow!(
                        "{} exceeds {} characters",
                        $display_name,
                        $max_len
                    ));
                }
                Ok(Self(s))
            }

            /// Create a new string without validation (for parsing responses).
            pub fn new_unchecked(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Get the string as a slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume self and return the inner string.
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}
