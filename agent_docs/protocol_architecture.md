# Type-Safe Protocol Node Architecture

All protocol stanza builders use the declarative, type-safe pattern defined in `wacore/src/iq/`. This architecture provides compile-time safety, validation, and clear separation between request building and response parsing.

## Core Traits

### `ProtocolNode` (`wacore/src/protocol.rs`)

Maps Rust structs to WhatsApp protocol nodes:

```rust
pub trait ProtocolNode: Sized {
    fn tag(&self) -> &'static str;
    fn into_node(self) -> Node;
    fn try_from_node(node: &Node) -> Result<Self>;
}
```

### `IqSpec` (`wacore/src/iq/spec.rs`)

Pairs IQ requests with their typed responses:

```rust
pub trait IqSpec {
    type Response;
    fn build_iq(&self) -> InfoQuery<'static>;
    fn parse_response(&self, response: &Node) -> Result<Self::Response>;
}
```

## Derive Macros (Recommended)

Use the derive macros from `wacore-derive` (re-exported via `wacore`):

```rust
use wacore::{ProtocolNode, EmptyNode, StringEnum};

// Empty node (tag only)
#[derive(EmptyNode)]
#[protocol(tag = "participants")]
pub struct ParticipantsRequest;

// Node with string attributes
#[derive(ProtocolNode)]
#[protocol(tag = "query")]
pub struct QueryRequest {
    #[attr(name = "request", default = "interactive")]
    pub request_type: String,
}

// Enum with string representations
#[derive(Debug, Clone, Copy, PartialEq, Eq, StringEnum)]
pub enum BlocklistAction {
    #[str = "block"]
    Block,
    #[str = "unblock"]
    Unblock,
}
```

**Available derive macros:**
- `EmptyNode` - For nodes with only a tag (no attributes)
- `ProtocolNode` - For nodes with string attributes
- `StringEnum` - For enums with string representations (generates `as_str()`, `Display`, `TryFrom<&str>`, `Default`)

For enums where the default should not be the first variant, use `#[string_default]`.

### Legacy Declarative Macros

Prefer derive macros for new code. Declarative macros in `wacore/src/protocol.rs` (`define_empty_node!`, `define_simple_node!`) are also available but considered legacy.

## Implementation Pattern

1. Define request struct with `ProtocolNode` (or derive macro)
2. Define response struct with `ProtocolNode`
3. Create `IqSpec` implementation pairing them
4. Use `client.execute(Spec::new(&jid)).await?` in feature code

See `wacore/src/iq/groups.rs` and `wacore/src/iq/blocklist.rs` for complete examples.

## IQ Executor

Use `Client::execute()` for simplified IQ request/response handling:

```rust
// Single call replaces manual build + send + parse
let response = client.execute(GroupQueryIq::new(&jid)).await?;
```

**API Design Note**: IqSpec constructors should take `&Jid` (not `Jid`) to avoid forcing callers to clone.

## Node Parsing Helpers

Use helpers from `wacore/src/iq/node.rs`:

```rust
use crate::iq::node::{required_child, required_attr, optional_attr, optional_jid};

fn try_from_node(node: &Node) -> Result<Self> {
    let id = required_attr(node, "id")?;
    let name = optional_attr(node, "name");
    let jid = optional_jid(node, "jid")?;
    let child = required_child(node, "group")?;
}
```

## Validated Newtypes

Use newtypes to enforce protocol constraints at compile time. See `GroupSubject` in `wacore/src/iq/groups.rs` for examples.

Constants from WhatsApp Web A/B props:
- `GROUP_SUBJECT_MAX_LENGTH`: 100 characters
- `GROUP_DESCRIPTION_MAX_LENGTH`: 2048 characters
- `GROUP_SIZE_LIMIT`: 257 participants

## File Organization

```
wacore/src/iq/
├── mod.rs          # Re-exports
├── spec.rs         # IqSpec trait definition
├── node.rs         # Helper functions
├── groups.rs       # Group types + IqSpec impls
└── blocklist.rs    # Blocklist types + IqSpec impls
```

Each feature file contains: constants, enums (`StringEnum`), request/response structs (`ProtocolNode`), `IqSpec` impls, and unit tests.
