# WhatsApp-Rust Copilot Instructions

You are an expert Rust developer specializing in asynchronous networking, cryptography, and reverse-engineered protocols. Your goal is to assist in developing a high-quality Rust port of the Go-based **whatsmeow** library.

---

## 1. Architecture Overview

The project is split into three main crates:

- **wacore**
  A platform-agnostic library containing core logic for the WhatsApp binary protocol, cryptography primitives, IQ protocol types, and state management traits.
  It has **no runtime dependencies** on Tokio or specific databases.

- **waproto**
  Houses the Protocol Buffers definitions (`whatsapp.proto`). It contains a `build.rs` script that uses **prost** to compile these definitions into Rust structs.

- **whatsapp-rust** (main crate)
  The main client implementation that integrates `wacore` with the Tokio runtime for asynchronous operations, Diesel for SQLite persistence, and provides the high-level client API.

### Key Components

- **Client** (`src/client.rs`): Orchestrates the connection lifecycle, event bus, and high-level operations.
- **PersistenceManager** (`src/store/persistence_manager.rs`): Manages all state.
- **Signal Protocol** (`wacore/libsignal/` & `src/store/signal*.rs`): E2E encryption via our Signal Protocol implementation.
- **Socket & Handshake** (`src/socket/`, `src/handshake.rs`): Handles WebSocket connection and Noise Protocol handshake.

---

## 2. Current Project State & Focus

### Stable Features

- QR code pairing and persistent sessions.
- Connection management and automatic reconnection.
- End-to-End encrypted one-on-one messaging (send/receive).
- End-to-End encrypted group messaging (send/receive).
- Media uploads and downloads (images, videos, documents, etc.), including all necessary encryption and decryption logic.

---

## 3. Critical Patterns & Conventions

- **State Management is Paramount**

  - Never modify Device state directly.
  - Use `DeviceCommand` + `PersistenceManager::process_command()`.
  - For read-only, use `PersistenceManager::get_device_snapshot()`.

- **Asynchronous Code**

  - All I/O uses Tokio. Be mindful of race conditions.
  - Use `Client::chat_locks` to serialize per-chat operations.
  - **All blocking I/O (like `ureq` calls) and heavy CPU-bound tasks (like media encryption) MUST be wrapped in `tokio::task::spawn_blocking` to avoid stalling the async runtime.**

- **Media Handling**

  - Media operations are handled in `src/download.rs` and `src/upload.rs`.
  - The `Downloadable` trait in `wacore/src/download.rs` provides a generic interface for any message type that contains downloadable media.
  - The `MediaConn` struct (`src/mediaconn.rs`) is used to get the current media servers and auth tokens. Always refresh it if it's expired.

- **Error Handling**

  - Use `thiserror` for custom errors (`SocketError`, etc.).
  - Use `anyhow::Error` for functions with multiple failure modes.
  - Avoid `.unwrap()` and `.expect()` outside of tests and unrecoverable logic paths.

- **Comments**
  - Keep comments concise and actionable.
  - Avoid narrating obvious code; prefer short summaries, invariants, or non-obvious behavior.

- **Protocol Implementation**
  - When in doubt, refer to the **whatsmeow** Go library as the source of truth.

---

## 4. Key Files for Understanding

- `src/client.rs`: Central hub of the client.
- `src/store/persistence_manager.rs`: Gatekeeper of all state changes.
- `src/message.rs`: Incoming message decryption pipeline.
- `src/send.rs`: Outgoing message encryption pipeline.
- `src/download.rs`: Media download logic.
- `src/upload.rs`: Media upload logic.
- `src/mediaconn.rs`: Media server connection management.
- `src/features/`: High-level feature APIs (groups, blocking, etc.).
- `wacore/src/iq/`: Type-safe IQ protocol types and specs.
- `waproto/src/whatsapp.proto`: Source of all message structures.
- `docs/captured-js/`: Captured WhatsApp Web JavaScript for reverse engineering.

---

## 5. Feature Implementation Philosophy (WhatsApp Web–based)

When adding a new feature, follow a repeatable flow that mirrors WhatsApp Web behavior while staying aligned with the project’s architecture:

1. **Identify the wire format first**
   - Capture or locate the WhatsApp Web request/response for the feature.
   - Extract the exact stanza structure: tags, attributes, and children.
   - Treat this as the ground truth for what must be sent and parsed.

2. **Map the feature to the right layer**
   - **wacore**: protocol logic, state traits, cryptographic helpers, and data models that must be platform-agnostic.
   - **whatsapp-rust**: runtime orchestration, storage integration, and user-facing API.
   - **waproto**: protobuf structures only (avoid feature logic here).

3. **Build minimal primitives before high-level APIs**
   - Start with the smallest IQ/message builder that can successfully round-trip.
   - Parse and validate the response path before adding options or convenience methods.

4. **Keep state changes behind the PersistenceManager**
   - If the feature touches device or chat state, use `DeviceCommand` and `PersistenceManager::process_command()`.
   - For read access, use `get_device_snapshot()`.

5. **Confirm concurrency requirements**
   - Network I/O stays async.
   - Blocking or heavy CPU work goes into `tokio::task::spawn_blocking`.
   - Use `Client::chat_locks` to serialize per-chat operations when needed.

6. **Add ergonomic API last**
   - Once the protocol is stable, add ergonomic Rust builders, enums, and result types.
   - Expose them via `src/features/mod.rs`.

7. **Test and verify**
   - Run `cargo fmt`, `cargo clippy --all-targets`, and `cargo test --all`.
   - Use logging to compare with WhatsApp Web traffic where applicable.

### Quick Structure Guide

- **Protocol entry points**: `src/send.rs`, `src/message.rs`, `src/socket/`, `src/handshake.rs`
- **Feature modules**: `src/features/`
- **State + storage**: `src/store/` + `PersistenceManager`
- **Core protocol & crypto**: `wacore/`
- **Protobufs**: `waproto/`

---

## 6. Type-Safe Protocol Node Architecture

All protocol stanza builders should use the declarative, type-safe pattern defined in `wacore/src/iq/`. This architecture provides compile-time safety, validation, and clear separation between request building and response parsing.

### Core Traits

#### `ProtocolNode` (`wacore/src/protocol.rs`)

Maps Rust structs to WhatsApp protocol nodes:

```rust
pub trait ProtocolNode: Sized {
    fn tag(&self) -> &'static str;
    fn into_node(self) -> Node;
    fn try_from_node(node: &Node) -> Result<Self>;
}
```

#### `IqSpec` (`wacore/src/iq/spec.rs`)

Pairs IQ requests with their typed responses:

```rust
pub trait IqSpec {
    type Response;
    fn build_iq(&self) -> InfoQuery<'static>;
    fn parse_response(&self, response: &Node) -> Result<Self::Response>;
}
```

### Implementation Pattern

1. **Define request struct with `ProtocolNode`**:

```rust
#[derive(Debug, Clone)]
pub struct GroupQueryRequest {
    pub request_type: String,
}

impl ProtocolNode for GroupQueryRequest {
    fn tag(&self) -> &'static str { "query" }
    fn into_node(self) -> Node {
        NodeBuilder::new("query")
            .attr("request", &self.request_type)
            .build()
    }
    fn try_from_node(node: &Node) -> Result<Self> { /* ... */ }
}
```

2. **Define response struct with `ProtocolNode`**:

```rust
pub struct GroupInfoResponse {
    pub id: Jid,
    pub subject: GroupSubject,
    pub addressing_mode: AddressingMode,
    pub participants: Vec<GroupParticipantResponse>,
}

impl ProtocolNode for GroupInfoResponse {
    fn tag(&self) -> &'static str { "group" }
    fn try_from_node(node: &Node) -> Result<Self> { /* parse from XML */ }
    fn into_node(self) -> Node { /* ... */ }
}
```

3. **Create IqSpec implementation**:

```rust
pub struct GroupQueryIq {
    group_jid: Jid,
}

impl GroupQueryIq {
    pub fn new(group_jid: &Jid) -> Self {
        Self { group_jid: group_jid.clone() }
    }
}

impl IqSpec for GroupQueryIq {
    type Response = GroupInfoResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::get(
            GROUP_IQ_NAMESPACE,
            self.group_jid.clone(),
            Some(NodeContent::Nodes(vec![
                GroupQueryRequest::default().into_node()
            ])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response> {
        GroupInfoResponse::try_from_node(response)
    }
}
```

4. **Use in feature code** (`src/features/`):

```rust
// Use client.execute() for simplified IQ handling
let group_response = self.client.execute(GroupQueryIq::new(&jid)).await?;
```

### Validated Newtypes

Use newtypes to enforce protocol constraints at compile time:

```rust
/// Group subject with WhatsApp's 100 character limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSubject(String);

impl GroupSubject {
    pub fn new(subject: impl Into<String>) -> Result<Self, anyhow::Error> {
        let s = subject.into();
        if s.len() > GROUP_SUBJECT_MAX_LENGTH {
            return Err(anyhow!("subject exceeds {} chars", GROUP_SUBJECT_MAX_LENGTH));
        }
        Ok(Self(s))
    }
}
```

Constants from WhatsApp Web A/B props (`wacore/src/iq/groups.rs`):
- `GROUP_SUBJECT_MAX_LENGTH`: 100 characters
- `GROUP_DESCRIPTION_MAX_LENGTH`: 2048 characters
- `GROUP_SIZE_LIMIT`: 257 participants

### Strongly Typed Enums

Replace stringly-typed attributes with enums using the `StringEnum` derive macro:

```rust
use wacore::StringEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, StringEnum)]
pub enum MemberAddMode {
    #[str = "admin_add"]
    AdminAdd,
    #[str = "all_member_add"]
    AllMemberAdd,
}

// Automatically generates:
// - as_str() -> &'static str
// - Display impl
// - TryFrom<&str> impl
// - Default impl (first variant, or use #[string_default])
```

For enums where the default should not be the first variant:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, StringEnum)]
pub enum MembershipApprovalMode {
    #[string_default]  // Mark this as default
    #[str = "off"]
    Off,
    #[str = "on"]
    On,
}
```

### Derive Macros (Recommended)

For simple nodes and enums, use the derive macros from `wacore-derive` (re-exported via `wacore`):

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

**Benefits over manual implementations:**
- Better IDE support (autocomplete, go-to-definition)
- Clearer error messages from the compiler
- Standard Rust derive pattern
- Less boilerplate code

### Declarative Macros (Legacy)

> **Note**: Prefer derive macros (`EmptyNode`, `ProtocolNode`, `StringEnum`) for new code.

For quick one-off definitions, declarative macros in `wacore/src/protocol.rs` are also available:

```rust
// Empty node
define_empty_node!(
    /// Wire format: `<participants/>`
    pub struct ParticipantsRequest("participants")
);

// Node with attributes
define_simple_node! {
    /// Wire format: `<query request="interactive"/>`
    pub struct QueryRequest("query") {
        #[attr("request")]
        pub request_type: String = "interactive",
    }
}
```

### Generic IQ Executor

Use `Client::execute()` for simplified IQ request/response handling:

```rust
// Before: manual build + send + parse
let spec = GroupQueryIq::new(&jid);
let resp_node = client.send_iq(spec.build_iq()).await?;
let response = spec.parse_response(&resp_node)?;

// After: single execute() call
let response = client.execute(GroupQueryIq::new(&jid)).await?;
```

**API Design Note**: IqSpec constructors should take `&Jid` instead of `Jid` to avoid forcing callers to clone. The clone happens inside the constructor:

```rust
impl UpdateBlocklistSpec {
    pub fn block(jid: &Jid) -> Self {
        Self { request: BlocklistItemRequest::block(jid) }
    }
}

// Caller doesn't need to clone
client.execute(UpdateBlocklistSpec::block(&jid)).await?;
```

### File Organization

```
wacore/src/iq/
├── mod.rs          # Re-exports
├── spec.rs         # IqSpec trait definition
├── node.rs         # Helper functions (required_child, required_attr, optional_attr)
├── groups.rs       # Group types, enums, newtypes, ProtocolNode & IqSpec impls
└── blocklist.rs    # Blocklist types, ProtocolNode & IqSpec impls
```

Each feature file (e.g., `groups.rs`, `blocklist.rs`) contains:
- Constants (namespaces, limits)
- Enums with `StringEnum` derive
- Request/Response structs with `ProtocolNode` impl
- `IqSpec` implementations pairing requests with responses
- Unit tests

### Node Parsing Helpers

Use helper functions from `wacore/src/iq/node.rs` for consistent parsing:

```rust
use crate::iq::node::{required_child, required_attr, optional_attr, optional_jid};

fn try_from_node(node: &Node) -> Result<Self> {
    let id = required_attr(node, "id")?;           // Error if missing
    let name = optional_attr(node, "name");         // Returns Option<&str>
    let jid = optional_jid(node, "jid")?;           // Returns Result<Option<Jid>>
    let child = required_child(node, "group")?;     // Error if missing
    // ...
}
```

### Benefits

| Aspect | Before (Imperative) | After (Type-Safe) |
|--------|---------------------|-------------------|
| Attribute names | Raw strings, typo-prone | Compile-time checked |
| Validation | Runtime, easy to forget | Enforced via newtypes |
| Request/Response | Disconnected functions | Paired via `IqSpec` |
| Wire format | Scattered in builders | Documented on types |
| Refactoring | Find-and-replace | Compiler-assisted |

---

## 7. Reverse Engineering Reference

The `docs/captured-js/` directory contains captured WhatsApp Web JavaScript files. Use these to verify protocol implementations:

```bash
# Search for blocklist-related code
grep -r "blocklist" docs/captured-js/*.js

# Find specific IQ namespace usage
grep -r "xmlns.*blocklist\|xmlns.*w:g2" docs/captured-js/*.js
```

**Key patterns to look for:**
- `xmlns: "namespace"` - IQ namespaces
- `action: "value"` - Action attributes
- `smax("tag", { attrs })` - Node construction
- Module names like `WASmaxOutBlocklists*` - Outgoing request builders
- Module names like `WASmaxInBlocklists*` - Incoming response parsers

---

## 8. Final Implementation Checks

Before finalizing a feature/fix, always run:

- **Format**: `cargo fmt`
- **Lint**: `cargo clippy --all-targets`
- **Test**: `cargo test --all`
- **Review**: `coderabbit review --prompt-only` (if available)

---

## 9. Debugging Tools

### evcxr - Rust REPL

For interactive debugging and quick code exploration, use `evcxr`:

```bash
# Install (use binstall for faster installation)
cargo binstall evcxr_repl -y

# Run from project root
evcxr
```

**Use cases:**

- **Decode binary protocol data**: Inspect nibble-encoded values, hex strings, or protocol buffers
- **Test encoding/decoding logic**: Quickly verify transformations without full compile cycles
- **Explore data structures**: Inspect how structs serialize/deserialize
- **Prototype algorithms**: Test Signal protocol operations or crypto functions

### Using Project Crates in evcxr

You can import local crates using the `:dep` command with relative paths. Note that package names use hyphens, but Rust imports use underscores:

```rust
// Add dependencies (run from project root)
:dep wacore-binary = { path = "wacore/binary" }
:dep hex = "0.4"

// Import modules
use wacore_binary::jid::Jid;
use wacore_binary::marshal::{marshal, unmarshal_ref};
use wacore_binary::builder::NodeBuilder;
```

**Important**: evcxr processes each line independently. For multi-line code with local variables, wrap in a block:

```rust
{
    let jid: Jid = "100000000000001.1:75@lid".parse().unwrap();
    println!("User: {}, Device: {}, Is LID: {}", jid.user, jid.device, jid.is_lid());
}
```

### Example: Decoding Binary Protocol Data

```rust
:dep wacore-binary = { path = "wacore/binary" }
:dep hex = "0.4"
use wacore_binary::marshal::unmarshal_ref;

{
    let data = hex::decode("f80f4c1a...").unwrap();
    let node = unmarshal_ref(&data).unwrap();
    println!("Tag: {}", node.tag);
    for (k, v) in node.attrs.iter() { println!("  {}: {}", k, v); }
}
```

### Example: Building and Marshaling Nodes

```rust
:dep wacore-binary = { path = "wacore/binary" }
use wacore_binary::builder::NodeBuilder;
use wacore_binary::marshal::marshal;

{
    let node = NodeBuilder::new("message")
        .attr("type", "text")
        .attr("to", "15551234567@s.whatsapp.net")
        .build();
    println!("{:?}", node);
    let bytes = marshal(&node).unwrap();
    println!("Marshaled: {:02x?}", bytes);
}
```

### Example: Decoding Nibble-Encoded Data

WhatsApp binary protocol uses nibble encoding for numeric strings. Each byte contains two digits (0-9), with 0xF as terminator for odd-length strings:

```rust
fn decode_nibbles(hex: &str) -> String {
    let mut result = String::new();
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i+2], 16).unwrap();
        let high = byte >> 4;
        let low = byte & 0x0f;
        if high < 10 { result.push(('0' as u8 + high) as char); }
        if low < 10 { result.push(('0' as u8 + low) as char); }
        else if low == 0x0f { break; } // terminator
    }
    result
}

fn encode_nibbles(s: &str) -> String {
    let mut result = String::new();
    let bytes: Vec<u8> = s.bytes().map(|b| b - b'0').collect();
    for chunk in bytes.chunks(2) {
        let high = chunk[0];
        let low = if chunk.len() > 1 { chunk[1] } else { 0x0f };
        result.push_str(&format!("{:x}{:x}", high, low));
    }
    result
}

decode_nibbles("100000000000001f") // -> "100000000000001"
encode_nibbles("100000000000001")  // -> "100000000000001f"
```
