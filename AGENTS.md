# WhatsApp-Rust Copilot Instructions

You are an expert Rust developer specializing in asynchronous networking, cryptography, and reverse-engineered protocols. Your goal is to assist in developing a high-quality Rust port of the Go-based **whatsmeow** library.

---

## 1. Architecture Overview

The project is split into three main crates:

- **wacore**
  A platform-agnostic library containing the pure, `no_std`-compatible core logic for the WhatsApp binary protocol, cryptography primitives, and state management traits.
  It has **no dependencies** on Tokio or specific databases.

- **waproto**
  Houses the Protocol Buffers definitions (`whatsapp.proto`). It contains a `build.rs` script that uses **prost** to compile these definitions into Rust structs.

- **whatsapp-rust** (main crate)
  The main client implementation that integrates `wacore` with the Tokio runtime for asynchronous operations, Diesel for SQLite persistence, and provides the high-level client API.

### Key Components

- **Client** (`src/client.rs`): Orchestrates the connection lifecycle, event bus, and high-level operations.
- **PersistenceManager** (`src/store/persistence_manager.rs`): Manages all state.
- **Signal Protocol** (`wacore/src/signal/` & `src/store/signal*.rs`): E2E encryption via our Signal Protocol implementation.
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
- `waproto/src/whatsapp.proto`: Source of all message structures.

---

## 5. Code Style & Comments

- **Avoid unnecessary comments**: Code should be self-documenting. Don't add comments that merely restate what the code does.
- **Keep doc comments concise**: Module-level (`//!`) and function-level (`///`) docs should be brief and focused. One-liner preferred.
- **Remove obvious comments**: Comments like `// Clone the value` or `// Return the result` add no value.
- **DRY applies to docs too**: Don't repeat parameter names/types in doc comments - they're already in the signature.
- **Section headers sparingly**: Use `// Section name` comments only for large files with distinct logical sections.

**Good:**
```rust
//! Message bubble component with responsive layout.

pub fn sidebar_width(&self) -> f32 { ... }
```

**Bad:**
```rust
//! Message bubble component for displaying chat messages
//!
//! Renders message bubbles with responsive layout support.
//! This component handles...

/// Get the sidebar width
/// Returns the width of the sidebar in pixels based on the current breakpoint
pub fn sidebar_width(&self) -> f32 { ... }
```

---

## 6. Final Implementation Checks

Before finalizing a feature/fix, always run:

- **Format**: `cargo fmt`
- **Lint**: `cargo clippy --all-targets`
- **Test**: `cargo test --all`

---

## 7. Debugging Tools

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
