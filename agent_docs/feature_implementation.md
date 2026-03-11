# Feature Implementation Guide

When adding a new feature, follow this flow that mirrors WhatsApp Web behavior while staying aligned with the project's architecture.

## Step-by-Step

1. **Identify the wire format first**
   - Capture or locate the WhatsApp Web request/response for the feature
   - Extract the exact stanza structure: tags, attributes, and children
   - Treat this as the ground truth for what must be sent and parsed

2. **Map the feature to the right layer**
   - **wacore**: protocol logic, state traits, cryptographic helpers, data models (platform-agnostic)
   - **whatsapp-rust**: runtime orchestration, storage integration, user-facing API
   - **waproto**: protobuf structures only (no feature logic)

3. **Build minimal primitives before high-level APIs**
   - Start with the smallest IQ/message builder that can successfully round-trip
   - Parse and validate the response path before adding options or convenience

4. **Keep state changes behind the PersistenceManager**
   - Use `DeviceCommand` + `PersistenceManager::process_command()` for mutations
   - Use `get_device_snapshot()` for read access

5. **Confirm concurrency requirements**
   - Network I/O stays async
   - Blocking or heavy CPU work goes into `tokio::task::spawn_blocking`
   - Use `Client::chat_locks` to serialize per-chat operations when needed

6. **Add ergonomic API last**
   - Once the protocol is stable, add Rust builders, enums, and result types
   - Expose via `src/features/mod.rs` and re-export in `src/lib.rs`

7. **Test and verify**
   - Run `cargo fmt`, `cargo clippy --all-targets`, and `cargo test --all`
   - Use logging to compare with WhatsApp Web traffic where applicable

## Protocol Architecture

For implementing `ProtocolNode`, `IqSpec`, derive macros, and node parsing patterns, read `agent_docs/protocol_architecture.md`.

## Reverse Engineering Reference

The `docs/captured-js/` directory contains captured WhatsApp Web JavaScript. Use these to verify protocol implementations:

**Key patterns to look for:**
- `xmlns: "namespace"` - IQ namespaces
- `action: "value"` - Action attributes
- `smax("tag", { attrs })` - Node construction
- Module names like `WASmaxOutBlocklists*` - Outgoing request builders
- Module names like `WASmaxInBlocklists*` - Incoming response parsers

## Quick Structure Guide

- **Protocol entry points**: `src/send.rs`, `src/message.rs`, `src/socket/`, `src/handshake.rs`
- **Feature modules**: `src/features/`
- **State + storage**: `src/store/` + `PersistenceManager`
- **Core protocol & crypto**: `wacore/`
- **Protobufs**: `waproto/`
