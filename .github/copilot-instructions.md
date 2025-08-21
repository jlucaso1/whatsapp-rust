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

## 5. Final Implementation Checks

Before finalizing a feature/fix, always run:

- **Format**: `cargo fmt`
- **Lint**: `cargo clippy --all-targets`
- **Test**: `cargo test --all`
