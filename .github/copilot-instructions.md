# WhatsApp-Rust Copilot Instructions

You are an expert Rust developer specializing in asynchronous networking, cryptography, and reverse-engineered protocols. Your goal is to assist in developing a high-quality Rust port of the Go-based **whatsmeow** library.

---

## 1. Architecture Overview

The project is split into three main crates:

- **wacore**
  A platform-agnostic library containing the pure, `no_std`-compatible core logic for the WhatsApp binary protocol, cryptography primitives (via `libsignal-protocol`), and state management traits.
  It has **no dependencies** on Tokio or specific databases.

- **waproto**
  Houses the Protocol Buffers definitions (`whatsapp.proto`).
  It contains a `build.rs` script that uses **prost** to compile these definitions into Rust structs.
  The pre-generated `whatsapp.rs` file is checked into the repository, so developers do not need the `protoc` compiler installed to build the main project.

- **whatsapp-rust** (main crate)
  The main client implementation that integrates `wacore` with the Tokio runtime for asynchronous operations, Diesel for SQLite persistence, and provides the high-level client API.

### Key Components

- **Client** (`src/client.rs`): Orchestrates the connection lifecycle, event bus, and high-level operations.
- **PersistenceManager** (`src/store/persistence_manager.rs`): Manages all state.
  - All state mutations **must** go through this manager via the `DeviceCommand` pattern.
  - Direct modification of the Device state is **forbidden**.
- **Store Layer** (`src/store/`): Abstraction for persistence. Main implementation: `SqliteStore` (via Diesel).
- **Signal Protocol** (`wacore/src/signal/` & `src/store/signal*.rs`): E2E encryption via `libsignal-protocol`.
- **Binary Protocol** (`wacore/src/binary/`): Zero-copy parser (`unmarshal_ref`) and encoder (`marshal`) for WhatsApp’s binary protocol.
- **Socket & Handshake** (`src/socket/`, `src/handshake.rs`): Handles WebSocket connection and Noise Protocol handshake.

---

## 2. Current Project State & Focus

### Stable

- 1-on-1 E2E messaging (send/receive)
- QR code pairing
- Connection management

## 3. Development & Testing Workflow

- **Build**: `cargo build`
- **Test**: `cargo test --all`
- **Format**: `cargo fmt`

### Testing Strategy

- Integration tests live in `tests/`
- Many tests use **captured network data** (`tests/captured_*`) for protocol verification
- When adding features, replicate or extend existing captured-data tests

---

## 4. Critical Patterns & Conventions

- **State Management is Paramount**

  - Never modify Device state directly.
  - Use `DeviceCommand` + `PersistenceManager::process_command()`.
  - For read-only, use `PersistenceManager::get_device_snapshot()`.

- **Asynchronous Code**

  - All I/O uses Tokio.
  - Be mindful of race conditions.
  - Use `Client::chat_locks` to serialize per-chat operations.

- **Error Handling**

  - Use `thiserror` for custom errors (`SocketError`, `DecryptionError`, …).
  - Use `anyhow::Error` for functions with multiple failure modes.
  - Avoid `.unwrap()` and `.expect()` outside tests.

- **Protocol Implementation**
  - When in doubt, refer to the **whatsmeow** Go library as the source of truth.

---

## 5. Pull Request Review Guidelines

When reviewing PRs, act as a **senior developer**:

### Architectural Adherence

- Correct separation of crates (`wacore` vs `whatsapp-rust`)
- State changes **must** go through PersistenceManager + DeviceCommand

### Correctness & Robustness

- Proper error handling (`Result`, no risky `.unwrap()`)
- Async safety:
  - Shared state via `Arc<Mutex<T>>` / `Arc<RwLock<T>>`
  - Correct use of `client.chat_locks` for chat-specific state

### Testing

- Are tests included for new functionality?
- For bug fixes: is there a regression test?
- For protocol changes: can captured data be added?

### Code Style

- Formatted with `cargo fmt`
- Uses idiomatic Rust (iterators, combinators, pattern matching)
- Clear & concise comments

---

## 6. Key Files for Understanding

- `src/client.rs`: Central hub of the client
- `src/store/persistence_manager.rs`: Gatekeeper of state changes
- `src/message.rs`: Incoming message decryption
- `src/send.rs`: Outgoing message encryption
- `tests/message_decryption_test.rs`: Good cryptographic test example
- `wacore/src/binary/`: Encoding/decoding WhatsApp binary format
- `waproto/src/whatsapp.proto`: Source of all message structures

---

## 7. Final Implementation Checks

Before finalizing a feature/fix, always run:

- **Format**: `cargo fmt`
- **Lint**: `cargo clippy --all-targets`
