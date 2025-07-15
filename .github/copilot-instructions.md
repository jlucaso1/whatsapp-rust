# WhatsApp-Rust Copilot Instructions

This is a Rust port of the Go-based `whatsmeow` library for WhatsApp client development, implementing the complete WhatsApp Web protocol with end-to-end encryption.

## Architecture Overview

### Core Components
- **Client** (`src/client.rs`): Main orchestrator managing connection lifecycle, event handling, and state coordination
- **Store Layer** (`src/store/`): Persistence abstraction with `PersistenceManager` for atomic state updates via command pattern
- **Signal Protocol** (`src/signal/`): Complete Double Ratchet E2EE implementation for 1-on-1 and group messaging
- **Binary Protocol** (`src/binary/`): WhatsApp's custom binary protocol (WABinary) encoder/decoder with zero-copy parsing
- **Socket Layer** (`src/socket/`): WebSocket + Noise Protocol handshake for secure transport
- **App State Sync** (`src/appstate/`): Handles WhatsApp's state synchronization (contacts, chats, settings)

### Data Flow Pattern
1. **Connection**: `FrameSocket` → `NoiseSocket` → authenticated WebSocket
2. **Message Processing**: Binary frames → `Node` structures → protocol handlers → Signal decryption → events
3. **State Updates**: Commands → `PersistenceManager` → background persistence with dirty tracking

## Development Workflows

### Building & Testing
```bash
# Build with all features
cargo build --release

# Run integration tests (includes E2E encryption tests)
cargo test

# Debug device state
cargo run --bin debug_device

# Run main client (handles QR pairing automatically)
cargo run

# After modifications run format
cargo fmt

```

### Key Testing Patterns
- Integration tests in `tests/` simulate full WhatsApp protocol flows
- `one_on_one_test.rs` demonstrates complete Signal Protocol session establishment
- Tests use `MemoryStore` for isolated state vs `FileStore` for persistence
- Mock clients can simulate phone-side pairing for automated testing

## Critical Patterns & Conventions

### State Management
- **Never access device state directly** - use `PersistenceManager::process_command()` for all mutations
- **Command Pattern**: All state changes go through `DeviceCommand` enum for atomicity and background persistence
- **Snapshot Pattern**: Use `get_device_snapshot()` for read-only access to current state

### Async Concurrency
- **Per-chat locks**: `chat_locks: DashMap<Jid, Arc<Mutex<()>>>` serializes messages within chats while allowing cross-chat concurrency
- **Event-driven**: Client emits `Event` enum for all protocol events (messages, presence, state changes)
- **Background tasks**: Keepalive, state sync, and persistence run as separate Tokio tasks

### Protocol Specifics
- **JID Format**: WhatsApp user/group identifiers use custom parsing in `types/jid.rs`
- **Binary Encoding**: Use `binary::marshal()` / `binary::unmarshal_ref()` for WABinary protocol
- **Signal Sessions**: Session establishment requires prekey bundles and device registration
- **Multi-device**: Handle `DeviceSentMessage` wrappers for messages sent from other user devices

### Error Handling
- **Protocol Errors**: Use `BinaryError` for WABinary parsing, `SocketError` for connection issues
- **Crypto Errors**: Signal Protocol errors in `signal/` modules, app state sync errors in `appstate/errors.rs`
- **Graceful degradation**: Connection drops trigger automatic reconnection with exponential backoff

### Key Files for Understanding
- `src/main.rs`: Complete client lifecycle example with QR pairing and event handling
- `src/handshake.rs`: WhatsApp authentication flow and server key verification
- `src/message.rs`: Message encryption/decryption and multi-device handling
- `src/appstate/processor.rs`: App state mutation processing (contacts, chat settings)
- `tests/conversation_e2e_test.rs`: Full E2E messaging test demonstrating proper usage patterns

## Integration Points

### External Dependencies
- **Tokio**: All async operations, client uses `Arc<Client>` for shared state across tasks
- **Protobuf**: Generated bindings in `waproto/` crate for WhatsApp's wire protocol
- **Cryptography**: `x25519-dalek`, `ed25519-dalek` for Signal Protocol, `aes-gcm` for symmetric encryption

### Store Backend Abstraction
- Implement `Backend` trait in `store/traits.rs` for custom persistence (SQLite, Redis, etc.)
- Current implementations: `FileStore` (production), `MemoryStore` (testing)
- All crypto material (identity keys, sessions, prekeys) stored via backend abstraction

### Event System
- Add handlers via `client.add_event_handler(Box::new(handler))`
- Events are `Arc<Event>` for efficient sharing across handlers
- Critical events: `Event::Message`, `Event::LoggedOut`, `Event::Connected`, `Event::AppStateSyncComplete`

When working on WhatsApp protocol features, always reference the existing integration tests for proper patterns and consult the Go `whatsmeow` documentation for protocol behavior.
