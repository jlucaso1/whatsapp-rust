# Whatsapp-Rust

A high-performance, asynchronous Rust library for interacting with the WhatsApp platform, inspired by the Go-based `whatsmeow` library and the Typescript-based `Baileys`. This project leverages Rust's safety, performance, and modern async ecosystem (Tokio) to provide a robust and type-safe client.

## Core Features

- ✅ **Secure Connection & Pairing:** Full implementation of the Noise Protocol handshake and QR code pairing for secure, multi-device sessions.
- ✅ **End-to-End Encrypted Messaging:** Robust support for the Signal Protocol, enabling E2E encrypted communication for both one-on-one and group chats.
- ✅ **Media Handling:** Full support for uploading and downloading media files (images, videos, documents, GIFs), including correct handling of encryption and MAC verification.
- ✅ **Flexible Storage Architecture:** Supports custom storage backends (PostgreSQL, MongoDB, Redis, etc.) through a clean trait-based interface, while maintaining SQLite as the default.
- ✅ **Persistent State:** Uses Diesel and SQLite for durable session state by default, ensuring the client can resume sessions after a restart.
- ✅ **Asynchronous by Design:** Built on `tokio` for efficient, non-blocking I/O and concurrent task handling.

## Storage Backends

The library uses a clean, trait-based storage architecture. You must provide a storage backend implementation when creating a bot.

### Using SQLite (Default Implementation)

```rust
use whatsapp_rust::bot::Bot;
use whatsapp_rust::store::sqlite_store::SqliteStore;
use std::sync::Arc;

let backend = Arc::new(SqliteStore::new("whatsapp.db").await?);

let bot = Bot::builder()
    .with_backend(backend)
    .build()
    .await?;
```

### Multi-Account Support

```rust
use whatsapp_rust::bot::Bot;
use whatsapp_rust::store::sqlite_store::SqliteStore;
use std::sync::Arc;

let backend = Arc::new(SqliteStore::new("whatsapp.db").await?);

// First, create device data for the specific device
let mut device = wacore::store::Device::new();
device.push_name = "My Device".to_string();
backend.save_device_data_for_device(42, &device).await?;

// Create bot for specific device
let bot = Bot::builder()
    .with_backend(backend)
    .for_device(42)
    .build()
    .await?;
```

### Custom Backend Implementation

```rust
use whatsapp_rust::bot::Bot;
use std::sync::Arc;

// Implement the Backend trait for your storage system
let custom_backend = Arc::new(MyPostgreSQLBackend::new("postgresql://..."));

let bot = Bot::builder()
    .with_backend(custom_backend)
    .build()
    .await?;
```

See `examples/custom_backend_example.rs` for a complete implementation template.

## Quick Start: A Universal Ping-Pong Bot

The following example demonstrates a simple bot that can "pong" back text, images, and videos.

Check the file `src/main.rs` and run it with `cargo run`.

## Current Status & Known Issues

### ⚠️ Priority Issue: LID Message Decryption

**Problem**: Messages from contacts using the new LID (Lightweight Identity) system cannot be decrypted when received in group chats if no prior 1-on-1 Signal session exists.

**Technical Details**:

- WhatsApp is migrating to a new identity system called LID (Lightweight Identity)
- LID JIDs use format: `236395184570386.1:75@lid` (note the dot in the user portion)
- When a LID user sends a group message and we don't have an established 1-on-1 Signal session with them, decryption fails with `SessionNotFound`
- The client now handles this gracefully (no crashes, dispatches `UndecryptableMessage` event) but messages remain unreadable
- The `offline` counter increases on each reconnection as the server keeps trying to deliver these messages

**Why This Happens**:

1. Group messages use the Signal Protocol's Sender Keys for efficiency
2. To decrypt sender key distribution messages (SKDM), we need an established Signal session with the sender
3. LID users may send group messages without ever having a 1-on-1 chat with us
4. Without the session, we can't decrypt the SKDM, and thus can't decrypt any group messages from that user

**Current Behavior**:

- ✅ No crashes or panics
- ✅ Graceful error handling with `UndecryptableMessage` events
- ✅ Proper JID parsing for LID format (fixed dot-splitting issue)
- ✅ Prevents retry loops by skipping group content when session establishment fails
- ❌ Messages remain undecryptable until a 1-on-1 session is established

**Potential Solutions** (to be implemented):

1. Proactively request pre-keys for LID senders when encountering them in groups
2. Send an empty message to LID contacts to force session establishment
3. Implement a pre-key bundle fetch mechanism similar to whatsmeow's approach
4. Handle session-less SKDM decryption if protocol allows

See test `test_lid_group_message_without_session` in `src/message.rs` for reproduction case.

---

## Roadmap

With the core messaging and media functionality now stable, the project can focus on expanding feature parity and improving robustness.

1.  **Phase 1: Critical Fixes (In Progress)**

    - [x] Fix LID JID parsing to handle dots in user portion
    - [x] Graceful handling of SessionNotFound errors
    - [x] Prevent retry loops for undecryptable messages
    - [ ] **[HIGH PRIORITY]** Implement session establishment for LID contacts to decrypt group messages

2.  **Phase 2: Robustness and Event Handling**

    - [ ] Implement handlers for all receipt types (read, played, etc.).
    - [ ] Implement presence handling (`<presence>`).
    - [ ] Expand `usync` implementation for robust contact and profile synchronization.

3.  **Phase 3: Expanded Message Types**

    - [ ] Add support for sending and receiving reactions.
    - [ ] Implement support for polls and other interactive messages.
    - [ ] Handle message edits and revokes.

4.  **Future Goals**
    - [ ] Profile management (setting status, profile pictures).
    - [ ] Explore newsletter and channel support.

## Disclaimer

This project is an unofficial, open-source reimplementation of a WhatsApp client. Using custom or third-party clients can violate WhatsApp/Meta's Terms of Service and may result in temporary or permanent account suspension or bans. Use this software at your own risk.

## Acknowledgements

Thanks to the following projects for their inspiration and reference implementations:

- whatsmeow (Go) — https://github.com/tulir/whatsmeow
- Baileys (NodeJS) — https://github.com/WhiskeySockets/Baileys

Their work has been invaluable for understanding the WhatsApp protocol and multi-device sync details used throughout this project.
