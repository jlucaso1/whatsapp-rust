# Whatsapp-Rust (whatsmeow Port)

This project is a Rust port of the core functionalities of the Go-based `whatsmeow` library. The goal is to create a robust, type-safe, and performant Rust library for interacting with the WhatsApp platform using modern and idiomatic async Rust.

This document outlines the migration progress and the current state of the project.

## Project Goals

- **Type Safety:** Leverage Rust's strong type system to eliminate entire classes of bugs.
- **Performance:** Utilize Rust's performance for efficient handling of binary protocols and cryptography.
- **Concurrency:** Build a modern asynchronous architecture using Tokio for high-throughput event processing.
- **Modularity:** Maintain a clean, modular architecture similar to `whatsmeow` to ensure the codebase is maintainable and extensible.

## Migration Status

### Legend

- `[x]` **Completed**: The feature is fully implemented and considered stable.
- `[~]` **In Progress / Partially Implemented**: The feature is under active development or has a partial implementation.
- `[ ]` **Not Started**: The feature has not yet been implemented.

---

### 1. Foundation & Core Primitives

These modules form the bedrock of the library. They are prerequisites for any higher-level functionality.

- `[x]` **Protocol Buffers (`proto/`)**:
  - `[x]` Project is configured with `prost-build` to generate Rust structs from `.proto` files.
- `[x]` **Cryptography Utilities (`crypto/`)**:
  - `[x]` Curve25519/X25519 Keypairs and signing (`key_pair.rs`).
  - `[x]` HKDF-SHA256 (`hkdf.rs`).
  - `[x]` AES-256-GCM for Noise protocol frames (`gcm.rs`).
  - `[x]` AES-256-CBC for media decryption (`cbc.rs`).
- `[x]` **Binary Protocol (`binary/`)**:
  - `[x]` Implemented Node, Attrs, and core structures.
  - `[x]` Implemented Node Encoder/Decoder (binary `unmarshal`/`marshal`).
  - `[x]` Implemented Zlib-based decompression for frames (`unpack`).
- `[~]` **Core Types (`types/`)**:
  - `[x]` JID (Jabber ID) parsing and handling.
  - `[x]` Structs for Message, Group, User, Presence, etc.
  - `[~]` Event structs (`events.rs`): Core connection and pairing events are implemented. Most app-state and other notification events are still pending.

---

### 2. Connection & Authentication

This section covers establishing and securing the connection to WhatsApp's servers.

- `[x]` **Socket Layer (`socket/`)**:
  - `[x]` `FrameSocket`: WebSocket wrapper for WhatsApp's framing protocol (3-byte length prefix).
  - `[x]` `NoiseSocket`: Encrypted socket layer for transparent encryption/decryption of frames.
- `[x]` **Authentication Handshake (`handshake.rs`)**:
  - `[x]` Implemented the Noise `XX` handshake flow.
  - `[x]` Implemented server certificate chain validation.
  - `[x]` `ClientPayload` generation for registration and login.
- `[x]` **Pairing Logic (`pair.rs`, `qrcode.rs`)**:
- `[x]` Handling of `<pair-device>` IQ to generate QR code data.
- `[x]` QR code generation, timeout, and channel-based event emission for UI consumption.
- `[x]` Handling of `<pair-success>` IQ to finalize the pairing process (storing identity, etc.).
- `[x]` Handling of `<pair-error>` responses from the server.

---

### 3. Main Client & Event Loop

This is the primary orchestrator that brings all other modules together.

- `[~]` **Client Struct (`client.rs`)**:
  - `[x]` Core `Client` struct with state management (Store, Sockets).
  - `[x]` `connect()` method to establish a connection and perform the handshake.
  - `[x]` Event dispatcher system (`add_event_handler`, `dispatch_event`).
  - `[~]` `read_messages_loop()`: The main event loop is running and can decrypt frames. It currently only delegates IQs to the appropriate handlers.
- `[x]` **IQ (Info/Query) Handling (`request.rs`)**:
  - `[x]` System for sending IQs and asynchronously waiting for responses (`send_iq`).
  - `[x]` Logic for routing incoming IQ responses to the correct waiting task.

---

### 4. Feature Handlers (Node Processing)

This section covers the processing of specific stanzas received after a successful connection.

- `[~]` **IQ Handlers**:
- `[x]` Pairing IQs (`<pair-device>`, `<pair-success>`, etc.).
- `[ ]` Privacy settings, blocklists, and other `get`/`set` IQs.
- `[ ]` **Message Handler**:
  - `[ ]` Decrypting incoming `message` stanzas (Signal Protocol).
  - `[ ]` Parsing `WebMessageInfo`.
  - `[ ]` Dispatching `events::Message` and `events::UndecryptableMessage`.
- `[ ]` **Receipt Handler**:
  - `[ ]` Processing `receipt` stanzas for delivery/read receipts.
- `[ ]` **Presence Handler**:
  - `[ ]` Processing `presence` and `chatstate` (typing) stanzas.
- `[ ]` **Notification Handler**:
  - `[ ]` Processing `notification` stanzas for group changes, profile picture updates, etc.
- `[ ]` **AppState/History Sync Handler**:
  - `[ ]` Processing history sync blobs and app state changes from other devices.

---

### 5. End-to-End Encryption (Signal Protocol)

The core of the end-to-end encryption. This is the next major implementation area.

- `[ ]` **Session Management**:
  - `[ ]` Build and process `PreKeySignalMessage`.
  - `[ ]` Build and process `SignalMessage`.
  - `[ ]` Manage the session store.
- `[ ]` **Identity Management**:
  - `[ ]` Handle identity keys and trust management.
- `[ ]` **PreKey Management**:
  - `[ ]` Generate, store, and manage one-time pre-keys.
- `[ ]` **Group/Sender Key Management**:
  - `[ ]` Manage group sessions using sender keys (`SenderKeyMessage`).

---

### 6. High-Level API

These are the user-facing methods that will be exposed on the `Client`.

- `[ ]` **Message Sending**: e.g., `send_text_message`, `send_image`, etc.
- `[ ]` **User/Group Info**: e.g., `get_user_info`, `get_group_info`.
- `[ ]` **Presence Control**: e.g., `send_presence`, `subscribe_presence`.
- `[ ]` **Media Handling**:
  - `[ ]` Media upload/download logic.
  - `[ ]` Media connection management.

---

### 7. Storage

A persistent storage solution is required to maintain the client's state across restarts.

- `[ ]` **Storage Traits**: Define `trait`-based abstractions for all required stores (Device, Identity, Session, Keys, etc.) to allow for different backends.
- `[ ]` **Device Store**: The `store::Device` struct currently holds data in-memory for a single session.
- `[ ]` **Persistent Implementation**: Provide an initial persistent implementation (e.g., using `sled`, `rusqlite`, or simple file-based storage).

## Next Steps

The immediate priorities for the project are:

1.  **Signal Protocol Integration**: Begin integrating a Signal Protocol library or implementing the necessary components to handle message encryption and decryption. This is the largest and most critical remaining feature.
2.  **Implement Message Handler**: Once Signal is integrated, create the handler to process incoming `message` stanzas.
