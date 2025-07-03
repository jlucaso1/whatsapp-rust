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

- `✅` **Completed**: The feature is fully implemented and considered stable.
- `⏳` **In Progress / Partially Implemented**: The feature is under active development or has a partial implementation.
- `📋` **Planned**: The feature has not yet been started but is the next priority.
- `[ ]` **Not Started**: The feature has not yet been implemented.

---

### 1. Foundation & Core Primitives

These modules form the bedrock of the library. They are prerequisites for any higher-level functionality.

- `✅` **Protocol Buffers (`proto/`)**:
  - `✅` Project is configured with `prost-build` to generate Rust structs from `.proto` files.
- `✅` **Cryptography Utilities (`crypto/`)**:
  - `✅` Curve25519/X25519 Keypairs (`key_pair.rs`).
  - `✅` HKDF-SHA256 (`hkdf.rs`).
  - `✅` AES-256-GCM for Noise protocol frames (`gcm.rs`).
  - `✅` AES-256-CBC for media decryption (`cbc.rs`).
  - `✅` XEd25519 for pairing signatures (`xed25519.rs`).
- `✅` **Binary Protocol (`binary/`)**:
  - `✅` Node, Attrs, and core structures.
  - `✅` Node Encoder/Decoder (binary `unmarshal`/`marshal`).
  - `✅` Zlib-based decompression for frames (`unpack`).
- `✅` **Core Types (`types/`)**:
  - `✅` JID (Jabber ID) parsing and handling.
  - `✅` Structs for Message, Group, User, Presence, etc.
  - `✅` Event structs (`events.rs`): Core connection and pairing events are implemented.

---

### 2. Connection & Authentication

This section covers establishing and securing the connection to WhatsApp's servers.

- `✅` **Socket Layer (`socket/`)**:
  - `✅` `FrameSocket`: WebSocket wrapper for WhatsApp's framing protocol.
  - `✅` `NoiseSocket`: Encrypted socket layer for transparent encryption/decryption.
- `✅` **Authentication Handshake (`handshake.rs`)**:
  - `✅` Implemented the Noise `XX` handshake flow.
  - `✅` Implemented server certificate chain validation.
  - `✅` `ClientPayload` generation for registration and login.
- `✅` **Pairing Logic (`pair.rs`, `qrcode.rs`)**:
  - `✅` Handling of `<pair-device>` IQ to generate QR code data.
  - `✅` QR code generation, timeout, and channel-based event emission.
  - `✅` Handling of `<pair-success>` IQ to finalize the pairing process.
  - `✅` Correctly handling the post-pairing `stream:error code="515"` reconnect.

---

### 3. Main Client & Event Loop

This is the primary orchestrator that brings all other modules together.

- `✅` **Client Struct (`client.rs`)**:
  - `✅` Core `Client` struct with state management (Store, Sockets).
  - `✅` `connect()` and `run()` methods to establish and maintain a connection.
  - `✅` Event dispatcher system (`add_event_handler`, `dispatch_event`).
  - `✅` Keepalive loop to maintain a stable connection.
  - `✅` Main event loop (`process_node`) that correctly handles connection-level stanzas (`success`, `failure`, `stream:error`, `ib`).
- `✅` **IQ (Info/Query) Handling (`request.rs`)**:
  - `✅` System for sending IQs and asynchronously waiting for responses (`send_iq`).
  - `✅` Ping/Pong handling.
- `⏳` **App State Synchronization (`appstate/`)**:
  - `✅` Logic to fetch app state patches from the server.
  - `✅` Stubbed logic to decode mutations.
  - `⏳` **Current Status:** The client can successfully connect, log in, and trigger app state syncs. It correctly handles `dirty` notifications to re-sync. However, decryption of the app state patches is currently blocked pending the implementation of the Signal Protocol (see next section). This is the expected state.

---

### 4. End-to-End Encryption (Signal Protocol)

The core of the end-to-end encryption. **This is the current major implementation area.**

- `📋` **Session Management (`signal/session.rs`)**:
  - `📋` Build and process `PreKeySignalMessage`.
  - `📋` Build and process `SignalMessage`.
  - `📋` Manage the session store.
- `📋` **Identity Management (`signal/identity.rs`)**:
  - `📋` Handle identity keys and trust management (`UntrustedIdentityError`).
- `📋` **PreKey Management**:
  - `[ ]` Generate, store, and manage one-time pre-keys.
- `[ ]` **Group/Sender Key Management**:
  - `[ ]` Manage group sessions using sender keys (`SenderKeyMessage`).

---

## Roadmap & Next Steps

The project has achieved a stable, authenticated connection and the app state sync mechanism is correctly implemented up to the decryption step. The next phase is to implement the full end-to-end encryption layer, which will unblock app state sync and enable message sending/receiving.

### Phase 1: Implement the Signal Protocol (In Progress)

This is the highest priority. The goal is to enable the client to decrypt incoming messages, which is required to receive the App State Sync Keys and complete the synchronization process.

1.  **Port `libsignal-protocol-go` Logic**:

    - **Task**: Continue fleshing out the `src/signal` module by porting the Rust equivalent of the `libsignal-protocol-go` library.
    - **Why**: This module contains the core Double Ratchet algorithm, which is essential for all E2EE communication.
    - **Key Files to Port**: `session/SessionCipher.go`, `session/SessionBuilder.go`, and the `state/record/*.go` files are critical.

2.  **Implement the `SignalProtocolStore` Trait**:

    - **Task**: Complete the `SignalProtocolStore` implementation in `src/store/signal.rs` and `src/store/memory.rs`. The placeholder methods need to be filled out to properly serialize and deserialize the `SessionRecord` and other cryptographic state objects.
    - **Why**: The Signal protocol logic needs a way to persist its state.

3.  **Complete `handle_encrypted_message`**:
    - **Task**: Once the Signal protocol port is complete, the existing `handle_encrypted_message` function will be able to decrypt the `AppStateSyncKeyShare` message.
    - **Why**: This will resolve the "No app state sync key found" warnings and complete the app state sync flow, allowing the client to see contacts, chats, etc.

### Phase 2: Sending and Receiving 1-on-1 Messages

Once the Signal protocol is functional, the client will be ready for messaging.

1.  **Implement Message Sending**:
    - **Task**: Create a high-level `send_text_message` function on the `Client`.
    - **Why**: To provide a simple, user-facing method for sending messages.
    - **Details**: This will involve checking for an existing session, fetching pre-keys if one doesn't exist, building a new session, and finally encrypting and sending the message.

### Phase 3: Feature Expansion

1.  **Group Messaging & E2EE**: Implement the Sender Keys mechanism for group chats.
2.  **Expanded Node Handlers**: Implement handlers for receipts, presence, and other notification types.
3.  **Media Upload/Download**: Implement the logic for sending and receiving media files.
