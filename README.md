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
  - `[x]` XEd25519 for pairing signatures (`xed25519.rs`).
- `[x]` **Binary Protocol (`binary/`)**:
  - `[x]` Node, Attrs, and core structures.
  - `[x]` Node Encoder/Decoder (binary `unmarshal`/`marshal`).
  - `[x]` Zlib-based decompression for frames (`unpack`).
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
  - `[x]` Handling of `<pair-success>` IQ to finalize the pairing process.
  - `[x]` Correctly handling the post-pairing `stream:error code="515"` reconnect.

---

### 3. Main Client & Event Loop

This is the primary orchestrator that brings all other modules together.

- `[~]` **Client Struct (`client.rs`)**:
  - `[x]` Core `Client` struct with state management (Store, Sockets).
  - `[x]` `connect()` and `run()` methods to establish and maintain a connection.
  - `[x]` Event dispatcher system (`add_event_handler`, `dispatch_event`).
  - `[x]` Keepalive loop to maintain a stable connection.
  - `[~]` `process_node`: The main event loop is running and can decrypt frames. It currently handles connection-level stanzas (`success`, `failure`, `stream:error`, `ib`) and basic IQs.
- `[~]` **IQ (Info/Query) Handling (`request.rs`)**:
  - `[x]` System for sending IQs and asynchronously waiting for responses (`send_iq`).
  - `[x]` Logic for routing incoming IQ responses to the correct waiting task.
  - `[x]` Ping/Pong handling.

---

### 4. End-to-End Encryption (Signal Protocol)

The core of the end-to-end encryption. This is the next major implementation area.

- `[ ]` **Session Management**:
  - `[ ]` Build and process `PreKeySignalMessage`.
  - `[ ]` Build and process `SignalMessage`.
  - `[ ]` Manage the session store.
- `[ ]` **Identity Management**:
  - `[ ]` Handle identity keys and trust management (`UntrustedIdentityError`).
- `[ ]` **PreKey Management**:
  - `[ ]` Generate, store, and manage one-time pre-keys.
- `[ ]` **Group/Sender Key Management**:
  - `[ ]` Manage group sessions using sender keys (`SenderKeyMessage`).

---

## Roadmap & Next Steps

The project has a stable, authenticated connection. The next phases focus on implementing the E2EE layer to send and receive messages, followed by expanding feature support.

### Phase 1: Signal Protocol & Pre-Key Management

This is the highest priority. The goal is to prepare the client to send and receive 1-on-1 encrypted messages.

1.  **Integrate `libsignal` Logic**:

    - **Task**: Create a new `src/signal` module to house the Rust port of the `libsignal-protocol-go` library.
    - **Why**: This module will contain the core Double Ratchet algorithm, which is essential for all E2EE communication.
    - **Key Files to Port**: Start with `session/SessionCipher.go`, `session/SessionBuilder.go`, and the `protocol/*.go` files.

2.  **Expand the Store Traits**:

    - **Task**: Define and implement the traits required by the Signal protocol in `src/store/`. This includes stores for `PreKey`, `SignedPreKey`, `Session`, and `IdentityKey` that match the `libsignal` interfaces.
    - **Why**: The Signal protocol logic needs a way to persist its cryptographic state (sessions, keys, etc.). Your `MemoryStore` will need to implement these new traits.

3.  **Implement Pre-Key Management**:

    - **Task**: Port the logic from `whatsmeow/prekeys.go`. Create a function to `upload_prekeys` to the server.
    - **Why**: Your client must have a batch of pre-keys on the server so other users can initiate an encrypted session with you. This should be called automatically after a successful login.

4.  **Implement Pre-Key Fetching**:
    - **Task**: Port `fetchPreKeys` from `whatsmeow/prekeys.go`.
    - **Why**: To start a conversation with someone, you must first download their pre-key bundle from the server.

### Phase 2: Sending and Receiving 1-on-1 Messages

With the Signal protocol foundation in place, you can now implement messaging.

1.  **Implement Message Decryption**:

    - **Task**: In `client.rs`, expand your message handler to process incoming `<message>` stanzas that contain an `<enc>` child.
    - **Why**: This is the core of receiving messages. You'll use your new `signal::SessionCipher` to decrypt the payload.
    - **Details**:
      - Handle both `pkmsg` (pre-key messages, for new sessions) and `msg` (standard messages).
      - Crucially, implement the logic to handle an `UntrustedIdentityError`. The standard behavior is to trust the new identity and proceed.

2.  **Implement Message Sending**:
    - **Task**: Create a high-level `send_text_message` function on the `Client`.
    - **Why**: This will be the primary user-facing method for sending messages.
    - **Details**:
      1.  Check if a session exists for the recipient.
      2.  If not, call your `fetch_prekeys` function to get their bundle.
      3.  Use your `signal::SessionBuilder` to establish a new session.
      4.  Use `signal::SessionCipher` to encrypt the message.
      5.  Construct the final `<message>` stanza and send it with `send_node`.

### Phase 3: Group Messaging & Feature Expansion

Once 1-on-1 messaging is working, you can expand to more complex features.

1.  **Implement Group E2EE (Sender Keys)**:

    - **Task**: Port the logic from `libsignal-protocol-go/groups/`.
    - **Why**: Group chats use a different E2EE mechanism called Sender Keys.
    - **Details**: Handle incoming `skmsg` (Sender Key Message) and `sender_key_distribution_message` stanzas.

2.  **Expand Node Handlers**:

    - **Task**: Create handlers for other common stanzas.
    - **Why**: To make the client feel complete and interactive.
    - **Stanzas to Implement**:
      - `<receipt>`: For handling delivery and read receipts.
      - `<presence>`: For online/offline status updates.
      - `<chatstate>`: For "typing..." and "recording audio..." indicators.
      - `<notification>`: For group metadata changes (subject, avatar), user profile picture updates, etc.

3.  **AppState & History Sync**:
    - **Task**: Implement the logic from `whatsmeow/appstate/`.
    - **Why**: This allows the client to sync its state (archived chats, muted chats, contacts) with other linked devices.

### Phase 4: Media and High-Level API

1.  **Media Upload/Download**:

    - **Task**: Port `whatsmeow/upload.go` and `download.go`.
    - **Why**: To enable sending and receiving images, videos, documents, etc. This involves a separate media connection and CBC encryption.

2.  **Build High-Level API**:
    - **Task**: Create simple, user-friendly functions like `send_image`, `get_group_info`, `set_group_subject`, etc.
    - **Why**: To abstract away the complexity of constructing and sending the underlying XML nodes.
