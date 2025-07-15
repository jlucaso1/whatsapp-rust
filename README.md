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

These modules form the bedrock of the library and are prerequisites for any higher-level functionality.

- `✅` **Protocol Buffers (`proto/`)**
- `✅` **Cryptography Utilities (`crypto/`)**
- `✅` **Binary Protocol (`binary/`)**
- `✅` **Core Types (`types/`)**

---

### 2. Connection & Authentication

This section covers establishing and securing the connection to WhatsApp's servers.

- `✅` **Socket Layer (`socket/`)**
- `✅` **Authentication Handshake (`handshake.rs`)**
- `✅` **Pairing Logic (QR Code, `pair.rs`, `qrcode.rs`)**

---

### 3. Main Client & Event Loop

This is the primary orchestrator that brings all other modules together.

- `✅` **Client Struct & Main Loop (`client.rs`)**
- `✅` **IQ (Info/Query) Handling (`request.rs`)**
- `✅` **Keepalive Loop (`keepalive.rs`)**
- `⏳` **App State Synchronization (`appstate/`)**:
  - `✅` Logic to fetch app state patches from the server.
  - `⏳` **Current Status:** The client can receive and decrypt app state patches. The next step is to process these patches to populate contacts, chats, and other client state.

---

### 4. End-to-End Encryption (Signal Protocol)

The core of the end-to-end encryption implementation.

- `✅` **Session Management (`signal/session.rs`)**:
  - `✅` Decryption of both `PreKeySignalMessage` and `SignalMessage` is working correctly.
  - `✅` Encryption for 1-on-1 chats is implemented, correctly handling multi-device `DeviceSentMessage` payloads.
- `⏳` **Group Messaging (`signal/groups/`)**:
  - `✅` Decryption of group messages (`skmsg`) is functional. The client can correctly receive and process messages sent to groups it is a part of.
  - `⏳` Encryption of group messages is partially implemented but contains a bug causing sent messages to be malformed or undecryptable by recipients. The core cryptographic logic passes local tests, suggesting a subtle issue in message construction or key distribution when interacting with the live server.
- `✅` **Core Protocol Structs (`signal/`)**: Identity, Keys, Ratchet, etc., have been ported and are in use.
- `✅` **Store Traits & Implementations (`store/`, `signal/store.rs`)**: The necessary traits and backend implementations for the protocol are defined and functional.

---

## Build Process

This project pre-compiles the Protocol Buffer definitions into Rust code to simplify the build process for developers and CI/CD environments. You do not need to have the `protobuf-compiler` (`protoc`) installed to build and run this project.

### Regenerating Protobuf Code

If you make changes to `waproto/src/whatsapp.proto`, you will need to regenerate the corresponding Rust code.

**Prerequisites:**

- You must have the protobuf compiler installed. On Debian/Ubuntu, you can install it with:
  ```sh
  sudo apt-get update && sudo apt-get install -y protobuf-compiler
  ```

**Command:**

- To regenerate the files, run the following command from the root of the repository:
  ```sh
  GENERATE_PROTO=1 cargo build -p waproto
  ```
  This command will execute the `waproto/build.rs` script, which regenerates `waproto/src/whatsapp.rs`. Remember to commit the updated generated file to the repository.

## Roadmap & Next Steps

The project has achieved a major milestone: a stable, authenticated, and end-to-end encrypted connection for one-on-one chats. The client can successfully pair, connect, and exchange messages with other WhatsApp clients, including handling the multi-device synchronization protocol correctly.

The current focus is on completing and stabilizing group messaging functionality.

### Phase 1: Complete Group Messaging (Highest Priority)

1.  **Debug Group Message Sending**:
    - **Task**: Investigate and fix the issue with sending group messages. While the client can successfully decrypt incoming group messages, outgoing messages are currently corrupted and cannot be decrypted by other participants. The problem likely lies in the final stanza construction or the pairwise encryption of the `SenderKeyDistributionMessage`.
    - **Why**: This is the final and most critical step to achieving full E2E messaging feature parity.

### Phase 2: App State and Media

1.  **Process App State Mutations**:

    - **Task**: Implement the logic in `appstate/processor.rs` to take the decrypted `Mutation` objects and apply them to the client's store. This includes updating contacts, chat settings (mute, archive), and more.
    - **Why**: This will give the client awareness of the user's account state and is essential for a fully-featured bot or client.

2.  **Implement Media Uploads/Downloads**:
    - **Task**: Add support for encrypting/uploading and downloading/decrypting media files (images, videos, documents). This involves handling media connection details (`mediaconn.rs`).
    - **Why**: Essential for any client that needs to handle more than just text.

### Phase 3: Robustness and Feature Parity

1.  **Full `usync` Implementation**: Implement a robust `get_user_devices` function using `usync` IQs to ensure device lists are always up-to-date.
2.  **Expand Event Handlers**: Implement handlers for receipts, presence, and other notification types to achieve closer feature parity with `whatsmeow`.
