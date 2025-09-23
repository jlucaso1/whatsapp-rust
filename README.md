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

The library provides a flexible storage architecture that allows you to choose your preferred database:

### Default SQLite Usage
```rust
use whatsapp_rust::{Bot, ClientConfig};

let config = ClientConfig {
    db_path: "whatsapp.db".to_string(),
    app_version_override: None,
};

let bot = Bot::builder()
    .with_config(config)
    .build()
    .await?;
```

### Custom Backend Usage
```rust
use whatsapp_rust::Bot;
use std::sync::Arc;

// Implement the Backend and DevicePersistence traits for your storage system
let custom_backend = Arc::new(MyPostgreSQLBackend::new("postgresql://..."));
let device_persistence = Arc::new(MyPostgreSQLDevicePersistence::new("postgresql://..."));

let bot = Bot::builder()
    .with_backend(custom_backend, device_persistence)
    .build()
    .await?;
```

See `examples/custom_backend_example.rs` for a complete implementation template.

## Quick Start: A Universal Ping-Pong Bot

The following example demonstrates a simple bot that can "pong" back text, images, and videos.

Check the file `src/main.rs` and run it with `cargo run`.

## Roadmap

With the core messaging and media functionality now stable, the project can focus on expanding feature parity and improving robustness.

1.  **Phase 2: Robustness and Event Handling**

    - [ ] Implement handlers for all receipt types (read, played, etc.).
    - [ ] Implement presence handling (`<presence>`).
    - [ ] Expand `usync` implementation for robust contact and profile synchronization.

2.  **Phase 3: Expanded Message Types**

    - [ ] Add support for sending and receiving reactions.
    - [ ] Implement support for polls and other interactive messages.
    - [ ] Handle message edits and revokes.

3.  **Future Goals**
    - [ ] Profile management (setting status, profile pictures).
    - [ ] Explore newsletter and channel support.

## Disclaimer

This project is an unofficial, open-source reimplementation of a WhatsApp client. Using custom or third-party clients can violate WhatsApp/Meta's Terms of Service and may result in temporary or permanent account suspension or bans. Use this software at your own risk.

## Acknowledgements

Thanks to the following projects for their inspiration and reference implementations:

- whatsmeow (Go) — https://github.com/tulir/whatsmeow
- Baileys (NodeJS) — https://github.com/WhiskeySockets/Baileys

Their work has been invaluable for understanding the WhatsApp protocol and multi-device sync details used throughout this project.
