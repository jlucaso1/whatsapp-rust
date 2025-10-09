# Whatsapp-Rust

A high-performance, asynchronous Rust library for interacting with the WhatsApp platform, inspired by the Go-based `whatsmeow` library and the Typescript-based `Baileys`. This project leverages Rust's safety, performance, and modern async ecosystem (Tokio) to provide a robust and type-safe client.

## Core Features

- ✅ **Secure Connection & Pairing:** Full implementation of the Noise Protocol handshake and QR code pairing for secure, multi-device sessions.
- ✅ **End-to-End Encrypted Messaging:** Robust support for the Signal Protocol, enabling E2E encrypted communication for both one-on-one and group chats.
- ✅ **Media Handling:** Full support for uploading and downloading media files (images, videos, documents, GIFs), including correct handling of encryption and MAC verification.
- ✅ **Runtime Agnostic:** Abstracted transport layer allows use with any async runtime or platform (Tokio, async-std, WASM, etc.).
- ✅ **Flexible Storage Architecture:** Storage-agnostic core with pluggable backends. SQLite provided by default, but supports custom implementations (PostgreSQL, MongoDB, Redis, browser storage, etc.) through a clean trait-based interface.
- ✅ **WASM Compatible:** Core library is free of C dependencies and ready for WebAssembly compilation. See [WASM.md](WASM.md) for details on WASM support.
- ✅ **Persistent State:** SQLite backend (when enabled) uses Diesel for durable session state, ensuring the client can resume sessions after a restart.
- ✅ **Asynchronous by Design:** Supports efficient, non-blocking I/O and concurrent task handling with any async runtime through pluggable transport implementations.

## Storage Backends

The library uses a clean, trait-based storage architecture. You must provide a storage backend implementation when creating a bot.

The core library (`whatsapp-rust`) is **storage-agnostic** and can be compiled without any specific storage implementation, making it suitable for WebAssembly and other constrained environments. Storage backends are provided as separate crates.

### Using SQLite (Default)

The SQLite backend is provided by the `whatsapp-rust-sqlite-storage` crate and is included by default through the `sqlite-storage` feature flag.

**In your `Cargo.toml`:**
```toml
[dependencies]
whatsapp-rust = "0.1"  # sqlite-storage feature is enabled by default
whatsapp-rust-tokio-transport = "0.1"
whatsapp-rust-ureq-http-client = "0.1"
```

**In your code:**
```rust
use whatsapp_rust::bot::Bot;
use whatsapp_rust::store::SqliteStore;
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use whatsapp_rust_ureq_http_client::UreqHttpClient;
use std::sync::Arc;

let backend = Arc::new(SqliteStore::new("whatsapp.db").await?);
let transport_factory = TokioWebSocketTransportFactory::new();
let http_client = UreqHttpClient::new();

let bot = Bot::builder()
    .with_backend(backend)
    .with_transport_factory(transport_factory)
    .with_http_client(http_client)
    .build()
    .await?;
```

### Multi-Account Support

```rust
use whatsapp_rust::bot::Bot;
use whatsapp_rust::store::SqliteStore;
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use std::sync::Arc;

let backend = Arc::new(SqliteStore::new("whatsapp.db").await?);
let transport_factory = TokioWebSocketTransportFactory::new();

// First, create device data for the specific device
let mut device = wacore::store::Device::new();
device.push_name = "My Device".to_string();
backend.save_device_data_for_device(42, &device).await?;

// Create bot for specific device
let bot = Bot::builder()
    .with_backend(backend)
    .with_transport_factory(transport_factory)
    .for_device(42)
    .build()
    .await?;
```

### Building Without SQLite (e.g., for WebAssembly)

To compile the library without SQLite dependencies (for WASM or other constrained environments), disable the default features:

```toml
[dependencies]
whatsapp-rust = { version = "0.1", default-features = false }
```

You can then provide your own storage backend by implementing the `wacore::store::traits::Backend` trait. This allows you to use:
- Browser storage APIs (localStorage, IndexedDB) for WASM
- PostgreSQL, MongoDB, Redis, or other databases
- In-memory storage for testing

**Note:** For complete WASM support, you'll also need WASM-compatible transport and HTTP implementations. The core `whatsapp-rust` library no longer has any platform-specific dependencies, making it truly WASM-compatible when paired with appropriate implementations.

### Custom Backend Implementation

```rust
use whatsapp_rust::bot::Bot;
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use std::sync::Arc;

// Implement the Backend trait for your storage system
let custom_backend = Arc::new(MyPostgreSQLBackend::new("postgresql://..."));
let transport_factory = TokioWebSocketTransportFactory::new();

let bot = Bot::builder()
    .with_backend(custom_backend)
    .with_transport_factory(transport_factory)
    .build()
    .await?;
```

See `examples/custom_backend_example.rs` for a complete implementation template.

## Transport and HTTP Client

The library uses abstracted transport and HTTP client layers, making it platform-agnostic. You must provide both a transport factory and HTTP client when creating a bot.

### Using Default Implementations

**In your `Cargo.toml`:**
```toml
[dependencies]
whatsapp-rust = "0.1"
whatsapp-rust-tokio-transport = "0.1"
whatsapp-rust-ureq-http-client = "0.1"
```

**In your code:**
```rust
use whatsapp_rust::bot::Bot;
use whatsapp_rust::store::SqliteStore;
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use whatsapp_rust_ureq_http_client::UreqHttpClient;
use std::sync::Arc;

let backend = Arc::new(SqliteStore::new("whatsapp.db").await?);
let transport_factory = TokioWebSocketTransportFactory::new();
let http_client = UreqHttpClient::new();

let bot = Bot::builder()
    .with_backend(backend)
    .with_transport_factory(transport_factory)
    .with_http_client(http_client)
    .build()
    .await?;
```

### Custom Transport and HTTP Implementations

You can implement your own transport and HTTP client for different runtimes or platforms by implementing the `Transport`, `TransportFactory`, and `HttpClient` traits. This enables:

- Using different async runtimes (async-std, smol)
- Compiling to WebAssembly with browser APIs
- Testing with mock implementations
- Custom protocols or proxies

See the `whatsapp-rust-tokio-transport` and `whatsapp-rust-ureq-http-client` crates for reference implementations.

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
