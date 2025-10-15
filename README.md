# Whatsapp-Rust

A high-performance, asynchronous Rust library for interacting with the WhatsApp platform, inspired by the Go-based `whatsmeow` library and the Typescript-based `Baileys`. This project leverages Rust's safety, performance, and modern async ecosystem (Tokio) to provide a robust and type-safe client.

## Core Features

- ✅ **Secure Connection & Pairing:** Full implementation of the Noise Protocol handshake and QR code pairing for secure, multi-device sessions.
- ✅ **End-to-End Encrypted Messaging:** Robust support for the Signal Protocol, enabling E2E encrypted communication for both one-on-one and group chats.
- ✅ **Media Handling:** Full support for uploading and downloading media files (images, videos, documents, GIFs), including correct handling of encryption and MAC verification.
- ✅ **Runtime Agnostic:** Abstracted transport layer allows use with any async runtime or platform (Tokio, async-std, WASM, etc.).
- ✅ **Flexible Storage Architecture:** Storage-agnostic core with pluggable backends. SQLite provided by default, but supports custom implementations (PostgreSQL, MongoDB, Redis, browser storage, etc.) through a clean trait-based interface.

### Custom Backend Implementation

See `examples/custom_backend_example.rs` for a complete implementation template.

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

1.  **Phase 1: Robustness and Event Handling**

    - [ ] Implement handlers for all receipt types (read, played, etc.).
    - [ ] Implement presence handling (`<presence>`).
    - [ ] Expand `usync` implementation for robust contact and profile synchronization.

2.  **Phase 2: Expanded Message Types**
    - [ ] Explore newsletter and channel support.
    - [ ] Profile management (setting status, profile pictures).

## Disclaimer

This project is an unofficial, open-source reimplementation of a WhatsApp client. Using custom or third-party clients can violate WhatsApp/Meta's Terms of Service and may result in temporary or permanent account suspension or bans. Use this software at your own risk.

## Acknowledgements

Thanks to the following projects for their inspiration and reference implementations:

- whatsmeow (Go) — https://github.com/tulir/whatsmeow
- Baileys (NodeJS) — https://github.com/WhiskeySockets/Baileys

Their work has been invaluable for understanding the WhatsApp protocol and multi-device sync details used throughout this project.
