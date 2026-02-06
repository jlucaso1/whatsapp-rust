# whatsapp-rust

A high-performance, async Rust library for the WhatsApp Web API. Inspired by [whatsmeow](https://github.com/tulir/whatsmeow) (Go) and [Baileys](https://github.com/WhiskeySockets/Baileys) (TypeScript).

## Features

### Authentication

- QR code pairing
- Pair code (phone number) linking
- Persistent sessions with automatic reconnection

### Messaging

- End-to-end encrypted messages (Signal Protocol)
- One-on-one and group chats
- Message editing and reactions
- Quoting/replying to messages
- Delivery, read, and played receipts

### Media

- Upload and download images, videos, documents, GIFs, and audio
- Automatic encryption and decryption

### Contacts & Groups

- Check if phone numbers are on WhatsApp
- Fetch profile pictures and user info
- Query group metadata and participants
- List all groups you're participating in

### Presence & Chat State

- Set online/offline presence
- Typing indicators (composing, recording, paused)
- Block and unblock contacts

### Architecture

- **Modular design** - Pluggable storage, transport, and HTTP clients
- **Runtime agnostic** - Works with Tokio, async-std, or WASM
- **SQLite included** - Default storage backend, easily swappable

## Quick Start

```rust
use std::sync::Arc;
use whatsapp_rust::bot::Bot;
use whatsapp_rust::store::SqliteStore;
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use whatsapp_rust_ureq_http_client::UreqHttpClient;
use wacore::types::events::Event;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(SqliteStore::new("whatsapp.db").await?);

    let mut bot = Bot::builder()
        .with_backend(backend)
        .with_transport_factory(TokioWebSocketTransportFactory::new())
        .with_http_client(UreqHttpClient::new())
        .on_event(|event, client| async move {
            match event {
                Event::PairingQrCode { code, .. } => println!("QR:\n{}", code),
                Event::Message(msg, info) => {
                    println!("Message from {}: {:?}", info.source.sender, msg);
                }
                _ => {}
            }
        })
        .build()
        .await?;

    bot.run().await?.await?;
    Ok(())
}
```

Run the included demo bot:

```bash
cargo run                          # QR code only
cargo run -- -p 15551234567        # Pair code + QR code
cargo run -- -p 15551234567 -c 12345678 # Custom pair code
```

## Project Structure

```
whatsapp-rust/
├── src/                    # Main client library
├── wacore/                 # Platform-agnostic core (no_std compatible)
│   ├── binary/             # WhatsApp binary protocol
│   ├── libsignal/          # Signal Protocol implementation
│   └── appstate/           # App state management
├── waproto/                # Protocol Buffers definitions
├── storages/sqlite-storage # SQLite backend
├── transports/tokio-transport
└── http_clients/ureq-client
```

## Custom Backends

Implement your own storage, transport, or HTTP client by implementing the respective traits. See the default implementations for reference.

## Disclaimer

This is an unofficial, open-source reimplementation. Using custom WhatsApp clients may violate Meta's Terms of Service and could result in account suspension. Use at your own risk.

## Acknowledgements

- [whatsmeow](https://github.com/tulir/whatsmeow) (Go)
- [Baileys](https://github.com/WhiskeySockets/Baileys) (TypeScript)
