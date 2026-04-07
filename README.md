# whatsapp-rust

A high-performance, async Rust library for the WhatsApp Web API. Inspired by [whatsmeow](https://github.com/tulir/whatsmeow) (Go) and [Baileys](https://github.com/WhiskeySockets/Baileys) (TypeScript).

**[Documentation](https://whatsapp-rust.jlucaso.com)** | [llms.txt](https://whatsapp-rust.jlucaso.com/llms.txt) | [llms-full.txt](https://whatsapp-rust.jlucaso.com/llms-full.txt)

## Features

- **Authentication** — QR code pairing, pair code linking, persistent sessions
- **Messaging** — E2E encrypted (Signal Protocol), 1-on-1 and group chats, editing, reactions, quoting, receipts
- **Media** — Upload/download images, videos, documents, GIFs, audio with automatic encryption
- **Groups & Communities** — Create, manage, invite, membership approval, subgroup linking
- **Newsletters** — Create, join, send messages, reactions
- **Status** — Text, image, and video status posts with privacy controls
- **Contacts** — Phone number lookup, profile pictures, user info, business profiles
- **Presence & Chat State** — Online/offline, typing indicators, blocking
- **Chat Actions** — Archive, pin, mute, star messages
- **Profile** — Set push name, status text, profile picture
- **Privacy** — Fetch/set privacy settings, disappearing messages
- **Modular** — Pluggable storage, transport, HTTP client, and async runtime
- **Runtime agnostic** — Bring your own async runtime via the `Runtime` trait (Tokio included by default)

For the full API reference and guides, see the **[documentation](https://whatsapp-rust.jlucaso.com)**.

## Quick Start

```rust
use std::sync::Arc;
use whatsapp_rust::bot::Bot;
use whatsapp_rust::store::SqliteStore;
use whatsapp_rust::TokioRuntime;
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
        .with_runtime(TokioRuntime)
        .on_event(|event, _client| async move {
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
cargo run                              # QR code only
cargo run -- -p 15551234567            # Pair code + QR code
cargo run -- -p 15551234567 -c MYCODE  # Custom pair code
```

## Project Structure

```
whatsapp-rust/
├── src/                    # Main client library
├── wacore/                 # Platform-agnostic core (no runtime deps)
│   ├── binary/             # WhatsApp binary protocol
│   ├── libsignal/          # Signal Protocol implementation
│   └── appstate/           # App state management
├── waproto/                # Protocol Buffers definitions
├── storages/sqlite-storage # SQLite backend
├── transports/tokio-transport
└── http_clients/ureq-client
```

## Disclaimer

This is an unofficial, open-source reimplementation. Using custom WhatsApp clients may violate Meta's Terms of Service and could result in account suspension. Use at your own risk.

## Acknowledgements

- [whatsmeow](https://github.com/tulir/whatsmeow) (Go)
- [Baileys](https://github.com/WhiskeySockets/Baileys) (TypeScript)
