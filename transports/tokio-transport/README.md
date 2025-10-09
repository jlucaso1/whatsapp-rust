# whatsapp-rust-tokio-transport

Tokio-based WebSocket transport implementation for [whatsapp-rust](https://github.com/jlucaso1/whatsapp-rust).

## Overview

This crate provides a concrete implementation of the `Transport` and `TransportFactory` traits using `tokio-websockets`. It handles the WebSocket connection to WhatsApp servers and manages the binary frame protocol.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
whatsapp-rust = "0.1"
whatsapp-rust-tokio-transport = "0.1"
```

Then use it with the bot builder:

```rust
use whatsapp_rust::bot::Bot;
use whatsapp_rust::store::sqlite_store::SqliteStore;
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = Arc::new(SqliteStore::new("whatsapp.db").await?);
    let transport_factory = TokioWebSocketTransportFactory::new();

    let mut bot = Bot::builder()
        .with_backend(backend)
        .with_transport_factory(transport_factory)
        .build()
        .await?;

    bot.run().await?;
    Ok(())
}
```

## Features

- Async WebSocket connection using `tokio-websockets`
- Automatic frame assembly and disassembly
- TLS support via `rustls`
- Connection lifecycle management (Connected, Disconnected events)

## Custom Transport Implementations

You can implement your own transport by implementing the `Transport` and `TransportFactory` traits. This is useful for:

- Using different async runtimes (async-std, smol)
- Testing with mock transports
- Implementing custom protocols or proxies
- Compiling to WebAssembly with browser WebSocket APIs

See the main whatsapp-rust documentation for more details on implementing custom transports.

## License

MIT
