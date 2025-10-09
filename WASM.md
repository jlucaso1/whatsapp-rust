# WebAssembly Support

## Current Status

The `whatsapp-rust` library has been refactored to support compilation to WebAssembly (WASM) targets. The key achievement is the **removal of C dependencies** (specifically `libsqlite3-sys` and Diesel) from the core library, which were previously blocking WASM compilation.

### What Works

✅ **Core Library Compilation**: The main `whatsapp-rust` library (without the `sqlite-storage` feature) compiles successfully for native targets without any C dependencies:

```bash
cargo build --lib --no-default-features
```

✅ **Storage Abstraction**: Storage backends are now fully pluggable via the `wacore::store::traits::Backend` trait, allowing you to provide WASM-compatible implementations (e.g., using IndexedDB or localStorage).

✅ **SQLite as Optional**: The SQLite storage backend is now in a separate crate (`whatsapp-rust-sqlite-storage`) and is only included when the `sqlite-storage` feature is enabled.

### What's Still Needed for Full WASM Support

The following components would need WASM-specific implementations:

1. **Random Number Generation**: The `rand` and `getrandom` crates need the `js` feature enabled for WASM. This can be configured in your project's `Cargo.toml`:
   ```toml
   [dependencies]
   getrandom = { version = "0.2", features = ["js"] }
   ```

2. **Transport Layer**: The default `whatsapp-rust-tokio-transport` uses Tokio and native TLS, which are not suitable for WASM. You would need to implement the `Transport` and `TransportFactory` traits using browser WebSocket APIs.

3. **HTTP Client**: The `whatsapp-rust-ureq-http-client` uses a native HTTP library. For WASM, you would implement the `HttpClient` trait using browser Fetch API.

4. **Storage Backend**: Provide a WASM-compatible storage implementation (e.g., using IndexedDB) by implementing the `Backend` trait.

### Example WASM Setup

Here's a conceptual example of what a WASM setup would look like:

```toml
# Cargo.toml for a WASM project
[dependencies]
whatsapp-rust = { version = "0.1", default-features = false }
getrandom = { version = "0.2", features = ["js"] }
wasm-bindgen = "0.2"
web-sys = { version = "0.3", features = ["WebSocket", "Window"] }
```

```rust
// Your WASM application code
use whatsapp_rust::bot::Bot;

// Implement WASM-specific components
let backend = WasmIndexedDBBackend::new().await?;
let transport_factory = BrowserWebSocketTransportFactory::new();
let http_client = BrowserFetchHttpClient::new();

let bot = Bot::builder()
    .with_backend(backend)
    .with_transport_factory(transport_factory)
    .with_http_client(http_client)
    .build()
    .await?;
```

## Benefits of This Refactoring

1. **No C Dependencies**: The core library is now free of C dependencies, which was the primary blocker for WASM compilation.

2. **Modular Architecture**: Storage, transport, and HTTP layers are all pluggable, making it easy to provide platform-specific implementations.

3. **Backward Compatibility**: The default build (with `sqlite-storage` feature) maintains full backward compatibility with existing code.

4. **Future-Proof**: The architecture is now ready for full WASM support once the WASM-specific transport, HTTP, and storage implementations are provided.

## Contributing WASM Implementations

If you're interested in creating WASM-compatible implementations of the transport, HTTP, or storage layers, please see the existing implementations in:

- `transports/tokio-transport/` - Reference implementation for Transport
- `http_clients/ureq-client/` - Reference implementation for HttpClient  
- `storages/sqlite-storage/` - Reference implementation for Backend

Your WASM implementations would follow the same trait-based patterns, using browser APIs instead of native libraries.
