# WhatsApp Rust WASM Signal Protocol

This repository implements a WebAssembly bridge for the Signal Protocol, allowing JavaScript/TypeScript applications to use the high-performance Rust-based Signal implementation from `wacore`.

## Architecture

```
┌─────────────────────┐    ┌──────────────────────┐    ┌─────────────────────┐
│   JavaScript App    │───▶│    WASM Bridge       │───▶│   Rust wacore       │
│                     │    │  (wacore-wasm)       │    │  Signal Protocol    │
│ SignalRepository    │    │  WasmSignalRepository│    │  SessionCipher,     │
│ Interface           │    │                      │    │  GroupCipher, etc.  │
└─────────────────────┘    └──────────────────────┘    └─────────────────────┘
```

## Implementation Status

### ✅ Completed
- [x] WASM crate structure (`wacore-wasm/`)
- [x] Basic WASM bindings with `wasm-bindgen`
- [x] TypeScript interface definitions (`src/Types/Signal.ts`)
- [x] JavaScript integration layer (`src/Signal/libsignal.ts`)
- [x] Build configuration with `wasm-pack`
- [x] Example key store implementation (`MemorySignalKeyStore`)
- [x] Demo HTML page for testing
- [x] Integration with existing workspace

### 🚧 In Progress (Stub Implementation)
- [x] `WasmSignalRepository` structure
- [x] Basic method signatures (`encryptMessage`, `decryptMessage`)
- [ ] Full Signal Protocol integration with `wacore/src/signal`
- [ ] JavaScript store trait bridge implementation
- [ ] Async promise handling for encryption/decryption
- [ ] Group messaging methods
- [ ] Session management methods

### 📋 Planned
- [ ] Complete `JsSignalStore` implementation with proper async trait bridging
- [ ] Full Signal Protocol method implementation in WASM
- [ ] Pre-key bundle processing
- [ ] Sender key distribution message handling
- [ ] Comprehensive error handling
- [ ] Performance optimization
- [ ] Browser and Node.js compatibility testing

## Building

### Prerequisites
```bash
# Install wasm-pack
cargo install wasm-pack

# Install Node.js dependencies (optional, for TypeScript)
npm install
```

### Build WASM Module
```bash
cd wacore-wasm
wasm-pack build --target web
```

### Build Entire Workspace
```bash
cargo build --workspace
```

### Run Tests
```bash
cargo test --workspace --exclude wacore-wasm
```

## Usage

### Basic Usage
```typescript
import { initSignalWasm, makeLibSignalRepository, MemorySignalKeyStore } from './src/Signal/libsignal.js';

// Initialize WASM module
await initSignalWasm();

// Create key store
const keyStore = new MemorySignalKeyStore();

// Create Signal repository
const signalRepo = makeLibSignalRepository(keyStore);

// Use the repository (currently returns "Not implemented yet")
const result = await signalRepo.encryptMessage("test@example.com", new TextEncoder().encode("Hello"));
```

### Demo
Open `demo.html` in a web browser to see the WASM integration in action.

## API Compatibility

The implementation maintains full compatibility with the `SignalRepository` interface defined in `src/Types/Signal.ts`, ensuring it can serve as a drop-in replacement for the existing JavaScript Signal Protocol implementation.

### Key Methods
- `encryptMessage(jid: string, plaintext: Uint8Array): Promise<EncryptResult>`
- `decryptMessage(jid: string, ciphertext: Uint8Array, messageType: number): Promise<DecryptResult>`
- `encryptGroupMessage(groupId: string, senderKeyId: string, plaintext: Uint8Array): Promise<EncryptResult>`
- `decryptGroupMessage(groupId: string, senderKeyId: string, ciphertext: Uint8Array): Promise<DecryptResult>`
- `injectE2ESession(jid: string, preKeyBundle: PreKeyBundle): Promise<void>`
- `processSenderKeyDistributionMessage(senderKeyId: string, distributionMessage: Uint8Array): Promise<void>`

## Files Structure

- `wacore-wasm/` - WASM bridge crate
  - `src/lib.rs` - Main WASM module with basic stubs
  - `src/store.rs` - JavaScript store trait implementations (placeholder)
  - `Cargo.toml` - WASM-specific dependencies
- `src/Types/Signal.ts` - TypeScript interface definitions
- `src/Signal/libsignal.ts` - JavaScript integration layer
- `demo.html` - Browser demo page
- `package.json` - NPM package configuration

## Performance Benefits

Once fully implemented, this WASM-based approach will provide:
- **Significant performance improvements** for CPU-intensive cryptographic operations
- **Memory efficiency** through Rust's zero-cost abstractions
- **Type safety** at the boundary between JavaScript and Rust
- **Consistent behavior** across different JavaScript environments

## Contributing

This is a foundational implementation that provides the structure for a complete WASM Signal Protocol bridge. The next steps involve implementing the actual Signal Protocol logic by integrating with the existing `wacore/src/signal` modules.