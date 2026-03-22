# WhatsApp-Rust

Rust implementation of the WhatsApp protocol, inspired by **whatsmeow** (Go), **Baileys** (TypeScript), and real **WhatsApp Web** behavior. Covers QR pairing, E2E encrypted messaging (1-on-1 + group), media upload/download, and connection management.

## Crate Structure

- **wacore** — Platform-agnostic core: binary protocol, crypto, IQ types, state traits. No Tokio dependency.
- **waproto** — Protobuf definitions (`whatsapp.proto`) compiled via prost. No feature logic here.
- **whatsapp-rust** — Main client: Tokio runtime, SQLite persistence (Diesel), high-level API.

## Build & Verify

```bash
cargo fmt --all
cargo clippy --all --tests
cargo test --all
cargo test -p e2e-tests          # requires mock server running
```

## Rust Style

- **Collapsible if**: Always use let-chains (`if let Some(x) = foo && let Some(y) = x.bar { ... }`) instead of nested `if let` blocks. Clippy's `collapsible_if` lint will reject the nested form.
- **No real PII in tests**: Use fictitious phone numbers and JIDs in test code. Never commit real user numbers.

## Critical Conventions

- **State**: Never modify Device state directly. Use `DeviceCommand` + `PersistenceManager::process_command()`. Read via `get_device_snapshot()`.
- **Async**: All I/O uses Tokio. Wrap blocking I/O (`ureq`) and heavy CPU work in `tokio::task::spawn_blocking`.
- **Concurrency**: Use `Client::chat_locks` to serialize per-chat operations.
- **Errors**: `thiserror` for typed errors, `anyhow` for multi-failure functions. No `.unwrap()` outside tests.
- **Protocol**: Cross-reference **whatsmeow**, **Baileys**, and captured WhatsApp Web JS (`docs/captured-js/`) to verify implementations.
- **IQ Requests**: Use `client.execute(Spec::new(&jid)).await?` pattern. IqSpec constructors take `&Jid` not `Jid`.
- **New features**: Expose via `src/features/mod.rs`, re-export in `src/lib.rs`.

## Detailed Docs

Read these when working on the relevant area:

- `agent_docs/protocol_architecture.md` — ProtocolNode, IqSpec, derive macros, node parsing
- `agent_docs/feature_implementation.md` — Step-by-step feature implementation flow
- `agent_docs/e2e_testing.md` — E2E test patterns, file organization, event-driven waiting
- `agent_docs/debugging.md` — evcxr REPL, binary protocol debugging
