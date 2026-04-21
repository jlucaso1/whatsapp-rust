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
- **Concurrency**: `session_locks` serializes per-sender Signal encrypt/decrypt. `message_enqueue_locks` serializes per-chat incoming message processing. Outgoing sends are not per-chat locked (matches WA Web).
- **Errors**: `thiserror` for typed errors, `anyhow` for multi-failure functions. No `.unwrap()` outside tests.
- **Protocol**: Cross-reference **whatsmeow**, **Baileys**, and captured WhatsApp Web JS (`docs/captured-js/`) to verify implementations.
- **IQ Requests**: Use `client.execute(Spec::new(&jid)).await?` pattern. IqSpec constructors take `&Jid` not `Jid`.
- **New features**: Expose via `src/features/mod.rs`, re-export in `src/lib.rs`.
- **Wire-tagged enums**: Every protocol enum uses `#[derive(WireEnum)]`. The `#[wire = "..."]` (or `#[wire = NUM]` for int mode) attribute is the SINGLE source of truth for each variant's wire value. Do NOT also derive `serde::Serialize`/`Deserialize` or add `#[serde(rename_all)]` — the derive owns both. Three modes: unit-string (default), tagged-with-payload (`#[wire(tag = "type")]` on the enum, optional `#[wire_alias = "..."]` and `#[wire(skip)]` on fields, `#[wire_fallback]` for catch-all), and int (`#[wire(kind = "int")]`). In tagged mode the derive auto-generates a sibling `<Name>Tag` enum; parsers must dispatch via `<Name>Tag::try_from(node.tag.as_ref())` instead of matching string literals, so renaming a wire tag stays a single-attribute change.

## Detailed Docs

Read these when working on the relevant area:

- `agent_docs/protocol_architecture.md` — ProtocolNode, IqSpec, derive macros, node parsing
- `agent_docs/feature_implementation.md` — Step-by-step feature implementation flow
- `agent_docs/e2e_testing.md` — E2E test patterns, file organization, event-driven waiting
- `agent_docs/debugging.md` — evcxr REPL, binary protocol debugging

When adding comments to the code, dont be so verbose, also only explain why, not what
