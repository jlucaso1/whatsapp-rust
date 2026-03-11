# E2E Testing Best Practices

E2E tests live in `tests/e2e/` and run against a mock WhatsApp server. They test real connection flows, encryption, and event delivery.

## Test Infrastructure

- **`tests/e2e/src/lib.rs`**: `TestClient` helper — connects to mock server, waits for pairing + sync, provides event-based assertions.
- Each test creates isolated in-memory SQLite DBs (UUID-based), so tests have no shared state.
- Tests across files run **in parallel**; tests within a file run **sequentially**.

## File Organization for Parallelism

Split test files by domain so they run concurrently. Cargo runs each test binary (file) in parallel, but tests within a binary run sequentially. A single large file becomes the bottleneck.

```
tests/e2e/tests/
├── chat_actions.rs      # Pin, mute, archive, star
├── connection.rs        # Connect, reconnect
├── groups.rs            # Group CRUD, admin, settings
├── media.rs             # Upload, download, send media
├── messaging.rs         # Send/receive text messages
├── chatstate_ttl.rs     # Chatstate TTL expiry (35s sleep — own file for parallelism)
├── offline_groups.rs    # Offline group notifications
├── offline_messages.rs  # Offline message queuing + delivery
├── offline_receipts.rs  # Offline receipt + presence delivery
├── presence.rs          # Typing indicators, availability
├── profile.rs           # Push name, status text
├── profile_picture.rs   # Profile picture CRUD
└── receipts.rs          # Online receipt routing
```

When adding new tests, place them in the file matching their domain. If a file grows beyond ~10-15 tests, consider splitting further.

## Event-Driven Waiting (Preferred)

Use `wait_for_event()` with predicates instead of arbitrary sleeps. This is both faster and more reliable:

```rust
// GOOD: event-driven — returns as soon as the event arrives
let event = client_b
    .wait_for_event(15, |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some("hello")))
    .await?;

// BAD: arbitrary sleep — wastes time or causes flaky failures
tokio::time::sleep(Duration::from_secs(2)).await;
```

Reference: `groups.rs` uses zero sleeps and runs at ~2.2s/test. Follow this pattern for new tests.

## Offline Testing Pattern

When testing offline event delivery, use short sleeps (100ms) after `reconnect()` or `disconnect()` to let the server detect the TCP close. Localhost connections close nearly instantly:

```rust
// Client goes offline (triggers auto-reconnect in background)
client_b.client.reconnect().await;
tokio::time::sleep(Duration::from_millis(100)).await;

// Now send while client is offline — server queues it
client_a.client.send_message(jid_b.clone(), message).await?;

// Client reconnects automatically and receives from offline queue
let event = client_b.wait_for_event(30, |e| matches!(e, Event::Message(..))).await?;
```

For full disconnects (no auto-reconnect):
```rust
client_b.disconnect().await;
tokio::time::sleep(Duration::from_millis(100)).await;
```

## `reconnect_and_wait()` Helper

Use `TestClient::reconnect_and_wait()` when you need the client back online (not testing offline behavior):

```rust
// Reconnects and waits for Connected event — no arbitrary sleep needed
client_b.reconnect_and_wait().await?;
```

Do NOT use this for offline tests — it waits for the client to be back online, defeating the purpose.

## Timeout Guidelines

- **Event waits in online flows**: 10-15s (events arrive in <1s normally)
- **Event waits after offline reconnect**: 30s (reconnect + offline queue drain)
- **Negative assertions** (event should NOT arrive): 3-5s
- **Post-disconnect sleeps**: 100ms (TCP close detection)
- **Sequential processing delays**: 50ms (ensure server ordering)

## Writing New E2E Tests

1. Use `TestClient::connect("unique_prefix")` with a unique prefix per client per test.
2. Use `wait_for_event()` for all assertions — avoid polling or sleeping.
3. Always call `disconnect()` on all clients at the end (cleanup).
4. Return `anyhow::Result<()>` for clean error propagation.
5. Use `env_logger` for debug output: `let _ = env_logger::builder().is_test(true).try_init();`
