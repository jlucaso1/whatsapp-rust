use std::sync::Arc;

use wacore::types::events::{Event, EventHandler};
use whatsapp_rust::bot::Bot;
use whatsapp_rust::store::traits::Backend;
use whatsapp_rust_sqlite_storage::SqliteStore;
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use whatsapp_rust_ureq_http_client::UreqHttpClient;

/// Creates a SqliteStore with a unique in-memory database for test isolation.
pub async fn create_test_store(prefix: &str) -> anyhow::Result<SqliteStore> {
    let db = format!(
        "file:{}_{}?mode=memory&cache=shared",
        prefix,
        uuid::Uuid::new_v4()
    );
    Ok(SqliteStore::new(&db).await?)
}

/// Returns the mock server WebSocket URL from env, or the default.
pub fn mock_server_url() -> String {
    std::env::var("MOCK_SERVER_URL").unwrap_or_else(|_| "wss://127.0.0.1:8080/ws/chat".to_string())
}

/// Event handler that sends events to a tokio broadcast channel for test assertions.
pub struct ChannelEventHandler {
    tx: tokio::sync::broadcast::Sender<Event>,
}

impl ChannelEventHandler {
    pub fn new() -> (Arc<Self>, tokio::sync::broadcast::Receiver<Event>) {
        let (tx, rx) = tokio::sync::broadcast::channel(1000);
        (Arc::new(Self { tx }), rx)
    }
}

impl EventHandler for ChannelEventHandler {
    fn handle_event(&self, event: &Event) {
        let _ = self.tx.send(event.clone());
    }
}

/// A connected client ready for testing, with its event receiver and run handle.
pub struct TestClient {
    pub client: Arc<whatsapp_rust::client::Client>,
    pub event_rx: tokio::sync::broadcast::Receiver<Event>,
    pub run_handle: tokio::task::JoinHandle<()>,
}

impl TestClient {
    /// Create a client, connect to the mock server, and wait for PairSuccess + Connected.
    /// Returns the connected TestClient with its JID available via `client.get_pn()`.
    pub async fn connect(prefix: &str) -> anyhow::Result<Self> {
        let store = create_test_store(prefix).await?;
        let backend = Arc::new(store) as Arc<dyn Backend>;
        let transport_factory = TokioWebSocketTransportFactory::new().with_url(mock_server_url());
        let (event_handler, mut event_rx) = ChannelEventHandler::new();

        let mut bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport_factory)
            .with_http_client(UreqHttpClient::new())
            .build()
            .await?;

        let client = bot.client();
        client.register_handler(event_handler);
        let run_handle = bot.run().await?;

        // Wait for PairSuccess + Connected
        let timeout = tokio::time::Duration::from_secs(30);
        let mut got_pair = false;
        let mut got_connected = false;

        let wait_result = tokio::time::timeout(timeout, async {
            loop {
                match event_rx.recv().await {
                    Ok(Event::PairSuccess(_)) => {
                        got_pair = true;
                        if got_connected {
                            break;
                        }
                    }
                    Ok(Event::Connected(_)) => {
                        got_connected = true;
                        if got_pair {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!(
                            "WARN: Event channel lagged during connect, {} messages dropped",
                            n
                        );
                        continue;
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("Event channel error during connect: {e}"));
                    }
                }
            }
            Ok(())
        })
        .await;

        match wait_result {
            Err(_) => {
                client.disconnect().await;
                run_handle.abort();
                return Err(anyhow::anyhow!(
                    "Timed out waiting for PairSuccess + Connected"
                ));
            }
            Ok(Err(e)) => {
                client.disconnect().await;
                run_handle.abort();
                return Err(e);
            }
            Ok(Ok(())) => {}
        }

        assert!(got_pair, "Should have received PairSuccess");
        assert!(got_connected, "Should have received Connected");

        if let Err(e) = client
            .wait_for_startup_sync(tokio::time::Duration::from_secs(15))
            .await
        {
            client.disconnect().await;
            run_handle.abort();
            let _ = run_handle.await;
            return Err(anyhow::anyhow!(
                "Timed out waiting for startup sync to become idle: {e}"
            ));
        }

        Ok(Self {
            client,
            event_rx,
            run_handle,
        })
    }

    /// Wait for an event matching the predicate, with a timeout in seconds.
    pub async fn wait_for_event<F>(
        &mut self,
        timeout_secs: u64,
        mut predicate: F,
    ) -> anyhow::Result<Event>
    where
        F: FnMut(&Event) -> bool,
    {
        let timeout = tokio::time::Duration::from_secs(timeout_secs);
        tokio::time::timeout(timeout, async {
            loop {
                match self.event_rx.recv().await {
                    Ok(event) if predicate(&event) => return Ok(event),
                    Ok(_) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("WARN: Event channel lagged, {} messages dropped", n);
                        // Continue receiving — the event may still arrive
                        continue;
                    }
                    Err(e) => return Err(anyhow::anyhow!("Event channel error: {e}")),
                }
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for event"))?
    }

    /// Wait for initial app state sync to complete (keys become available).
    ///
    /// The `SelfPushNameUpdated` event fires during critical_block sync, which
    /// completes before `Connected` is dispatched. Since `connect()` waits for
    /// `Connected`, the push name is already set when this method is called.
    /// We verify this by checking the push name state directly.
    pub async fn wait_for_app_state_sync(&mut self) -> anyhow::Result<()> {
        // Push name is set during critical_block sync, which completes before
        // Connected (which connect() already waited for). Check state directly.
        let push_name = self.client.get_push_name().await;
        if !push_name.is_empty() {
            return Ok(());
        }
        // Fallback: wait for the event if push name isn't set yet
        self.wait_for_event(10, |e| matches!(e, Event::SelfPushNameUpdated(_)))
            .await?;
        Ok(())
    }

    /// Reconnect and wait for the Connected event (replaces sleep-based waiting).
    ///
    /// Drains any stale Connected events from the broadcast channel before
    /// triggering reconnect, so only the new Connected event is matched.
    pub async fn reconnect_and_wait(&mut self) -> anyhow::Result<()> {
        // Drain any buffered Connected events from prior connections
        while let Ok(event) = self.event_rx.try_recv() {
            if matches!(event, Event::Connected(_)) {
                continue;
            }
        }
        self.client.reconnect().await;
        self.wait_for_event(10, |e| matches!(e, Event::Connected(_)))
            .await?;
        Ok(())
    }

    /// Disconnect and abort the run handle.
    pub async fn disconnect(self) {
        self.client.disconnect().await;
        let mut run_handle = self.run_handle;

        match tokio::time::timeout(tokio::time::Duration::from_secs(5), &mut run_handle).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) if e.is_cancelled() => {}
            Ok(Err(e)) => {
                eprintln!("WARN: client run task finished with error during disconnect: {e}");
            }
            Err(_) => {
                eprintln!("WARN: timed out waiting for client run task shutdown; aborting");
                run_handle.abort();
                let _ = run_handle.await;
            }
        }
    }
}
