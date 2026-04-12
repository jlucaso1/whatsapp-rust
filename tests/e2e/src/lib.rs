use std::sync::Arc;

use wacore::store::traits::TcTokenEntry;
use wacore::types::events::{ChannelEventHandler, Event};
use wacore_binary::node::Node;
use whatsapp_rust::Jid;
use whatsapp_rust::bot::Bot;
use whatsapp_rust::store::traits::Backend;
use whatsapp_rust::waproto::whatsapp as wa;
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

pub fn unique_push_name(prefix: &str) -> String {
    format!("{}_{}", prefix, uuid::Uuid::new_v4())
}

pub fn restricted_push_name(prefix: &str) -> String {
    format!("restricted:{}", unique_push_name(prefix))
}

pub fn scenario_push_name(prefix: &str, flags: &[&str]) -> String {
    assert!(
        !flags.is_empty(),
        "scenario_push_name requires at least one flag"
    );
    format!("scenario:{}:{}", flags.join(","), unique_push_name(prefix))
}

/// A connected client ready for testing, with its event receiver and run handle.
pub struct TestClient {
    pub client: Arc<whatsapp_rust::client::Client>,
    pub event_rx: async_channel::Receiver<Arc<Event>>,
    pub run_handle: whatsapp_rust::bot::BotHandle,
}

impl TestClient {
    /// Create a client, connect to the mock server, and wait for PairSuccess + Connected.
    /// Returns the connected TestClient with its JID available via `client.get_pn()`.
    pub async fn connect(prefix: &str) -> anyhow::Result<Self> {
        Self::connect_inner(prefix, None).await
    }

    /// Connect with a specific push_name for deterministic phone assignment.
    ///
    /// Two clients with the same `push_name` will be paired to the same phone number
    /// with different device IDs, enabling multi-device testing.
    pub async fn connect_as(prefix: &str, push_name: &str) -> anyhow::Result<Self> {
        Self::connect_inner(prefix, Some(push_name.to_string())).await
    }

    async fn connect_inner(prefix: &str, push_name: Option<String>) -> anyhow::Result<Self> {
        let store = create_test_store(prefix).await?;
        let backend = Arc::new(store) as Arc<dyn Backend>;
        let transport_factory = TokioWebSocketTransportFactory::new().with_url(mock_server_url());
        let (event_handler, event_rx) = ChannelEventHandler::new();

        let mut builder = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport_factory)
            .with_http_client(UreqHttpClient::new())
            .with_runtime(whatsapp_rust::TokioRuntime)
            .with_version((2, 3000, 0));

        if let Some(name) = push_name {
            builder = builder.with_push_name(name);
        }

        let mut bot = builder.build().await?;

        let client = bot.client();
        client.register_handler(event_handler);
        let run_handle = bot.run().await?;

        // Wait for PairSuccess + Connected.
        //
        // PairSuccess arrives quickly (handshake only), but Connected is dispatched
        // only after the critical app-state sync completes (sync_collections_batched).
        // Under CI load with many concurrent clients, the mock server may be slow to
        // serve app-state IQs, so Connected can take significantly longer than pairing.
        //
        // We use a two-phase timeout: 30s for pairing, then an additional 30s for
        // Connected (which includes critical sync). This avoids a single shared timeout
        // where a slow sync eats into the pairing budget.
        let timeout = tokio::time::Duration::from_secs(30);
        let mut got_pair = false;
        let mut got_connected = false;

        let wait_result = tokio::time::timeout(timeout, async {
            loop {
                match event_rx.recv().await {
                    Ok(ref event) if matches!(**event, Event::PairSuccess(_)) => {
                        got_pair = true;
                        if got_connected {
                            break;
                        }
                    }
                    Ok(ref event) if matches!(**event, Event::Connected(_)) => {
                        got_connected = true;
                        if got_pair {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        return Err(anyhow::anyhow!("Event channel closed during connect: {e}"));
                    }
                }
            }
            Ok(())
        })
        .await;

        match wait_result {
            Err(_) => {
                // If we got PairSuccess but not Connected, the critical sync is slow.
                // Give it extra time via wait_for_startup_sync instead of failing immediately.
                if got_pair && !got_connected {
                    eprintln!(
                        "WARN: Got PairSuccess but Connected timed out after {timeout:?}, \
                         waiting for startup sync..."
                    );
                    if let Err(e) = client
                        .wait_for_startup_sync(tokio::time::Duration::from_secs(30))
                        .await
                    {
                        client.disconnect().await;
                        drop(run_handle);
                        return Err(anyhow::anyhow!(
                            "Timed out waiting for Connected after PairSuccess: {e}"
                        ));
                    }
                    // Drain the Connected event that should now be available
                    let connected_timeout = tokio::time::Duration::from_secs(5);
                    let _ = tokio::time::timeout(connected_timeout, async {
                        loop {
                            match event_rx.recv().await {
                                Ok(ref event) if matches!(**event, Event::Connected(_)) => break,
                                Ok(_) => continue,
                                Err(_) => break,
                            }
                        }
                    })
                    .await;
                } else {
                    client.disconnect().await;
                    drop(run_handle);
                    return Err(anyhow::anyhow!(
                        "Timed out waiting for PairSuccess + Connected \
                         (got_pair={got_pair}, got_connected={got_connected})"
                    ));
                }
            }
            Ok(Err(e)) => {
                client.disconnect().await;
                drop(run_handle);
                return Err(e);
            }
            Ok(Ok(())) => {}
        }

        if let Err(e) = client
            .wait_for_startup_sync(tokio::time::Duration::from_secs(15))
            .await
        {
            client.disconnect().await;
            drop(run_handle);
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

    // ── JID helpers ─────────────────────────────────────────────────────────

    /// Get this client's phone number JID (non-AD format).
    pub async fn jid(&self) -> Jid {
        self.client
            .get_pn()
            .await
            .expect("Client should have a JID after connect")
            .to_non_ad()
    }

    /// Get the storage key used for this client's tcToken entries.
    ///
    /// Notification handling stores tcTokens under the sender's LID when it is
    /// available, otherwise it falls back to the phone-number user part.
    pub async fn tc_token_key(&self) -> anyhow::Result<String> {
        if let Some(lid) = self.client.get_lid().await {
            return Ok(lid.user.to_string());
        }

        self.client
            .get_pn()
            .await
            .map(|jid| jid.user.to_string())
            .ok_or_else(|| anyhow::anyhow!("Client should have a JID after connect"))
    }

    /// Wait until a tcToken entry exists for the given storage key.
    pub async fn wait_for_tc_token(
        &self,
        jid_key: &str,
        timeout_secs: u64,
    ) -> anyhow::Result<TcTokenEntry> {
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_secs);

        loop {
            if let Some(entry) = self.client.tc_token().get(jid_key).await? {
                return Ok(entry);
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(anyhow::anyhow!(
                    "Timed out waiting for tc_token entry for {}",
                    jid_key
                ));
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
    }

    pub fn sent_message_waiter(
        &self,
        msg_id: &str,
    ) -> futures::channel::oneshot::Receiver<Arc<Node>> {
        self.client
            .wait_for_sent_node(whatsapp_rust::NodeFilter::tag("message").attr("id", msg_id))
    }

    pub fn next_sent_message_waiter(&self) -> futures::channel::oneshot::Receiver<Arc<Node>> {
        self.client
            .wait_for_sent_node(whatsapp_rust::NodeFilter::tag("message"))
    }

    pub async fn nct_salt(&self) -> Option<Vec<u8>> {
        self.client
            .persistence_manager()
            .get_device_snapshot()
            .await
            .nct_salt
            .clone()
    }

    pub async fn wait_for_nct_salt(&self, timeout_secs: u64) -> anyhow::Result<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_secs);

        loop {
            if let Some(salt) = self.nct_salt().await {
                return Ok(salt);
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(anyhow::anyhow!("Timed out waiting for NCT salt"));
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
    }

    // ── Event waiting ───────────────────────────────────────────────────────

    /// Wait for an event matching the predicate, with a timeout in seconds.
    pub async fn wait_for_event<F>(
        &mut self,
        timeout_secs: u64,
        mut predicate: F,
    ) -> anyhow::Result<Arc<Event>>
    where
        F: FnMut(&Event) -> bool,
    {
        let timeout = tokio::time::Duration::from_secs(timeout_secs);
        tokio::time::timeout(timeout, async {
            loop {
                match self.event_rx.recv().await {
                    Ok(event) if predicate(&event) => return Ok(event),
                    Ok(_) => continue,
                    Err(e) => return Err(anyhow::anyhow!("Event channel closed: {e}")),
                }
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for event"))?
    }

    /// Wait for a text message with specific content.
    pub async fn wait_for_text(
        &mut self,
        text: &str,
        timeout_secs: u64,
    ) -> anyhow::Result<Arc<Event>> {
        let text = text.to_string();
        self.wait_for_event(timeout_secs, move |e| {
            e.message_text() == Some(text.as_str())
        })
        .await
    }

    /// Wait for a text message on a specific group.
    pub async fn wait_for_group_text(
        &mut self,
        group_jid: &Jid,
        text: &str,
        timeout_secs: u64,
    ) -> anyhow::Result<Arc<Event>> {
        let gid = group_jid.clone();
        let text = text.to_string();
        self.wait_for_event(timeout_secs, move |e| {
            matches!(
                e,
                Event::Message(msg, info)
                if info.source.chat == gid
                    && msg.conversation.as_deref() == Some(text.as_str())
            )
        })
        .await
    }

    /// Wait for a w:gp2 group notification.
    pub async fn wait_for_group_notification(
        &mut self,
        timeout_secs: u64,
    ) -> anyhow::Result<Arc<Event>> {
        self.wait_for_event(timeout_secs, |e| {
            matches!(e, Event::Notification(node) if node.get().get_attr("type").is_some_and(|v| v.as_str() == "w:gp2"))
        })
        .await
    }

    /// Assert that NO event matching the predicate arrives within the timeout.
    /// Returns Ok(()) if the wait times out (expected), panics if an event arrives.
    pub async fn assert_no_event<F>(
        &mut self,
        timeout_secs: u64,
        predicate: F,
        context: &str,
    ) -> anyhow::Result<()>
    where
        F: FnMut(&Event) -> bool,
    {
        let result = self.wait_for_event(timeout_secs, predicate).await;
        match result {
            Ok(event) => panic!("{context}: expected no event but got: {event:?}"),
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("Timed out"),
                    "{context}: expected timeout error, got: {msg}"
                );
                Ok(())
            }
        }
    }

    /// Wait for initial app state sync to complete (keys become available).
    pub async fn wait_for_app_state_sync(&mut self) -> anyhow::Result<()> {
        let push_name = self.client.get_push_name().await;
        if !push_name.is_empty() {
            return Ok(());
        }
        self.wait_for_event(10, |e| matches!(e, Event::SelfPushNameUpdated(_)))
            .await?;
        Ok(())
    }

    // ── Connection lifecycle ────────────────────────────────────────────────

    /// Reconnect and wait for the Connected event.
    pub async fn reconnect_and_wait(&mut self) -> anyhow::Result<()> {
        // Drain any buffered Connected events from prior connections
        while let Ok(event) = self.event_rx.try_recv() {
            if matches!(&*event, Event::Connected(_)) {
                continue;
            }
        }
        self.client.reconnect().await;
        self.wait_for_event(10, |e| matches!(e, Event::Connected(_)))
            .await?;
        Ok(())
    }

    /// Disconnect and wait for the run task to complete cleanly.
    pub async fn disconnect(self) {
        self.client.disconnect().await;
        let run_handle = self.run_handle;

        match tokio::time::timeout(tokio::time::Duration::from_secs(5), run_handle).await {
            Ok(_) => {}
            Err(_) => {
                eprintln!("WARN: timed out waiting for client run task shutdown");
                // BotHandle's Drop aborts the task automatically
            }
        }
    }
}

// ── Free-standing test helpers ──────────────────────────────────────────────

/// Build a simple text message.
pub fn text_msg(text: &str) -> wa::Message {
    wa::Message {
        conversation: Some(text.to_string()),
        ..Default::default()
    }
}

/// Send a text message and wait for the receiver to get it. Returns the message ID.
pub async fn send_and_expect_text(
    sender: &whatsapp_rust::client::Client,
    receiver: &mut TestClient,
    to: &Jid,
    text: &str,
    timeout_secs: u64,
) -> anyhow::Result<String> {
    let result = sender.send_message(to.clone(), text_msg(text)).await?;
    receiver.wait_for_text(text, timeout_secs).await?;
    Ok(result.message_id)
}
