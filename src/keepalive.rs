use crate::binary::node::{Node, NodeContent};
use crate::client::Client;
use crate::request::{InfoQuery, InfoQueryType, IqError};
use crate::types::jid::SERVER_JID;
use log::{debug, info, warn};
use rand::Rng;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

// Constants ported from whatsmeow/keepalive.go
const KEEP_ALIVE_INTERVAL_MIN: Duration = Duration::from_secs(20);
const KEEP_ALIVE_INTERVAL_MAX: Duration = Duration::from_secs(30);
const KEEP_ALIVE_MAX_FAIL_TIME: Duration = Duration::from_secs(180); // 3 minutes
const KEEP_ALIVE_RESPONSE_DEADLINE: Duration = Duration::from_secs(20);

impl Client {
    /// Sends a single keepalive ping and waits for a pong.
    /// Returns true on success, false on failure.
    async fn send_keepalive(&self) -> bool {
        if !self.is_connected() {
            return false;
        }

        info!(target: "Client/Keepalive", "Sending keepalive ping");

        let iq = InfoQuery {
            namespace: "w:p",
            query_type: InfoQueryType::Get,
            to: SERVER_JID.parse().unwrap(),
            target: None,
            id: None,
            content: Some(NodeContent::Nodes(vec![Node {
                tag: "ping".to_string(),
                ..Default::default()
            }])),
            timeout: Some(KEEP_ALIVE_RESPONSE_DEADLINE),
        };

        match self.send_iq(iq).await {
            Ok(_) => {
                debug!(target: "Client/Keepalive", "Received keepalive pong");
                true
            }
            Err(e) => {
                warn!(target: "Client/Keepalive", "Keepalive ping failed: {e:?}");
                !matches!(e, IqError::Socket(_) | IqError::Disconnected(_))
            }
        }
    }

    /// The main keepalive loop. This should be spawned as a background task.
    pub(crate) async fn keepalive_loop(self: Arc<Self>) {
        let mut last_success = chrono::Utc::now();
        let mut error_count = 0u32;

        loop {
            let interval_ms = rand::thread_rng().gen_range(
                KEEP_ALIVE_INTERVAL_MIN.as_millis()..=KEEP_ALIVE_INTERVAL_MAX.as_millis(),
            );
            let interval = Duration::from_millis(interval_ms as u64);

            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    if !self.is_connected() {
                        debug!(target: "Client/Keepalive", "Not connected, exiting keepalive loop.");
                        return;
                    }

                    let is_success = self.send_keepalive().await;

                    if is_success {
                        if error_count > 0 {
                            info!(target: "Client/Keepalive", "Keepalive restored.");
                        }
                        error_count = 0;
                        last_success = chrono::Utc::now();
                    } else {
                        error_count += 1;
                        warn!(target: "Client/Keepalive", "Keepalive timeout, error count: {error_count}");

                        // If auto-reconnect is enabled and we haven't had a successful ping in a while,
                        // force a disconnect so the main `run` loop can handle reconnecting.
                        if self.enable_auto_reconnect.load(Ordering::Relaxed)
                            && chrono::Utc::now().signed_duration_since(last_success)
                                > chrono::Duration::from_std(KEEP_ALIVE_MAX_FAIL_TIME).unwrap()
                        {
                            warn!(target: "Client/Keepalive", "Forcing reconnect due to keepalive failure for over {} seconds.", KEEP_ALIVE_MAX_FAIL_TIME.as_secs());
                            self.disconnect().await;
                            // The main run loop will handle the reconnect logic.
                            return;
                        }
                    }
                },
                _ = self.shutdown_notifier.notified() => {
                    debug!(target: "Client/Keepalive", "Shutdown signaled, exiting keepalive loop.");
                    return;
                }
            }
        }
    }
}
