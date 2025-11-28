use crate::client::Client;
use crate::jid_utils::server_jid;
use crate::request::{InfoQuery, InfoQueryType, IqError};
use log::{debug, info, warn};
use rand_core::{OsRng, TryRngCore};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::node::NodeContent;

const KEEP_ALIVE_INTERVAL_MIN: Duration = Duration::from_secs(20);
const KEEP_ALIVE_INTERVAL_MAX: Duration = Duration::from_secs(30);
const KEEP_ALIVE_MAX_FAIL_TIME: Duration = Duration::from_secs(180);
const KEEP_ALIVE_RESPONSE_DEADLINE: Duration = Duration::from_secs(20);

impl Client {
    async fn send_keepalive(&self) -> bool {
        if !self.is_connected() {
            return false;
        }

        info!(target: "Client/Keepalive", "Sending keepalive ping");

        let iq = InfoQuery {
            namespace: "w:p",
            query_type: InfoQueryType::Get,
            to: server_jid(),
            target: None,
            id: None,
            content: Some(NodeContent::Nodes(vec![NodeBuilder::new("ping").build()])),
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

    pub(crate) async fn keepalive_loop(self: Arc<Self>) {
        let mut last_success = chrono::Utc::now();
        let mut error_count = 0u32;

        loop {
            let mut rng = OsRng;
            let interval_ms = random_keepalive_interval_ms(&mut rng);
            let interval = Duration::from_millis(interval_ms);

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

                        if self.enable_auto_reconnect.load(Ordering::Relaxed)
                            && chrono::Utc::now().signed_duration_since(last_success)
                                > chrono::Duration::from_std(KEEP_ALIVE_MAX_FAIL_TIME)
                                    .expect("KEEP_ALIVE_MAX_FAIL_TIME fits in chrono::Duration")
                        {
                            warn!(target: "Client/Keepalive", "Forcing reconnect due to keepalive failure for over {} seconds.", KEEP_ALIVE_MAX_FAIL_TIME.as_secs());
                            self.disconnect().await;
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

fn random_keepalive_interval_ms(rng: &mut OsRng) -> u64 {
    let min = u64::try_from(KEEP_ALIVE_INTERVAL_MIN.as_millis()).expect("min interval fits in u64");
    let max = u64::try_from(KEEP_ALIVE_INTERVAL_MAX.as_millis()).expect("max interval fits in u64");
    let span = max - min + 1;
    let rejection_zone = u64::MAX - u64::MAX % span;
    loop {
        let sample = rng
            .try_next_u64()
            .expect("failed to sample keepalive interval");
        if sample < rejection_zone {
            return min + (sample % span);
        }
    }
}
