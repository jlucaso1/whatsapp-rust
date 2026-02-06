use crate::client::Client;
use crate::request::IqError;
use log::{debug, warn};
use rand::Rng;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use wacore::iq::keepalive::KeepaliveSpec;

const KEEP_ALIVE_INTERVAL_MIN: Duration = Duration::from_secs(20);
const KEEP_ALIVE_INTERVAL_MAX: Duration = Duration::from_secs(30);
const KEEP_ALIVE_MAX_FAIL_TIME: Duration = Duration::from_secs(180);
const KEEP_ALIVE_RESPONSE_DEADLINE: Duration = Duration::from_secs(20);

impl Client {
    async fn send_keepalive(&self) -> bool {
        if !self.is_connected() {
            return false;
        }

        debug!(target: "Client/Keepalive", "Sending keepalive ping");

        match self
            .execute(KeepaliveSpec::with_timeout(KEEP_ALIVE_RESPONSE_DEADLINE))
            .await
        {
            Ok(()) => {
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
            let interval_ms = rand::rng().random_range(
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
                            debug!(target: "Client/Keepalive", "Keepalive restored.");
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
