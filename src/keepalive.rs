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

#[derive(Debug, PartialEq)]
enum KeepaliveResult {
    /// Server responded to the ping.
    Ok,
    /// Ping failed but the connection may recover (e.g. timeout, server error).
    TransientFailure,
    /// Connection is dead — loop should exit immediately.
    FatalFailure,
}

/// Classifies an IQ error into a keepalive result.
///
/// Fatal errors indicate the connection is already gone — there is no point
/// waiting for the 180 s grace window.  Transient errors (timeout, unexpected
/// server response) still count as failures but allow the grace window to
/// decide whether to force-reconnect.
fn classify_keepalive_error(e: &IqError) -> KeepaliveResult {
    match e {
        IqError::Socket(_)
        | IqError::Disconnected(_)
        | IqError::NotConnected
        | IqError::InternalChannelClosed => KeepaliveResult::FatalFailure,
        _ => KeepaliveResult::TransientFailure,
    }
}

impl Client {
    async fn send_keepalive(&self) -> KeepaliveResult {
        if !self.is_connected() {
            return KeepaliveResult::FatalFailure;
        }

        debug!(target: "Client/Keepalive", "Sending keepalive ping");

        match self
            .execute(KeepaliveSpec::with_timeout(KEEP_ALIVE_RESPONSE_DEADLINE))
            .await
        {
            Ok(()) => {
                debug!(target: "Client/Keepalive", "Received keepalive pong");
                KeepaliveResult::Ok
            }
            Err(e) => {
                let result = classify_keepalive_error(&e);
                warn!(target: "Client/Keepalive", "Keepalive ping failed: {e:?}");
                result
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

                    match self.send_keepalive().await {
                        KeepaliveResult::Ok => {
                            if error_count > 0 {
                                debug!(target: "Client/Keepalive", "Keepalive restored after {error_count} failure(s).");
                            }
                            error_count = 0;
                            last_success = chrono::Utc::now();
                        }
                        KeepaliveResult::FatalFailure => {
                            debug!(target: "Client/Keepalive", "Fatal keepalive failure, exiting loop.");
                            return;
                        }
                        KeepaliveResult::TransientFailure => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket::error::SocketError;
    use wacore_binary::builder::NodeBuilder;

    #[test]
    fn test_classify_timeout_is_transient() {
        assert_eq!(
            classify_keepalive_error(&IqError::Timeout),
            KeepaliveResult::TransientFailure,
            "Timeout should be transient — connection may recover"
        );
    }

    #[test]
    fn test_classify_not_connected_is_fatal() {
        assert_eq!(
            classify_keepalive_error(&IqError::NotConnected),
            KeepaliveResult::FatalFailure,
        );
    }

    #[test]
    fn test_classify_internal_channel_closed_is_fatal() {
        assert_eq!(
            classify_keepalive_error(&IqError::InternalChannelClosed),
            KeepaliveResult::FatalFailure,
        );
    }

    #[test]
    fn test_classify_socket_error_is_fatal() {
        assert_eq!(
            classify_keepalive_error(&IqError::Socket(SocketError::Crypto("test".to_string()))),
            KeepaliveResult::FatalFailure,
        );
    }

    #[test]
    fn test_classify_disconnected_is_fatal() {
        let node = NodeBuilder::new("disconnect").build();
        assert_eq!(
            classify_keepalive_error(&IqError::Disconnected(node)),
            KeepaliveResult::FatalFailure,
        );
    }

    #[test]
    fn test_classify_server_error_is_transient() {
        assert_eq!(
            classify_keepalive_error(&IqError::ServerError {
                code: 500,
                text: "internal".to_string()
            }),
            KeepaliveResult::TransientFailure,
            "ServerError should be transient — server may recover"
        );
    }
}
