use crate::client::Client;
use crate::request::IqError;
use futures::FutureExt;
use log::{debug, warn};
use rand::RngExt;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use wacore::iq::spec::IqSpec;
use wacore::protocol::keepalive::{
    KEEP_ALIVE_INTERVAL_MAX, KEEP_ALIVE_INTERVAL_MIN, KEEP_ALIVE_RESPONSE_DEADLINE, is_dead_socket,
    ms_since,
};

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
/// waiting for the grace window.  Transient errors (timeout, unexpected
/// server response) still count as failures but allow the grace window to
/// decide whether to force-reconnect.
fn classify_keepalive_error(e: &IqError) -> KeepaliveResult {
    match e {
        IqError::Socket(_)
        | IqError::Disconnected(_)
        | IqError::NotConnected
        | IqError::InternalChannelClosed => KeepaliveResult::FatalFailure,
        // Exhaustive: forces a compile error when new IqError variants are added
        // so the developer must decide the classification.
        IqError::Timeout | IqError::ServerError { .. } | IqError::ParseError(_) => {
            KeepaliveResult::TransientFailure
        }
    }
}

impl Client {
    /// Sends a keepalive ping and updates the server time offset from
    /// the pong's `t` attribute using RTT-adjusted midpoint calculation.
    ///
    /// WA Web: `sendPing` → `onClockSkewUpdate(Math.round((start + rtt/2) / 1000 - serverTime))`
    async fn send_keepalive(&self) -> KeepaliveResult {
        if !self.is_connected() {
            return KeepaliveResult::FatalFailure;
        }

        // WA Web: skip ping if there are pending IQs
        // (`activePing || ackHandlers.length || pendingIqs.size`)
        let has_pending = !self.response_waiters.lock().await.is_empty();
        if has_pending {
            debug!(target: "Client/Keepalive", "Skipping ping: IQ responses pending");
            return KeepaliveResult::Ok;
        }

        debug!(target: "Client/Keepalive", "Sending keepalive ping");

        let start_ms = wacore::time::now_millis();
        let iq = wacore::iq::keepalive::KeepaliveSpec::with_timeout(KEEP_ALIVE_RESPONSE_DEADLINE)
            .build_iq();
        match self.send_iq(iq).await {
            Ok(response_node) => {
                let end_ms = wacore::time::now_millis();
                let rtt_ms = end_ms - start_ms;
                debug!(target: "Client/Keepalive", "Received keepalive pong (RTT: {rtt_ms}ms)");
                // WA Web: onClockSkewUpdate — Math.round((startTime + rtt/2) / 1000 - serverTime)
                self.unified_session.update_server_time_offset_with_rtt(
                    response_node.get(),
                    start_ms,
                    rtt_ms,
                );
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
        let mut error_count = 0u32;
        let mut cleanup_counter = 0u32;
        let sent_msg_ttl = self.cache_config.sent_message_ttl_secs;

        loop {
            // Register the shutdown listener BEFORE calculating the sleep
            // duration so we never miss a notification between loop iterations.
            let shutdown = self.shutdown_notifier.listen();

            let interval_ms = rand::make_rng::<rand::rngs::StdRng>().random_range(
                KEEP_ALIVE_INTERVAL_MIN.as_millis()..=KEEP_ALIVE_INTERVAL_MAX.as_millis(),
            );
            let interval = Duration::from_millis(interval_ms as u64);

            futures::select! {
                _ = self.runtime.sleep(interval).fuse() => {
                    if !self.is_connected() {
                        debug!(target: "Client/Keepalive", "Not connected, exiting keepalive loop.");
                        return;
                    }

                    let last_recv = self.last_data_received_ms.load(Ordering::Relaxed);

                    // WA Web: maybeScheduleHealthCheck — only send ping when idle.
                    // If we recently received data, the connection is proven alive;
                    // skip the ping and reschedule (same as WA Web rescheduling the
                    // healthCheckTimer after activity).
                    if let Some(since_recv) = ms_since(last_recv)
                        && since_recv < KEEP_ALIVE_INTERVAL_MIN.as_millis() as u64
                    {
                        // Connection alive — reset error state, skip ping.
                        if error_count > 0 {
                            debug!(target: "Client/Keepalive", "Keepalive restored (recent activity).");
                            error_count = 0;
                        }
                        continue;
                    }

                    // Probe the connection BEFORE checking dead-socket so that a
                    // successful pong updates last_received_ms and prevents a
                    // false-positive dead-socket trigger on an idle-but-healthy
                    // connection.  WA Web uses a separate 20 s timer that is
                    // cancelled on any receive; our periodic loop needs to send the
                    // ping first to give the server a chance to prove it is alive.
                    match self.send_keepalive().await {
                        KeepaliveResult::Ok => {
                            if error_count > 0 {
                                debug!(target: "Client/Keepalive", "Keepalive restored after {error_count} failure(s).");
                            }
                            error_count = 0;

                            // Periodic cleanup of expired sent messages (~every 12 ticks ≈ 5 min)
                            cleanup_counter += 1;
                            if sent_msg_ttl > 0 && cleanup_counter >= 12 {
                                cleanup_counter = 0;
                                let backend = self.persistence_manager.backend();
                                let cutoff = wacore::time::now_secs()
                                    - sent_msg_ttl as i64;
                                self.runtime.spawn(Box::pin(async move {
                                    if let Err(e) = backend.delete_expired_sent_messages(cutoff).await {
                                        log::debug!(target: "Client/Keepalive", "Sent message cleanup error: {e}");
                                    }
                                })).detach();
                            }
                        }
                        KeepaliveResult::FatalFailure => {
                            debug!(target: "Client/Keepalive", "Fatal keepalive failure, exiting loop.");
                            return;
                        }
                        KeepaliveResult::TransientFailure => {
                            error_count += 1;
                            warn!(target: "Client/Keepalive", "Keepalive timeout, error count: {error_count}");
                        }
                    }

                    // WA Web: deadSocketTimer is an independent 20s watchdog armed on
                    // every send and cancelled on every receive. We approximate this by
                    // checking is_dead_socket on EVERY keepalive tick — not just after
                    // a failed ping. This catches scenarios where pending IQs caused
                    // the ping to be skipped, or where the ping "succeeded" but the
                    // connection died immediately after.
                    let last_sent = self.last_data_sent_ms.load(Ordering::Relaxed);
                    let last_recv = self.last_data_received_ms.load(Ordering::Relaxed);
                    if is_dead_socket(last_sent, last_recv) {
                        let elapsed = ms_since(last_sent).unwrap_or(0);
                        warn!(
                            target: "Client/Keepalive",
                            "No data received for {:.1}s after send (dead socket), forcing reconnect.",
                            elapsed as f64 / 1000.0
                        );
                        self.reconnect_immediately().await;
                        return;
                    }
                },
                _ = shutdown.fuse() => {
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

    #[test]
    fn test_classify_parse_error_is_transient() {
        assert_eq!(
            classify_keepalive_error(&IqError::ParseError(anyhow::anyhow!("bad response"))),
            KeepaliveResult::TransientFailure,
            "ParseError should be transient — bad response, not a dead connection"
        );
    }

    // ms_since, is_dead_socket, and constants tests live in wacore::protocol::keepalive
}
