use crate::client::Client;
use crate::request::IqError;
use log::{debug, warn};
use rand::Rng;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use wacore::iq::spec::IqSpec;

/// Returns the number of milliseconds elapsed since a stored timestamp.
/// Returns `None` if the timestamp was never set (value 0).
fn ms_since(timestamp_ms: u64) -> Option<u64> {
    if timestamp_ms == 0 {
        return None;
    }
    let now = chrono::Utc::now().timestamp_millis() as u64;
    Some(now.saturating_sub(timestamp_ms))
}

/// Checks the dead-socket condition: data was sent but nothing received
/// within `DEAD_SOCKET_TIME`.
///
/// WA Web: `deadSocketTimer` is armed on every `callStanza` (send) and
/// cancelled on every `parseAndHandleStanza` (receive).  It fires when
/// `deadSocketTime` (20 s) elapses after the last send without any receive.
fn is_dead_socket(last_sent_ms: u64, last_received_ms: u64) -> bool {
    // Never sent anything yet — timer not armed.
    if last_sent_ms == 0 {
        return false;
    }
    // Received data after (or at) the last send — timer cancelled.
    if last_received_ms >= last_sent_ms {
        return false;
    }
    // Sent but no reply: check if DEAD_SOCKET_TIME has elapsed since the send.
    ms_since(last_sent_ms)
        .map(|elapsed| elapsed > DEAD_SOCKET_TIME.as_millis() as u64)
        .unwrap_or(false)
}

/// WA Web: `healthCheckInterval = 15` → `15 * (1 + random())` = 15–30 s.
const KEEP_ALIVE_INTERVAL_MIN: Duration = Duration::from_secs(15);
const KEEP_ALIVE_INTERVAL_MAX: Duration = Duration::from_secs(30);
const KEEP_ALIVE_RESPONSE_DEADLINE: Duration = Duration::from_secs(20);
/// WA Web: `deadSocketTime = 20_000` — if no data arrives for this long
/// after a send, the socket is considered dead and forcibly closed.
const DEAD_SOCKET_TIME: Duration = Duration::from_secs(20);

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

        let start_ms = chrono::Utc::now().timestamp_millis();
        let iq = wacore::iq::keepalive::KeepaliveSpec::with_timeout(KEEP_ALIVE_RESPONSE_DEADLINE)
            .build_iq();
        match self.send_iq(iq).await {
            Ok(response_node) => {
                let end_ms = chrono::Utc::now().timestamp_millis();
                let rtt_ms = end_ms - start_ms;
                debug!(target: "Client/Keepalive", "Received keepalive pong (RTT: {rtt_ms}ms)");
                // WA Web: onClockSkewUpdate — Math.round((startTime + rtt/2) / 1000 - serverTime)
                self.unified_session.update_server_time_offset_with_rtt(
                    &response_node,
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

                    // Dead-socket check (WA Web: deadSocketTimer → softCloseSocket).
                    // Armed on send, cancelled on receive. Fires when data was sent
                    // but no reply arrived within DEAD_SOCKET_TIME.
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

                    // WA Web: maybeScheduleHealthCheck — only send ping when idle.
                    // If we recently received data, the connection is proven alive;
                    // skip the ping and reschedule (same as WA Web rescheduling the
                    // healthCheckTimer after activity).
                    if let Some(since_recv) = ms_since(last_recv) {
                        if since_recv < KEEP_ALIVE_INTERVAL_MIN.as_millis() as u64 {
                            // Connection alive — reset error state, skip ping.
                            if error_count > 0 {
                                debug!(target: "Client/Keepalive", "Keepalive restored (recent activity).");
                                error_count = 0;
                            }
                            continue;
                        }
                    }

                    match self.send_keepalive().await {
                        KeepaliveResult::Ok => {
                            if error_count > 0 {
                                debug!(target: "Client/Keepalive", "Keepalive restored after {error_count} failure(s).");
                            }
                            error_count = 0;
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

    #[test]
    fn test_classify_parse_error_is_transient() {
        assert_eq!(
            classify_keepalive_error(&IqError::ParseError(anyhow::anyhow!("bad response"))),
            KeepaliveResult::TransientFailure,
            "ParseError should be transient — bad response, not a dead connection"
        );
    }

    // ── ms_since tests ───────────────────────────────────────────────────

    #[test]
    fn test_ms_since_never_set() {
        assert_eq!(ms_since(0), None, "should return None when timestamp is 0");
    }

    #[test]
    fn test_ms_since_recent() {
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let elapsed = ms_since(now_ms).unwrap();
        assert!(elapsed < 100, "should be near-zero, got {elapsed}ms");
    }

    #[test]
    fn test_ms_since_stale() {
        let thirty_sec_ago = (chrono::Utc::now().timestamp_millis() as u64).saturating_sub(30_000);
        let elapsed = ms_since(thirty_sec_ago).unwrap();
        assert!(
            elapsed >= 29_000 && elapsed <= 31_000,
            "should be ~30s, got {elapsed}ms"
        );
    }

    // ── is_dead_socket tests ─────────────────────────────────────────────

    #[test]
    fn test_dead_socket_never_sent() {
        // Never sent anything → timer not armed
        assert!(!is_dead_socket(0, 0));
    }

    #[test]
    fn test_dead_socket_received_after_send() {
        // Sent at T, received at T+1 → timer cancelled
        let t = chrono::Utc::now().timestamp_millis() as u64;
        assert!(!is_dead_socket(t, t + 1));
    }

    #[test]
    fn test_dead_socket_sent_recently() {
        // Sent just now, no reply yet but within 20s → not dead
        let now = chrono::Utc::now().timestamp_millis() as u64;
        assert!(!is_dead_socket(now, 0));
    }

    #[test]
    fn test_dead_socket_sent_long_ago_no_reply() {
        // Sent 30s ago, no reply → dead
        let thirty_ago = (chrono::Utc::now().timestamp_millis() as u64).saturating_sub(30_000);
        assert!(is_dead_socket(thirty_ago, 0));
    }

    #[test]
    fn test_dead_socket_sent_long_ago_old_reply() {
        // Sent 30s ago, last reply was 31s ago (before the send) → dead
        let thirty_ago = (chrono::Utc::now().timestamp_millis() as u64).saturating_sub(30_000);
        let thirty_one_ago = thirty_ago.saturating_sub(1_000);
        assert!(is_dead_socket(thirty_ago, thirty_one_ago));
    }

    #[test]
    fn test_dead_socket_sent_long_ago_recent_reply() {
        // Sent 30s ago, last reply was 1s ago → not dead (reply cancelled timer)
        let thirty_ago = (chrono::Utc::now().timestamp_millis() as u64).saturating_sub(30_000);
        let one_ago = (chrono::Utc::now().timestamp_millis() as u64).saturating_sub(1_000);
        assert!(!is_dead_socket(thirty_ago, one_ago));
    }

    // ── constants sanity tests ───────────────────────────────────────────

    #[test]
    fn test_keepalive_interval_matches_wa_web() {
        // WA Web: healthCheckInterval = 15, formula 15*(1+random()) = 15–30s
        assert_eq!(KEEP_ALIVE_INTERVAL_MIN, Duration::from_secs(15));
        assert_eq!(KEEP_ALIVE_INTERVAL_MAX, Duration::from_secs(30));
    }

    #[test]
    fn test_dead_socket_time_matches_wa_web() {
        // WA Web: deadSocketTime = 20_000
        assert_eq!(DEAD_SOCKET_TIME, Duration::from_secs(20));
    }
}
