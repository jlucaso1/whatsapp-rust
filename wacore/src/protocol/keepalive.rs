//! Pure helpers for keepalive / dead-socket detection.
//!
//! Constants and predicate functions with no runtime dependencies
//! (`self`, `Client`, spawn, sleep). The keepalive loop orchestration
//! and IQ error classification remain in `whatsapp-rust/src/keepalive.rs`
//! because `IqError` depends on `SocketError` which lives in whatsapp-rust.

use std::time::Duration;

/// WA Web: `healthCheckInterval = 15` -> `15 * (1 + random())` = 15-30 s.
pub const KEEP_ALIVE_INTERVAL_MIN: Duration = Duration::from_secs(15);
/// Upper bound of the randomized keepalive interval (30 s).
pub const KEEP_ALIVE_INTERVAL_MAX: Duration = Duration::from_secs(30);
/// Maximum time to wait for a keepalive pong before declaring timeout (20 s).
pub const KEEP_ALIVE_RESPONSE_DEADLINE: Duration = Duration::from_secs(20);
/// WA Web: `deadSocketTime = 20_000` -- if no data arrives for this long
/// after a send, the socket is considered dead and forcibly closed.
pub const DEAD_SOCKET_TIME: Duration = Duration::from_secs(20);

/// Returns the number of milliseconds elapsed since a stored timestamp.
/// Returns `None` if the timestamp was never set (value 0).
pub fn ms_since(timestamp_ms: u64) -> Option<u64> {
    if timestamp_ms == 0 {
        return None;
    }
    let now = chrono::Utc::now().timestamp_millis() as u64;
    Some(now.saturating_sub(timestamp_ms))
}

/// Checks the dead-socket condition: data was sent but nothing received
/// within [`DEAD_SOCKET_TIME`].
///
/// WA Web: `deadSocketTimer` is armed on every `callStanza` (send) and
/// cancelled on every `parseAndHandleStanza` (receive).  It fires when
/// `deadSocketTime` (20 s) elapses after the last send without any receive.
pub fn is_dead_socket(last_sent_ms: u64, last_received_ms: u64) -> bool {
    // Never sent anything yet -- timer not armed.
    if last_sent_ms == 0 {
        return false;
    }
    // Received data after (or at) the last send -- timer cancelled.
    if last_received_ms >= last_sent_ms {
        return false;
    }
    // Sent but no reply: check if DEAD_SOCKET_TIME has elapsed since the send.
    ms_since(last_sent_ms)
        .map(|elapsed| elapsed > DEAD_SOCKET_TIME.as_millis() as u64)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- ms_since tests --

    #[test]
    fn ms_since_never_set() {
        assert_eq!(ms_since(0), None);
    }

    #[test]
    fn ms_since_recent() {
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let elapsed = ms_since(now_ms).unwrap();
        assert!(elapsed < 100, "should be near-zero, got {elapsed}ms");
    }

    #[test]
    fn ms_since_stale() {
        let thirty_sec_ago = (chrono::Utc::now().timestamp_millis() as u64).saturating_sub(30_000);
        let elapsed = ms_since(thirty_sec_ago).unwrap();
        assert!(
            (29_000..=31_000).contains(&elapsed),
            "should be ~30s, got {elapsed}ms"
        );
    }

    // -- is_dead_socket tests --

    #[test]
    fn dead_socket_never_sent() {
        assert!(!is_dead_socket(0, 0));
    }

    #[test]
    fn dead_socket_received_after_send() {
        let t = chrono::Utc::now().timestamp_millis() as u64;
        assert!(!is_dead_socket(t, t + 1));
    }

    #[test]
    fn dead_socket_sent_recently() {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        assert!(!is_dead_socket(now, 0));
    }

    #[test]
    fn dead_socket_sent_long_ago_no_reply() {
        let thirty_ago = (chrono::Utc::now().timestamp_millis() as u64).saturating_sub(30_000);
        assert!(is_dead_socket(thirty_ago, 0));
    }

    #[test]
    fn dead_socket_sent_long_ago_old_reply() {
        let thirty_ago = (chrono::Utc::now().timestamp_millis() as u64).saturating_sub(30_000);
        let thirty_one_ago = thirty_ago.saturating_sub(1_000);
        assert!(is_dead_socket(thirty_ago, thirty_one_ago));
    }

    #[test]
    fn dead_socket_sent_long_ago_recent_reply() {
        let thirty_ago = (chrono::Utc::now().timestamp_millis() as u64).saturating_sub(30_000);
        let one_ago = (chrono::Utc::now().timestamp_millis() as u64).saturating_sub(1_000);
        assert!(!is_dead_socket(thirty_ago, one_ago));
    }

    // -- constant sanity --

    #[test]
    fn constants_match_wa_web() {
        assert_eq!(KEEP_ALIVE_INTERVAL_MIN, Duration::from_secs(15));
        assert_eq!(KEEP_ALIVE_INTERVAL_MAX, Duration::from_secs(30));
        assert_eq!(DEAD_SOCKET_TIME, Duration::from_secs(20));
    }
}
