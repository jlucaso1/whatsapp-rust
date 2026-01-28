//! Unified session telemetry manager.
//!
//! Sends `<ib><unified_session id="..."/></ib>` stanzas to match WhatsApp Web behavior.
//! Features: server time sync, duplicate prevention, sequence counter.

use log::debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use tokio::sync::Mutex;
use wacore::ib::{IbStanza, UnifiedSession};
use wacore::protocol::ProtocolNode;
use wacore_binary::node::Node;

/// Manager for unified session telemetry.
pub struct UnifiedSessionManager {
    server_time_offset_ms: Arc<AtomicI64>,
    last_sent_id: Arc<Mutex<Option<String>>>,
    sequence: Arc<AtomicU64>,
}

impl Default for UnifiedSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl UnifiedSessionManager {
    pub fn new() -> Self {
        Self {
            server_time_offset_ms: Arc::new(AtomicI64::new(0)),
            last_sent_id: Arc::new(Mutex::new(None)),
            sequence: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn server_time_offset_ms(&self) -> i64 {
        self.server_time_offset_ms.load(Ordering::Relaxed)
    }

    pub fn sequence(&self) -> u64 {
        self.sequence.load(Ordering::Relaxed)
    }

    /// Update server time offset from node's `t` attribute (Unix timestamp in seconds).
    pub fn update_server_time_offset(&self, node: &Node) {
        if let Some(t_str) = node.attrs.get("t").and_then(|v| v.as_str())
            && let Ok(server_time) = t_str.parse::<i64>()
            && server_time > 0
        {
            let local_time = chrono::Utc::now().timestamp();
            let offset_ms = (server_time - local_time) * 1000;
            self.server_time_offset_ms
                .store(offset_ms, Ordering::Relaxed);
            debug!(target: "UnifiedSession", "Server time offset: {}ms", offset_ms);
        }
    }

    pub fn calculate_session_id(&self) -> String {
        let offset = self.server_time_offset_ms.load(Ordering::Relaxed);
        UnifiedSession::calculate_id(offset)
    }

    /// Prepare to send unified session. Returns None if duplicate (already sent this ID).
    pub async fn prepare_send(&self) -> Option<(Node, u64)> {
        let session_id = self.calculate_session_id();

        {
            let mut last_id = self.last_sent_id.lock().await;
            if let Some(ref prev_id) = *last_id
                && prev_id == &session_id
            {
                debug!(target: "UnifiedSession", "Skipping duplicate id={}", session_id);
                return None;
            }

            // Reset sequence when session ID changes (matches WhatsApp Web behavior)
            if last_id.as_ref() != Some(&session_id) {
                self.sequence.store(0, Ordering::Relaxed);
            }
            *last_id = Some(session_id.clone());
        }

        // Pre-increment to return 1 on first call (matches WhatsApp Web's ++$2)
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let stanza = IbStanza::unified_session(UnifiedSession::new(&session_id));
        let node = stanza.into_node();

        debug!(target: "UnifiedSession", "Sending id={}, seq={}", session_id, sequence);

        Some((node, sequence))
    }

    /// Clear last sent ID to allow retry on failure.
    pub async fn clear_last_sent(&self) {
        *self.last_sent_id.lock().await = None;
    }

    /// Reset state on disconnect (keeps sequence counter).
    pub async fn reset(&self) {
        self.server_time_offset_ms.store(0, Ordering::Relaxed);
        *self.last_sent_id.lock().await = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore_binary::builder::NodeBuilder;

    #[test]
    fn test_manager_default() {
        let manager = UnifiedSessionManager::new();
        assert_eq!(manager.server_time_offset_ms(), 0);
        assert_eq!(manager.sequence(), 0);
    }

    #[test]
    fn test_update_server_time_offset() {
        let manager = UnifiedSessionManager::new();

        let server_time = chrono::Utc::now().timestamp() + 10;
        let node = NodeBuilder::new("success")
            .attr("t", server_time.to_string())
            .build();

        manager.update_server_time_offset(&node);

        let offset = manager.server_time_offset_ms();
        assert!(
            (offset - 10000).abs() < 1000,
            "Offset should be ~10000ms, got {}",
            offset
        );
    }

    #[test]
    fn test_update_server_time_offset_invalid() {
        let manager = UnifiedSessionManager::new();

        let node = NodeBuilder::new("success").build();
        manager.update_server_time_offset(&node);
        assert_eq!(manager.server_time_offset_ms(), 0);

        let node = NodeBuilder::new("success")
            .attr("t", "not_a_number")
            .build();
        manager.update_server_time_offset(&node);
        assert_eq!(manager.server_time_offset_ms(), 0);

        let node = NodeBuilder::new("success").attr("t", "0").build();
        manager.update_server_time_offset(&node);
        assert_eq!(manager.server_time_offset_ms(), 0);
    }

    #[test]
    fn test_calculate_session_id() {
        let manager = UnifiedSessionManager::new();
        let id = manager.calculate_session_id();

        let id_num: i64 = id.parse().expect("Should be a valid number");
        const WEEK_MS: i64 = 7 * 24 * 60 * 60 * 1000;
        assert!((0..WEEK_MS).contains(&id_num));
    }

    #[tokio::test]
    async fn test_prepare_send() {
        let manager = UnifiedSessionManager::new();

        // Use a loop to handle potential millisecond boundary crossing during the test.
        // Duplicate prevention only applies if the session ID (which is time-dependent) remains the same.
        loop {
            manager.reset().await; // Start clean for each attempt
            let result = manager.prepare_send().await;
            assert!(result.is_some());
            let (node, seq) = result.unwrap();
            assert_eq!(node.tag, "ib");
            assert_eq!(seq, 1);

            let result2 = manager.prepare_send().await;
            if result2.is_none() {
                // Success: duplicate was prevented within the same millisecond/session
                assert_eq!(manager.sequence(), 1);
                break;
            }
            // If result2 is Some, it means the millisecond changed and it's a new session.
            // We'll loop and try again to catch it within the same millisecond.
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn test_clear_last_sent() {
        let manager = UnifiedSessionManager::new();

        let (_, seq1) = manager.prepare_send().await.unwrap();
        assert_eq!(seq1, 1);
        assert_eq!(manager.sequence(), 1);

        manager.clear_last_sent().await;

        // After clear, it's treated as a new session -> sequence resets
        let result = manager.prepare_send().await;
        assert!(result.is_some());
        let (_, seq2) = result.unwrap();
        assert_eq!(seq2, 1, "Sequence resets when session ID changes");
        assert_eq!(manager.sequence(), 1);
    }

    #[tokio::test]
    async fn test_reset() {
        let manager = UnifiedSessionManager::new();

        let node = NodeBuilder::new("success")
            .attr("t", (chrono::Utc::now().timestamp() + 10).to_string())
            .build();
        manager.update_server_time_offset(&node);
        let (_, seq1) = manager.prepare_send().await.unwrap();
        assert_eq!(seq1, 1);

        manager.reset().await;

        assert_eq!(manager.server_time_offset_ms(), 0);
        // Sequence persists until next prepare_send detects new session ID
        assert_eq!(manager.sequence(), 1);

        // After reset, next send will reset sequence since session ID changed
        let (_, seq2) = manager.prepare_send().await.unwrap();
        assert_eq!(seq2, 1, "Sequence resets on new session");
    }
}
