//! Session management with deduplication for concurrent prekey fetches.
//!
//! This module implements a pattern similar to WhatsApp Web's `ensureE2ESessions`,
//! which provides:
//! - Deduplication: Multiple concurrent requests for the same JID share a single fetch
//! - Batching: Prekey fetches are batched up to SESSION_CHECK_BATCH_SIZE
//!
//! This prevents redundant network requests when sending messages to the same
//! recipient from multiple concurrent operations.

use async_lock::Mutex;
use futures::channel::oneshot;
use std::collections::{HashMap, HashSet};
use wacore_binary::jid::Jid;

// Tests live in whatsapp-rust/src/session.rs (they use tokio for spawning)

/// Maximum number of JIDs to include in a single prekey fetch request.
/// Matches WhatsApp Web's SESSION_CHECK_BATCH constant.
pub const SESSION_CHECK_BATCH_SIZE: usize = 50;

/// Result of a session ensure operation
pub type SessionResult = Result<(), SessionError>;

/// Errors that can occur during session management
#[derive(Debug, Clone)]
pub enum SessionError {
    /// The prekey fetch operation failed
    FetchFailed(String),
    /// The session establishment failed
    EstablishmentFailed(String),
    /// Internal channel error
    ChannelClosed,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::FetchFailed(msg) => write!(f, "prekey fetch failed: {}", msg),
            SessionError::EstablishmentFailed(msg) => {
                write!(f, "session establishment failed: {}", msg)
            }
            SessionError::ChannelClosed => write!(f, "internal channel closed"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Manages session establishment with deduplication.
///
/// When multiple concurrent operations need sessions for overlapping JIDs,
/// this manager ensures only one prekey fetch is performed per JID.
/// Subsequent requests wait for the in-flight fetch to complete.
pub struct SessionManager {
    /// JIDs currently being processed (prekeys being fetched + sessions being established)
    processing: Mutex<HashSet<String>>,

    /// JIDs waiting for processing, mapped to their notification channels.
    /// When a JID finishes processing, all waiters are notified.
    pending: Mutex<HashMap<String, Vec<oneshot::Sender<SessionResult>>>>,
}

impl SessionManager {
    /// Create a new SessionManager
    pub fn new() -> Self {
        Self {
            processing: Mutex::new(HashSet::new()),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Ensure sessions exist for the given JIDs.
    ///
    /// This method deduplicates requests: if a JID is already being processed,
    /// this call will wait for that processing to complete rather than
    /// initiating a duplicate fetch.
    ///
    /// # Arguments
    /// * `jids` - JIDs that need sessions
    /// * `has_session` - Closure to check if a session already exists
    /// * `fetch_and_establish` - Closure to fetch prekeys and establish sessions
    ///
    /// # Returns
    /// Ok(()) if all sessions were established (or already existed)
    pub async fn ensure_sessions<F, H, Fut>(
        &self,
        jids: Vec<Jid>,
        has_session: H,
        fetch_and_establish: F,
    ) -> SessionResult
    where
        H: Fn(&Jid) -> bool,
        F: Fn(Vec<Jid>) -> Fut,
        Fut: std::future::Future<Output = Result<(), anyhow::Error>>,
    {
        if jids.is_empty() {
            return Ok(());
        }

        // Step 1: Filter to JIDs that actually need sessions
        let jids_needing_sessions: Vec<Jid> =
            jids.into_iter().filter(|jid| !has_session(jid)).collect();

        if jids_needing_sessions.is_empty() {
            return Ok(());
        }

        // Step 2: Determine which JIDs we need to process vs wait for.
        // Store (Jid, String) pairs so the string key computed here can be
        // reused in step 3 cleanup, avoiding a redundant second to_string() pass.
        let (to_process, to_wait) = {
            let mut processing = self.processing.lock().await;
            let mut pending = self.pending.lock().await;

            let mut to_process: Vec<(Jid, String)> =
                Vec::with_capacity(jids_needing_sessions.len());
            let mut to_wait = Vec::with_capacity(jids_needing_sessions.len());

            for jid in jids_needing_sessions {
                let jid_str = jid.to_string();

                if processing.contains(&jid_str) {
                    // Already being processed - we need to wait
                    let (tx, rx) = oneshot::channel();
                    pending.entry(jid_str).or_default().push(tx);
                    to_wait.push(rx);
                } else {
                    // Not being processed - we'll handle it
                    processing.insert(jid_str.clone());
                    to_process.push((jid, jid_str));
                }
            }

            (to_process, to_wait)
        };

        // Step 3: Process JIDs we're responsible for (in batches)
        let mut process_error: Option<SessionError> = None;

        if !to_process.is_empty() {
            // Process in batches of SESSION_CHECK_BATCH_SIZE
            for batch in to_process.chunks(SESSION_CHECK_BATCH_SIZE) {
                let batch_jids: Vec<Jid> = batch.iter().map(|(jid, _)| jid.clone()).collect();

                let result = fetch_and_establish(batch_jids).await;

                // Notify any waiters and remove from processing
                let notify_result = match &result {
                    Ok(()) => Ok(()),
                    Err(e) => Err(SessionError::FetchFailed(e.to_string())),
                };

                if notify_result.is_err() && process_error.is_none() {
                    process_error = Some(notify_result.clone().unwrap_err());
                }

                // Clean up processing set and notify waiters
                // Reuse the string keys stored alongside each JID in step 2.
                {
                    let mut processing = self.processing.lock().await;
                    let mut pending = self.pending.lock().await;

                    for (_, jid_str) in batch {
                        processing.remove(jid_str);

                        if let Some(waiters) = pending.remove(jid_str) {
                            for waiter in waiters {
                                let _ = waiter.send(notify_result.clone());
                            }
                        }
                    }
                }
            }
        }

        // Step 4: Wait for JIDs being processed by others
        for rx in to_wait {
            match rx.await {
                Ok(result) => {
                    if let Err(e) = result
                        && process_error.is_none()
                    {
                        process_error = Some(e);
                    }
                }
                Err(_) => {
                    if process_error.is_none() {
                        process_error = Some(SessionError::ChannelClosed);
                    }
                }
            }
        }

        match process_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Check if a JID is currently being processed
    pub async fn is_processing(&self, jid: &str) -> bool {
        self.processing.lock().await.contains(jid)
    }

    /// Get the number of JIDs currently being processed
    pub async fn processing_count(&self) -> usize {
        self.processing.lock().await.len()
    }

    /// Get the number of JIDs with pending waiters
    pub async fn pending_count(&self) -> usize {
        self.pending.lock().await.len()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}
