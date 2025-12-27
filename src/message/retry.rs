//! Retry logic for failed message decryption.
//!
//! This module handles retry receipt sending when message decryption fails.
//! It includes:
//! - Retry count tracking with maximum limits
//! - Atomic increment operations to prevent race conditions
//! - PDO (Peer Data Operation) fallback requests

use crate::client::Client;
use crate::types::events::Event;
use crate::types::message::MessageInfo;
use log::debug;
use std::sync::Arc;
use wacore::types::message::{HIGH_RETRY_COUNT_THRESHOLD, MAX_DECRYPT_RETRIES, RetryReason};

impl Client {
    /// Dispatches an `UndecryptableMessage` event to notify consumers that a message
    /// could not be decrypted. This is called when decryption fails and we need to
    /// show a placeholder to the user (like "Waiting for this message...").
    ///
    /// # Arguments
    /// * `info` - The message info for the undecryptable message
    /// * `decrypt_fail_mode` - Whether to show or hide the placeholder (matches WhatsApp Web's `hideFail`)
    pub(crate) fn dispatch_undecryptable_event(
        &self,
        info: &MessageInfo,
        decrypt_fail_mode: crate::types::events::DecryptFailMode,
    ) {
        self.core.event_bus.dispatch(&Event::UndecryptableMessage(
            crate::types::events::UndecryptableMessage {
                info: info.clone(),
                is_unavailable: false,
                unavailable_type: crate::types::events::UnavailableType::Unknown,
                decrypt_fail_mode,
            },
        ));
    }

    /// Handles a decryption failure by dispatching an undecryptable event and spawning a retry receipt.
    ///
    /// This is a convenience method that combines the common pattern of:
    /// 1. Dispatching an UndecryptableMessage event
    /// 2. Spawning a retry receipt to request re-encryption
    ///
    /// Returns `true` to be assigned to `dispatched_undecryptable` flag.
    pub(crate) fn handle_decrypt_failure(
        self: &Arc<Self>,
        info: &MessageInfo,
        reason: RetryReason,
    ) -> bool {
        self.dispatch_undecryptable_event(info, crate::types::events::DecryptFailMode::Show);
        self.spawn_retry_receipt(info, reason);
        true
    }

    /// Atomically increments the retry count for a message and returns the new count.
    /// Returns `None` if max retries have been reached.
    ///
    /// Uses moka's `and_compute_with` for truly atomic read-modify-write operations,
    /// preventing race conditions where concurrent calls could exceed MAX_DECRYPT_RETRIES.
    pub(crate) async fn increment_retry_count(&self, cache_key: &str) -> Option<u8> {
        use moka::ops::compute::Op;

        let result = self
            .message_retry_counts
            .entry_by_ref(cache_key)
            .and_compute_with(|maybe_entry| {
                let op = if let Some(entry) = maybe_entry {
                    let current = entry.into_value();
                    if current >= MAX_DECRYPT_RETRIES {
                        // Max retries reached, don't increment
                        Op::Nop
                    } else {
                        // Increment the counter
                        Op::Put(current + 1)
                    }
                } else {
                    // No entry exists, insert initial count of 1
                    Op::Put(1_u8)
                };
                std::future::ready(op)
            })
            .await;

        // Extract the new count from the result
        match result {
            moka::ops::compute::CompResult::Inserted(entry) => Some(entry.into_value()),
            moka::ops::compute::CompResult::ReplacedWith(entry) => Some(entry.into_value()),
            moka::ops::compute::CompResult::Unchanged(_) => None, // Max retries reached
            moka::ops::compute::CompResult::StillNone(_) => None, // Should not happen
            moka::ops::compute::CompResult::Removed(_) => None,   // Should not happen
        }
    }

    /// Spawns a task that sends a retry receipt for a failed decryption.
    ///
    /// This is used when sessions are not found or invalid to request the sender to resend
    /// the message with a PreKeySignalMessage to re-establish the session.
    ///
    /// # Retry Count Tracking
    ///
    /// This method tracks retry counts per message (keyed by `{chat}:{msg_id}:{sender}`)
    /// and stops sending retry receipts after `MAX_DECRYPT_RETRIES` (5) attempts to prevent
    /// infinite retry loops. This matches WhatsApp Web's behavior.
    ///
    /// # PDO Backup
    ///
    /// A PDO (Peer Data Operation) request is spawned only on the FIRST retry attempt.
    /// This asks our primary phone to share the already-decrypted message content.
    /// PDO is NOT spawned on subsequent retries to avoid duplicate requests.
    ///
    /// When max retries is reached, an immediate PDO request is sent as a last resort.
    ///
    /// # Arguments
    /// * `info` - The message info for the failed message
    /// * `reason` - The retry reason code (matches WhatsApp Web's RetryReason enum)
    pub(crate) fn spawn_retry_receipt(self: &Arc<Self>, info: &MessageInfo, reason: RetryReason) {
        let cache_key = format!("{}:{}:{}", info.source.chat, info.id, info.source.sender);
        let client = Arc::clone(self);
        let info = info.clone();

        tokio::spawn(async move {
            // Atomically increment retry count and check if we should continue
            let Some(retry_count) = client.increment_retry_count(&cache_key).await else {
                // Max retries reached
                log::info!(
                    "Max retries ({}) reached for message {} from {} [{:?}]. Sending immediate PDO request.",
                    MAX_DECRYPT_RETRIES,
                    info.id,
                    info.source.sender,
                    reason
                );
                // Send PDO request immediately (no delay) as last resort
                client.spawn_pdo_request_with_options(&info, true);
                return;
            };

            // Log warning for high retry counts (like WhatsApp Web's MessageHighRetryCount)
            if retry_count > HIGH_RETRY_COUNT_THRESHOLD {
                log::warn!(
                    "High retry count ({}) for message {} from {} [{:?}]",
                    retry_count,
                    info.id,
                    info.source.sender,
                    reason
                );
            }

            // Send the retry receipt with the actual retry count and reason
            match client.send_retry_receipt(&info, retry_count, reason).await {
                Ok(()) => {
                    debug!(
                        "Sent retry receipt #{} for message {} from {} [{:?}]",
                        retry_count, info.id, info.source.sender, reason
                    );
                }
                Err(e) => {
                    log::error!(
                        "Failed to send retry receipt #{} for message {} [{:?}]: {:?}",
                        retry_count,
                        info.id,
                        reason,
                        e
                    );
                }
            }

            // Only spawn PDO on the FIRST retry to avoid duplicate requests.
            // The PDO cache also provides deduplication, but this reduces unnecessary work.
            if retry_count == 1 {
                client.spawn_pdo_request(&info);
            }
        });
    }
}
