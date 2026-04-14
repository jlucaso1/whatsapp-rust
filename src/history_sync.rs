use crate::types::events::{Event, LazyHistorySync};
use std::sync::Arc;
use wacore::history_sync::{TcTokenCandidate, process_history_sync};
use wacore::store::traits::TcTokenEntry;
use waproto::whatsapp::message::HistorySyncNotification;

use crate::client::Client;

impl Client {
    pub(crate) async fn handle_history_sync(
        self: &Arc<Self>,
        message_id: String,
        notification: HistorySyncNotification,
    ) {
        if self.is_shutting_down() {
            log::debug!(
                "Dropping history sync {} during shutdown (Type: {:?})",
                message_id,
                notification.sync_type()
            );
            return;
        }

        if self.skip_history_sync_enabled() {
            log::debug!(
                "Skipping history sync for message {} (Type: {:?})",
                message_id,
                notification.sync_type()
            );
            // Send receipt so the phone considers this chunk delivered and stops
            // retrying. This intentionally diverges from WhatsApp Web's AB prop
            // drop path (which sends no receipt) because bots will never process
            // history, and without the receipt the phone would keep re-uploading
            // blobs that will never be consumed.
            self.send_protocol_receipt(
                message_id,
                crate::types::presence::ReceiptType::HistorySync,
            )
            .await;
            return;
        }

        // Enqueue a MajorSyncTask for the dedicated sync worker to consume.
        self.begin_history_sync_task();
        let task = crate::sync_task::MajorSyncTask::HistorySync {
            message_id,
            notification: Box::new(notification),
        };
        if let Err(e) = self.major_sync_task_sender.send(task).await {
            self.finish_history_sync_task();
            if self.is_shutting_down() {
                log::debug!("Dropping history sync task during shutdown: {e}");
            } else {
                log::error!("Failed to enqueue history sync task: {e}");
            }
        }
    }

    /// Process history sync: decompress, extract internal data (tctokens,
    /// pushname, nct_salt), then dispatch a single `Event::HistorySync`
    /// with the full decompressed blob for on-demand consumer decoding.
    pub(crate) async fn process_history_sync_task(
        self: &Arc<Self>,
        message_id: String,
        mut notification: HistorySyncNotification,
    ) {
        if self.is_shutting_down() {
            log::debug!("Aborting history sync {} before processing", message_id);
            return;
        }

        log::info!(
            "Processing history sync for message {} (Size: {}, Type: {:?})",
            message_id,
            notification.file_length(),
            notification.sync_type()
        );

        self.send_protocol_receipt(
            message_id.clone(),
            crate::types::presence::ReceiptType::HistorySync,
        )
        .await;

        if self.is_shutting_down() {
            log::debug!(
                "Aborting history sync {} after receipt during shutdown",
                message_id
            );
            return;
        }

        // file_length is the decrypted (but still zlib-compressed) blob size, not
        // the final decompressed size. We still pass it as a hint — the decompressor
        // uses it with a 4x multiplier, which is a better estimate than guessing
        // from the encrypted size (which includes MAC/padding overhead).
        let compressed_size_hint = notification.file_length.filter(|&s| s > 0);

        // Use take() to avoid cloning large payloads - moves ownership instead
        let compressed_data = if let Some(inline_payload) =
            notification.initial_hist_bootstrap_inline_payload.take()
        {
            log::info!(
                "Found inline history sync payload ({} bytes). Using directly.",
                inline_payload.len()
            );
            inline_payload
        } else {
            log::info!("Downloading external history sync blob...");
            if self.is_shutting_down() || !self.is_connected() {
                log::debug!(
                    "Aborting history sync {} before blob download: client disconnected",
                    message_id
                );
                return;
            }
            // Stream-decrypt: reads encrypted chunks (8KB) from the network and
            // decrypts on the fly into a Vec, avoiding holding the full encrypted
            // blob in memory alongside the decrypted one.
            match self
                .download_to_writer(&notification, std::io::Cursor::new(Vec::new()))
                .await
            {
                Ok(cursor) => {
                    log::info!("Successfully downloaded history sync blob.");
                    cursor.into_inner()
                }
                Err(e) => {
                    if self.is_shutting_down() {
                        log::debug!(
                            "History sync blob download aborted during shutdown: {:?}",
                            e
                        );
                    } else {
                        log::error!("Failed to download history sync blob: {:?}", e);
                    }
                    return;
                }
            }
        };

        let own_user = {
            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            device_snapshot.pn.as_ref().map(|j| j.to_non_ad().user)
        };

        let has_listeners = self.core.event_bus.has_handlers();

        // Small blobs (PushName, Recent): decode inline to avoid spawn_blocking overhead.
        // Large blobs: use blocking thread to avoid stalling the async runtime.
        const INLINE_THRESHOLD: usize = 256 * 1024;
        let parse_result = if compressed_data.len() < INLINE_THRESHOLD {
            Some(process_history_sync(
                compressed_data,
                own_user.as_deref(),
                has_listeners,
                compressed_size_hint,
            ))
        } else {
            let (result_tx, result_rx) = futures::channel::oneshot::channel();
            let blocking_fut = self.runtime.spawn_blocking(Box::new(move || {
                let result = process_history_sync(
                    compressed_data,
                    own_user.as_deref(),
                    has_listeners,
                    compressed_size_hint,
                );
                let _ = result_tx.send(result);
            }));
            self.runtime
                .spawn(Box::pin(async move {
                    blocking_fut.await;
                }))
                .detach();
            result_rx.await.ok()
        };

        if self.is_shutting_down() {
            log::debug!(
                "Aborting history sync {} after parse during shutdown",
                message_id
            );
            return;
        }

        match parse_result {
            Some(Ok(sync_result)) => {
                log::info!(
                    "Successfully processed HistorySync (message {message_id}); {} conversations",
                    sync_result.conversations_processed
                );

                // Update own push name if found
                if let Some(new_name) = sync_result.own_pushname {
                    log::info!("Updating own push name from history sync to '{new_name}'");
                    self.update_push_name_and_notify(new_name).await;
                }

                // Store NCT salt if found.
                // WA Web: storeNctSaltFromHistorySync in MsgHandlerAction.js
                if let Some(salt) = sync_result.nct_salt {
                    log::info!(
                        "History sync provided NCT salt ({} bytes); applying as backfill only",
                        salt.len()
                    );
                    self.persistence_manager
                        .process_command(
                            wacore::store::commands::DeviceCommand::SetNctSaltFromHistorySync(salt),
                        )
                        .await;
                }

                // Store tctokens extracted during streaming
                for candidate in &sync_result.tc_token_candidates {
                    self.store_tc_token_candidate(candidate).await;
                }

                // Dispatch a single event with the full decompressed blob
                if let Some(decompressed) = sync_result.decompressed_bytes {
                    let lazy_hs = LazyHistorySync::new(
                        decompressed,
                        notification.sync_type().into(),
                        notification.chunk_order,
                        notification.progress,
                    );
                    self.core
                        .event_bus
                        .dispatch(Event::HistorySync(Box::new(lazy_hs)));
                }
            }
            Some(Err(e)) => {
                log::error!("Failed to process HistorySync data: {:?}", e);
            }
            None => {
                log::error!("History sync blocking task was cancelled");
            }
        }
    }

    /// Store a tctoken candidate extracted during history sync streaming.
    async fn store_tc_token_candidate(&self, candidate: &TcTokenCandidate) {
        let jid: wacore_binary::Jid = match candidate.id.parse() {
            Ok(j) => j,
            Err(_) => return,
        };

        let resolved_lid = if jid.is_lid() {
            None
        } else {
            self.lid_pn_cache.get_current_lid(&jid.user).await
        };
        let token_key: &str = resolved_lid.as_deref().unwrap_or(&jid.user);

        let backend = self.persistence_manager.backend();

        // Avoid clobbering a newer local sender_timestamp from post-send issuance
        let incoming_sender_ts = candidate.tc_token_sender_timestamp.map(|ts| ts as i64);
        let merged_sender_ts = if let Ok(Some(existing)) = backend.get_tc_token(token_key).await {
            if (existing.token_timestamp as u64) > candidate.tc_token_timestamp {
                return;
            }
            match (existing.sender_timestamp, incoming_sender_ts) {
                (Some(e), Some(i)) => Some(e.max(i)),
                (Some(e), None) => Some(e),
                (None, i) => i,
            }
        } else {
            incoming_sender_ts
        };

        let entry = TcTokenEntry {
            token: candidate.tc_token.clone(),
            token_timestamp: candidate.tc_token_timestamp as i64,
            sender_timestamp: merged_sender_ts,
        };

        if let Err(e) = backend.put_tc_token(token_key, &entry).await {
            log::warn!(
                target: "Client/TcToken",
                "Failed to store history sync tctoken for {}: {e}",
                token_key
            );
        } else {
            log::debug!(
                target: "Client/TcToken",
                "Stored tctoken from history sync for {} (t={})",
                token_key,
                candidate.tc_token_timestamp
            );
        }
    }
}
