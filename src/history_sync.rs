use crate::types::events::{Event, LazyConversation};
use bytes::Bytes;
use std::sync::Arc;
use wacore::history_sync::process_history_sync;
use wacore::store::traits::TcTokenEntry;
use wacore_binary::jid::JidExt;
use waproto::whatsapp::message::HistorySyncNotification;

use crate::client::Client;

/// Minimal proto decode struct for extracting tctoken fields from Conversation.
/// Avoids decoding the full Conversation (which includes heavy `messages` field).
#[derive(Clone, PartialEq, prost::Message)]
struct ConversationTcTokenFields {
    #[prost(string, required, tag = "1")]
    pub id: String,
    #[prost(bytes = "vec", optional, tag = "21")]
    pub tc_token: Option<Vec<u8>>,
    #[prost(uint64, optional, tag = "22")]
    pub tc_token_timestamp: Option<u64>,
    #[prost(uint64, optional, tag = "28")]
    pub tc_token_sender_timestamp: Option<u64>,
}

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

    /// Process history sync with streaming and lazy parsing.
    ///
    /// Memory efficient: raw bytes are wrapped in LazyConversation and only
    /// parsed if the event handler actually accesses the conversation data.
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

        // Get own user for pushname extraction (moved into blocking task, no clone needed)
        let own_user = {
            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            device_snapshot.pn.as_ref().map(|j| j.to_non_ad().user)
        };

        // Check if anyone is listening for events
        let has_listeners = self.core.event_bus.has_handlers();

        let parse_result = if has_listeners {
            // Use a bounded channel to stream raw conversation bytes as Bytes (zero-copy)
            let (tx, rx) = async_channel::bounded::<Bytes>(4);

            // Run streaming parsing in blocking thread
            // own_user is moved directly, no clone needed
            let (result_tx, result_rx) = futures::channel::oneshot::channel();
            // Spawn the blocking work concurrently — it runs while we
            // process channel items below.
            let blocking_fut = self.runtime.spawn_blocking(Box::new(move || {
                let own_user_ref = own_user.as_deref();

                // Streaming: decompresses and extracts raw bytes incrementally
                // No parsing happens here - just raw byte extraction
                // Uses Bytes for zero-copy reference counting
                let result = process_history_sync(
                    compressed_data,
                    own_user_ref,
                    Some(|raw_bytes: Bytes| {
                        // Send Bytes through channel (zero-copy clone)
                        #[cfg(not(target_arch = "wasm32"))]
                        let _ = tx.send_blocking(raw_bytes);
                        #[cfg(target_arch = "wasm32")]
                        let _ = tx.try_send(raw_bytes);
                    }),
                    compressed_size_hint,
                );
                // tx dropped here, closing channel
                let _ = result_tx.send(result);
            }));
            // Drive the blocking future to completion in the background
            self.runtime
                .spawn(Box::pin(async move {
                    blocking_fut.await;
                }))
                .detach();

            // Receive and dispatch lazy conversations as they come in
            let mut conv_count = 0usize;
            while let Ok(raw_bytes) = rx.recv().await {
                if self.is_shutting_down() {
                    log::debug!(
                        "Stopping history sync {} event dispatch during shutdown",
                        message_id
                    );
                    break;
                }
                conv_count += 1;
                if conv_count.is_multiple_of(25) {
                    log::info!("History sync progress: {conv_count} conversations processed...");
                }
                // Extract tctoken data before dispatching (lightweight partial decode).
                // Matches WA Web's storeTcTokensFromHistorySync / bulkCreateOrMerge.
                self.store_tc_token_from_conversation_bytes(&raw_bytes)
                    .await;

                // Wrap Bytes in LazyConversation using from_bytes (true zero-copy)
                // Parsing only happens if the event handler calls .conversation() or .get()
                let lazy_conv = LazyConversation::from_bytes(raw_bytes);
                self.core.event_bus.dispatch(&Event::JoinedGroup(lazy_conv));
            }

            // Drop receiver before awaiting the blocking task. If we broke out
            // of the loop during shutdown, the sender may be blocked on
            // tx.send_blocking() — dropping rx causes it to return Err and
            // unblock, preventing a deadlock.
            drop(rx);

            // Wait for parsing result
            result_rx.await.ok()
        } else {
            // No listeners - skip conversation processing entirely
            log::debug!("No event handlers registered, skipping conversation processing");

            // own_user is moved directly, no clone needed
            Some(
                wacore::runtime::blocking(&*self.runtime, move || {
                    let own_user_ref = own_user.as_deref();

                    // Pass None for callback - conversations are skipped at protobuf level
                    process_history_sync::<fn(Bytes)>(
                        compressed_data,
                        own_user_ref,
                        None,
                        compressed_size_hint,
                    )
                })
                .await,
            )
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
            }
            Some(Err(e)) => {
                log::error!("Failed to process HistorySync data: {:?}", e);
            }
            None => {
                log::error!("History sync blocking task was cancelled");
            }
        }
    }

    /// Extract and store tctoken data from a raw Conversation protobuf.
    ///
    /// Matches WA Web's `storeTcTokensFromHistorySync` / Baileys'
    /// `storeTcTokensFromHistorySync`. Uses a lightweight partial decode
    /// that only reads fields 1 (id), 21 (tcToken), 22 (tcTokenTimestamp),
    /// and 28 (tcTokenSenderTimestamp) — skipping the heavy messages field.
    async fn store_tc_token_from_conversation_bytes(&self, raw_bytes: &[u8]) {
        use prost::Message;

        let conv = match ConversationTcTokenFields::decode(raw_bytes) {
            Ok(c) => c,
            Err(_) => return,
        };

        let token = match conv.tc_token {
            Some(ref t) if !t.is_empty() => t,
            _ => return,
        };

        let Some(timestamp) = conv.tc_token_timestamp else {
            return;
        };

        // Resolve conversation JID to LID for storage key
        let jid: wacore_binary::jid::Jid = match conv.id.parse() {
            Ok(j) => j,
            Err(_) => return,
        };

        // Only store for user JIDs (not groups, newsletters, etc.)
        if jid.is_group() || jid.is_newsletter() || jid.is_bot() {
            return;
        }

        let token_key = if jid.is_lid() {
            jid.user.clone()
        } else {
            self.lid_pn_cache
                .get_current_lid(&jid.user)
                .await
                .unwrap_or_else(|| jid.user.clone())
        };

        let backend = self.persistence_manager.backend();

        // Monotonicity guard: only store if incoming timestamp >= existing
        if let Ok(Some(existing)) = backend.get_tc_token(&token_key).await
            && (existing.token_timestamp as u64) > timestamp
        {
            return;
        }

        let entry = TcTokenEntry {
            token: token.clone(),
            token_timestamp: timestamp as i64,
            sender_timestamp: conv.tc_token_sender_timestamp.map(|ts| ts as i64),
        };

        if let Err(e) = backend.put_tc_token(&token_key, &entry).await {
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
                timestamp
            );
        }
    }
}
