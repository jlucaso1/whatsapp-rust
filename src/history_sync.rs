use crate::types::events::Event;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use wacore::history_sync::{HistorySyncOptions, process_history_sync};
use waproto::whatsapp as wa;
use waproto::whatsapp::message::HistorySyncNotification;

use crate::client::Client;

impl Client {
    pub(crate) async fn handle_history_sync(
        self: &Arc<Self>,
        message_id: String,
        notification: HistorySyncNotification,
    ) {
        // Enqueue a MajorSyncTask for the dedicated sync worker to consume.
        let task = crate::sync_task::MajorSyncTask::HistorySync {
            message_id,
            notification: Box::new(notification),
        };
        if let Err(e) = self.major_sync_task_sender.send(task).await {
            log::error!("Failed to enqueue history sync task: {e}");
        }
    }

    // Private worker-invoked implementation containing the heavy logic
    pub(crate) async fn process_history_sync_task(
        self: &Arc<Self>,
        message_id: String,
        mut notification: HistorySyncNotification,
    ) {
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
            match self.download(&notification).await {
                Ok(data) => {
                    log::info!("Successfully downloaded history sync blob.");
                    data
                }
                Err(e) => {
                    log::error!("Failed to download history sync blob: {:?}", e);
                    return;
                }
            }
        };

        // Get own user for pushname extraction
        let own_user = {
            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            device_snapshot.pn.as_ref().map(|j| j.to_non_ad().user)
        };

        // Check if user wants to receive conversation events
        let emit_events = self.emit_history_sync_events.load(Ordering::Relaxed);

        if emit_events {
            // Full processing - parse conversations and emit events
            self.process_history_sync_full(compressed_data, own_user, &message_id)
                .await;
        } else {
            // Minimal processing - only extract own pushname
            self.process_history_sync_minimal(compressed_data, own_user, &message_id)
                .await;
        }
    }

    /// Minimal processing: only extract own pushname to save memory
    async fn process_history_sync_minimal(
        self: &Arc<Self>,
        compressed_data: Vec<u8>,
        own_user: Option<String>,
        message_id: &str,
    ) {
        if let Some(own_user) = own_user {
            let result = tokio::task::spawn_blocking(move || {
                wacore::history_sync::extract_own_pushname(&compressed_data, &own_user)
                // compressed_data is dropped here
            })
            .await;

            match result {
                Ok(Ok(Some(new_name))) => {
                    log::info!("Updating own push name from history sync to '{new_name}'");
                    self.clone().update_push_name_and_notify(new_name).await;
                }
                Ok(Ok(None)) => {
                    log::debug!("No own pushname found in history sync");
                }
                Ok(Err(e)) => {
                    log::error!("Failed to extract pushname from history sync: {:?}", e);
                }
                Err(e) => {
                    log::error!("History sync blocking task panicked: {:?}", e);
                }
            }
        } else {
            log::debug!("Skipping history sync pushname extraction - own user not known yet");
        }

        log::info!("Successfully processed HistorySync (message {message_id}).");
    }

    /// Full processing: parse conversations and emit JoinedGroup events
    async fn process_history_sync_full(
        self: &Arc<Self>,
        compressed_data: Vec<u8>,
        own_user: Option<String>,
        message_id: &str,
    ) {
        // Use a bounded channel to stream conversations without accumulating in memory
        let (tx, mut rx) = tokio::sync::mpsc::channel::<wa::Conversation>(16);

        let own_user_for_pushname = own_user.clone();

        // Run parsing in blocking thread
        let parse_handle = tokio::task::spawn_blocking(move || {
            let own_user_ref = own_user_for_pushname.as_deref();

            let result = process_history_sync(
                &compressed_data,
                HistorySyncOptions {
                    on_conversation: Some(|conv: wa::Conversation| {
                        // Send through channel - will block if channel is full
                        let _ = tx.blocking_send(conv);
                    }),
                    own_user_for_pushname: own_user_ref,
                },
            );

            result.map(|sync_result| {
                (sync_result.own_pushname, sync_result.conversations_processed)
            })
            // tx dropped here, closing channel
            // compressed_data dropped here
        });

        // Receive and dispatch conversations as they come in
        let mut conv_count = 0usize;
        while let Some(conv) = rx.recv().await {
            conv_count += 1;
            if conv_count % 25 == 0 {
                log::info!("History sync progress: {conv_count} conversations processed...");
            }
            self.core
                .event_bus
                .dispatch(&Event::JoinedGroup(Box::new(conv)));
        }

        // Wait for parsing to complete
        let parse_result = parse_handle.await;

        match parse_result {
            Ok(Ok((own_pushname, total))) => {
                log::info!(
                    "Successfully processed HistorySync (message {message_id}); {total} conversations"
                );

                // Update own push name if found
                if let Some(new_name) = own_pushname {
                    log::info!("Updating own push name from history sync to '{new_name}'");
                    self.clone().update_push_name_and_notify(new_name).await;
                }
            }
            Ok(Err(e)) => {
                log::error!("Failed to process HistorySync data: {:?}", e);
            }
            Err(e) => {
                log::error!("History sync blocking task panicked: {:?}", e);
            }
        }
    }
}
