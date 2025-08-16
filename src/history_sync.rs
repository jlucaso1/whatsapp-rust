use crate::types::events::Event;
use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{Binary as SqlBinary, Text as SqlText};
use prost::Message;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;
use waproto::whatsapp as wa;
use waproto::whatsapp::message::HistorySyncNotification;

use crate::client::Client;

impl Client {
    pub async fn handle_history_sync(
        self: &Arc<Self>,
        message_id: String,
        notification: HistorySyncNotification,
    ) {
        // Do not take the global full_sync_lock here to avoid deadlocks with IQ/presence flows.
        let log_msg_id = message_id.clone();
        log::info!(
            "Downloading history sync blob for message {} (Size: {}, Type: {:?})",
            message_id,
            notification.file_length(),
            notification.sync_type()
        );

        self.send_protocol_receipt(
            message_id.clone(),
            crate::types::presence::ReceiptType::HistorySync,
        )
        .await;
        let msg_id_for_log = log_msg_id;
        match self.download(&notification).await {
            Ok(compressed_data) => {
                log::info!("Successfully downloaded history sync blob.");

                // Use streaming parser to avoid decoding the full HistorySync into memory
                // Collect small top-level fields (like pushnames) and stream conversations
                let collected_pushnames: Arc<Mutex<Vec<wa::Pushname>>> =
                    Arc::new(Mutex::new(Vec::new()));

                let persistence_manager = self.persistence_manager.clone();
                let core_bus = self.core.event_bus.clone();
                let sqlite_store = persistence_manager.sqlite_store();
                let sqlite_store_for_handler = sqlite_store.clone();
                // Per-conversation writes; track progress
                let processed_count = Arc::new(AtomicUsize::new(0));
                let processed_count_for_final = processed_count.clone();

                let conv_handler = move |conv: wa::Conversation| {
                    let bus = core_bus.clone();
                    let store_opt = sqlite_store_for_handler.clone();
                    let pm_clone = persistence_manager.clone();
                    let processed = processed_count.clone();
                    async move {
                        let conv_id = conv.id.clone();
                        if let Some(store) = &store_opt {
                            // Heavy blocking DB work offloaded
                            let conv_clone = conv.clone();
                            let store_clone = store.clone();
                            if let Err(e) = tokio::task::spawn_blocking(move || {
                                if let Ok(mut c) = store_clone.get_connection() {
                                    // normalized + messages
                                    let _ = store_clone.save_conversation_normalized_in_conn(&mut c, &conv_clone);
                                    // raw blob
                                    let data = conv_clone.encode_to_vec();
                                    let _ = sql_query("INSERT INTO conversations(id,data) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET data=excluded.data;")
                                        .bind::<SqlText,_>(conv_clone.id.as_str())
                                        .bind::<SqlBinary,_>(&data)
                                        .execute(&mut c);
                                }
                            }).await {
                                log::warn!("History sync: spawn_blocking join error for conversation {conv_id}: {e:?}");
                            }
                        } else {
                            pm_clone.save_conversation_proto(&conv).await;
                        }
                        let new = processed.fetch_add(1, Ordering::Relaxed) + 1;
                        if new % 25 == 0 {
                            log::info!("History sync progress: {new} conversations processed...");
                        }
                        bus.dispatch(&Event::JoinedGroup(Box::new(conv)));
                    }
                };

                let push_collector = collected_pushnames.clone();
                let pushname_handler = move |pn: wa::Pushname| {
                    let pc = push_collector.clone();
                    async move {
                        pc.lock().await.push(pn);
                    }
                };

                let stream_result = wacore::history_sync::process_history_sync_stream(
                    &compressed_data,
                    conv_handler,
                    pushname_handler,
                )
                .await;
                let total = processed_count_for_final.load(Ordering::Relaxed);
                log::debug!(
                    "History sync stream finished processing (message {msg_id_for_log}); total conversations processed={total}"
                );

                // No transaction commit step

                match stream_result {
                    Ok(()) => {
                        log::info!("Successfully processed HistorySync stream.");

                        // If pushnames were collected (not implemented in-stream yet), handle them
                        let push_vec = collected_pushnames.lock().await;
                        if !push_vec.is_empty() {
                            log::debug!(
                                "Collected {} push names from history sync; invoking handler",
                                push_vec.len()
                            );
                            self.clone().handle_historical_pushnames(&push_vec).await;
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to process HistorySync data stream: {:?}", e);
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to download history sync blob: {:?}", e);
            }
        }
    }

    pub async fn handle_historical_pushnames(self: Arc<Self>, pushnames: &[wa::Pushname]) {
        if pushnames.is_empty() {
            return;
        }

        log::info!(
            "Processing {} push names from history sync.",
            pushnames.len()
        );

        let mut latest_own_pushname = None;
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        // Compare against the non-AD (base) user so 5599xxxx:58 matches pushname id 5599xxxx
        let own_base_user = device_snapshot.id.as_ref().map(|j| j.to_non_ad().user);

        if let Some(own_user) = own_base_user {
            log::debug!(
                "Looking for own push name among {} entries (own_user={})",
                pushnames.len(),
                own_user
            );
            for pn in pushnames {
                if let Some(id) = &pn.id
                    && *id == own_user
                    && let Some(name) = &pn.pushname
                {
                    log::debug!("Matched own push name candidate id={} name={}", id, name);
                    latest_own_pushname = Some(name.clone());
                }
            }
        } else {
            log::warn!("Could not determine own JID user to extract push name from history sync.");
        }

        if let Some(new_name) = latest_own_pushname {
            log::info!("Updating own push name from history sync to '{new_name}'");
            self.clone().update_push_name_and_notify(new_name).await;
        }
    }
}
