use crate::types::events::Event;
use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{Binary as SqlBinary, Text as SqlText};
use prost::Message;
use std::sync::Arc;
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
        log::info!(
            "Downloading history sync blob for message {} (Size: {}, Type: {:?})",
            message_id,
            notification.file_length(),
            notification.sync_type()
        );

        self.send_protocol_receipt(message_id, crate::types::presence::ReceiptType::HistorySync)
            .await;

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
                // Transaction-scoped connection (optional)
                let tx_conn_holder = sqlite_store
                    .as_ref()
                    .and_then(|s| s.begin_transaction().ok());
                let tx_conn_arc_for_commit = Arc::new(Mutex::new(tx_conn_holder));
                let tx_conn_arc_handler = tx_conn_arc_for_commit.clone();

                let conv_handler = move |conv: wa::Conversation| {
                    let bus = core_bus.clone();
                    let tx_conn_arc = tx_conn_arc_handler.clone();
                    let store_opt = sqlite_store_for_handler.clone();
                    let pm_clone = persistence_manager.clone();
                    async move {
                        if let Some(store) = &store_opt {
                            if let Some(ref mut pooled) = *tx_conn_arc.lock().await {
                                // normalized
                                let _ = store.save_conversation_normalized_in_conn(pooled, &conv);
                                // raw blob (optional)
                                let data = conv.encode_to_vec();
                                let _ = sql_query("INSERT INTO conversations(id,data) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET data=excluded.data;")
                                    .bind::<SqlText,_>(conv.id.as_str())
                                    .bind::<SqlBinary,_>(&data)
                                    .execute(pooled);
                            }
                        } else {
                            // Fallback: per-conversation persistence (no global tx)
                            pm_clone.save_conversation_proto(&conv).await;
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

                // Commit or rollback transaction
                if let Some(store) = sqlite_store.as_ref()
                    && let Some(ref mut pooled) = *tx_conn_arc_for_commit.lock().await
                {
                    match &stream_result {
                        Ok(_) => {
                            let _ = store.commit_transaction(pooled);
                        }
                        Err(_) => {
                            let _ = store.rollback_transaction(pooled);
                        }
                    }
                }

                match stream_result {
                    Ok(()) => {
                        log::info!("Successfully processed HistorySync stream.");

                        // If pushnames were collected (not implemented in-stream yet), handle them
                        let push_vec = collected_pushnames.lock().await;
                        if !push_vec.is_empty() {
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
        let own_jid_user = device_snapshot.id.as_ref().map(|j| j.user.as_str());

        for pn in pushnames {
            if let Some(id) = &pn.id
                && Some(id.as_str()) == own_jid_user
                && let Some(name) = &pn.pushname
            {
                latest_own_pushname = Some(name.clone());
            }
        }

        if let Some(new_name) = latest_own_pushname {
            self.clone().update_push_name_and_notify(new_name).await;
        }
    }
}
