use crate::types::events::Event;
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
                let collected_pushnames: Arc<Mutex<Vec<wa::Pushname>>> = Arc::new(Mutex::new(Vec::new()));

                let persistence = self.persistence_manager.clone();
                let core_bus = self.core.event_bus.clone();
                let conv_handler = move |conv: wa::Conversation| {
                    let p = persistence.clone();
                    let bus = core_bus.clone();
                    async move {
                        p.save_conversation_proto(&conv).await;
                        // Dispatch lightweight event (optional)
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

                match wacore::history_sync::process_history_sync_stream(
                    &compressed_data,
                    conv_handler,
                    pushname_handler,
                )
                .await
                {
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
