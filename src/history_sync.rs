use crate::types::events::Event;
use std::sync::Arc;
use waproto::whatsapp as wa;
use waproto::whatsapp::history_sync::HistorySyncType;
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

                match wacore::history_sync::process_history_sync_blob(&compressed_data) {
                    Ok(history_data) => {
                        log::info!(
                            "Successfully parsed HistorySync protobuf (Type: {:?}, Conversations: {})",
                            history_data.sync_type(),
                            history_data.conversations.len()
                        );

                        if history_data.sync_type() == HistorySyncType::PushName {
                            self.clone()
                                .handle_historical_pushnames(&history_data.pushnames)
                                .await;
                        }

                        self.core
                            .event_bus
                            .dispatch(&Event::HistorySync(history_data));
                    }
                    Err(e) => {
                        log::error!("Failed to process HistorySync data: {:?}", e);
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
