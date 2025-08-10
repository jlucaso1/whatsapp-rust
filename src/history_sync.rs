use crate::types::events::{Event, SelfPushNameUpdated};
use crate::types::presence::Presence;
use flate2::read::ZlibDecoder;
use prost::Message;
use std::io::Read;
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
            Ok(decompressed_data) => {
                log::info!("Successfully downloaded and decompressed history sync blob.");

                let mut decoder = ZlibDecoder::new(&decompressed_data[..]);
                let mut uncompressed = Vec::new();
                if let Err(e) = decoder.read_to_end(&mut uncompressed) {
                    log::error!("Failed to zlib decompress history sync data: {:?}", e);
                    return;
                }

                match wa::HistorySync::decode(uncompressed.as_slice()) {
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
                        log::error!("Failed to parse HistorySync protobuf: {:?}", e);
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
            let old_name = device_snapshot.push_name.clone();
            if old_name != new_name {
                log::info!(
                    "Updating own push name from history sync: '{}' -> '{}'",
                    old_name,
                    new_name
                );
                self.persistence_manager
                    .process_command(crate::store::commands::DeviceCommand::SetPushName(
                        new_name.clone(),
                    ))
                    .await;
                self.core
                    .event_bus
                    .dispatch(&Event::SelfPushNameUpdated(SelfPushNameUpdated {
                        from_server: true,
                        old_name,
                        new_name,
                    }));

                let client_clone = self.clone();
                tokio::task::spawn_local(async move {
                    if let Err(e) = client_clone.send_presence(Presence::Available).await {
                        log::warn!("Failed to send presence after history sync update: {:?}", e);
                    } else {
                        log::info!("Sent presence after receiving push name via history sync");
                    }
                });
            }
        }
    }
}
