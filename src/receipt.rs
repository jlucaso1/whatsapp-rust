use crate::client::Client;
use crate::types::events::{Event, Receipt};
use crate::types::presence::ReceiptType;
use libsignal_protocol::SessionRecord;
use log::info;
use std::sync::Arc;
use tokio::task;
use wacore::types::jid::JidExt;

impl Client {
    pub(crate) async fn handle_receipt(self: &Arc<Self>, node: &crate::binary::node::Node) {
        let mut attrs = node.attrs();
        let from = attrs.jid("from");
        let id = attrs.string("id");
        let receipt_type_str = attrs.optional_string("type").unwrap_or("delivery");
        let participant = attrs.optional_jid("participant");

        let receipt_type = ReceiptType::from(receipt_type_str.to_string());

        info!("Received receipt type '{receipt_type:?}' for message {id} from {from}");

        // --- START: Handle sender receipts from companion devices ---
        // If this is a 'sender' receipt from a companion device, it acknowledges
        // a PreKey message, allowing us to clear the unacknowledged state and
        // switch to faster SignalMessages for subsequent sends.
        if receipt_type == ReceiptType::Sender && from.is_ad() {
            let client_clone = self.clone();
            let from_clone = from.clone();
            tokio::task::spawn(async move {
                let addr = from_clone.to_protocol_address();
                let device_arc = client_clone.persistence_manager.get_device_arc().await;
                let device_guard = device_arc.read().await;

                // 1. Load the session
                if let Ok(Some(session_bytes)) =
                    device_guard.backend.get_session(&addr.to_string()).await
                {
                    if let Ok(mut session) = SessionRecord::deserialize(&session_bytes) {
                        if let Some(session_state) = session.session_state() {
                            let needs_update = session_state
                                .unacknowledged_pre_key_message_items()
                                .unwrap_or(None)
                                .is_some();

                            // 2. If it has an unacknowledged pre-key, clear it and save back
                            if needs_update {
                                if let Some(session_state_mut) = session.session_state_mut() {
                                    session_state_mut.clear_unacknowledged_pre_key_message();
                                    if let Ok(updated_bytes) = session.serialize() {
                                        if let Err(e) = device_guard
                                            .backend
                                            .put_session(&addr.to_string(), &updated_bytes)
                                            .await
                                        {
                                            log::warn!(
                                                "Failed to save session for {} after clearing unacknowledged pre-key: {}",
                                                addr,
                                                e
                                            );
                                        } else {
                                            log::info!(
                                                "Cleared unacknowledged pre-key for {} on Sender receipt",
                                                addr
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            });
        }
        // --- END: Handle sender receipts from companion devices ---

        let from_clone = from.clone();
        let sender = if from.is_group() {
            if let Some(participant) = participant {
                participant
            } else {
                from_clone
            }
        } else {
            from.clone()
        };

        let receipt = Receipt {
            message_ids: vec![id.clone()],
            source: crate::types::message::MessageSource {
                chat: from.clone(),
                sender: sender.clone(),
                ..Default::default()
            },
            timestamp: chrono::Utc::now(),
            r#type: receipt_type.clone(),
            message_sender: sender.clone(),
        };

        if receipt_type == ReceiptType::Retry {
            let client_clone = Arc::clone(self);
            let node_clone = node.clone();
            task::spawn_local(async move {
                if let Err(e) = client_clone
                    .handle_retry_receipt(&receipt, &node_clone)
                    .await
                {
                    log::warn!(
                        "Failed to handle retry receipt for {}: {:?}",
                        receipt.message_ids[0],
                        e
                    );
                }
            });
        } else {
            self.core.event_bus.dispatch(&Event::Receipt(receipt));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::presence::ReceiptType;
    use wacore::types::jid::Jid;

    #[test]
    fn test_receipt_type_sender_detection() {
        // Test that sender receipt type is correctly parsed
        let receipt_type = ReceiptType::from("sender".to_string());
        assert_eq!(receipt_type, ReceiptType::Sender);
    }

    #[test]
    fn test_receipt_type_delivery_detection() {
        // Test that delivery receipt type is correctly parsed
        let receipt_type = ReceiptType::from("".to_string());
        assert_eq!(receipt_type, ReceiptType::Delivered);
    }

    #[test]
    fn test_companion_device_detection() {
        // Test that companion devices (AD devices) are properly detected
        let jid: Jid = "1234567890:45@s.whatsapp.net".parse().unwrap();
        assert!(jid.is_ad());

        let regular_jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        assert!(!regular_jid.is_ad());
    }
}
