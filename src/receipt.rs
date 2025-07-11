use crate::client::Client;
use crate::types::events::{Event, Receipt};
use crate::types::presence::ReceiptType;
use log::info;
use std::sync::Arc;

impl Client {
    pub(crate) async fn handle_receipt(self: &Arc<Self>, node: &crate::binary::node::Node) {
        let mut attrs = node.attrs();
        let from = attrs.jid("from");
        let id = attrs.string("id");
        let receipt_type_str = attrs.optional_string("type").unwrap_or("delivery");
        let participant = attrs.optional_jid("participant");

        let receipt_type = ReceiptType::from(receipt_type_str.to_string());

        info!("Received receipt type '{receipt_type:?}' for message {id} from {from}");

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
            tokio::spawn(async move {
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
            self.dispatch_event(Event::Receipt(receipt)).await;
        }
    }
}
