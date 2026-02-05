use crate::client::Client;
use crate::types::events::{Event, Receipt};
use crate::types::presence::ReceiptType;
use log::info;
use std::collections::HashMap;
use std::sync::Arc;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, JidExt as _};

use wacore_binary::node::Node;

impl Client {
    pub(crate) async fn handle_receipt(self: &Arc<Self>, node: Arc<Node>) {
        let mut attrs = node.attrs();
        let from = attrs.jid("from");
        let id = match attrs.optional_string("id") {
            Some(id) => id.to_string(),
            None => {
                log::warn!("Receipt stanza missing required 'id' attribute");
                return;
            }
        };
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
            // Arc clone is cheap - just reference count increment
            let node_clone = Arc::clone(&node);
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
            self.core.event_bus.dispatch(&Event::Receipt(receipt));
        }
    }

    /// Sends a delivery receipt to the sender of a message.
    ///
    /// This function handles:
    /// - Direct messages (DMs) - sends receipt to the sender's JID.
    /// - Group messages - sends receipt to the group JID with the sender as a participant.
    /// - It correctly skips sending receipts for self-sent messages, status broadcasts, or messages without an ID.
    pub(crate) async fn send_delivery_receipt(&self, info: &crate::types::message::MessageInfo) {
        use wacore_binary::jid::STATUS_BROADCAST_USER;

        // Don't send receipts for our own messages, status broadcasts, or if ID is missing.
        if info.source.is_from_me
            || info.id.is_empty()
            || info.source.chat.user == STATUS_BROADCAST_USER
        {
            return;
        }

        let mut attrs = HashMap::new();
        attrs.insert("id".to_string(), info.id.clone());
        // The 'to' attribute is always the JID from which the message originated (the chat JID for groups).
        attrs.insert("to".to_string(), info.source.chat.to_string());
        attrs.insert("type".to_string(), "delivery".to_string());

        // For group messages, the 'participant' attribute is required to identify the sender.
        if info.source.is_group {
            attrs.insert("participant".to_string(), info.source.sender.to_string());
        }

        let receipt_node = NodeBuilder::new("receipt").attrs(attrs).build();

        info!(target: "Client/Receipt", "Sending delivery receipt for message {} to {}", info.id, info.source.sender);

        if let Err(e) = self.send_node(receipt_node).await {
            log::warn!(target: "Client/Receipt", "Failed to send delivery receipt for message {}: {:?}", info.id, e);
        }
    }

    /// Sends read receipts for one or more messages.
    ///
    /// For group messages, pass the message sender as `sender`.
    pub async fn mark_as_read(
        &self,
        chat: &Jid,
        sender: Option<&Jid>,
        message_ids: Vec<String>,
    ) -> Result<(), anyhow::Error> {
        if message_ids.is_empty() {
            return Ok(());
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string();

        let mut builder = NodeBuilder::new("receipt")
            .attr("to", chat.to_string())
            .attr("type", "read")
            .attr("id", &message_ids[0])
            .attr("t", &timestamp);

        if let Some(sender) = sender {
            builder = builder.attr("participant", sender.to_string());
        }

        // Additional message IDs go into <list><item id="..."/></list>
        if message_ids.len() > 1 {
            let items: Vec<wacore_binary::node::Node> = message_ids[1..]
                .iter()
                .map(|id| NodeBuilder::new("item").attr("id", id).build())
                .collect();
            builder = builder.children(vec![NodeBuilder::new("list").children(items).build()]);
        }

        let node = builder.build();

        info!(target: "Client/Receipt", "Sending read receipt for {} message(s) to {}", message_ids.len(), chat);

        self.send_node(node)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send read receipt: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::persistence_manager::PersistenceManager;
    use crate::test_utils::MockHttpClient;
    use crate::types::message::{MessageInfo, MessageSource};

    #[tokio::test]
    async fn test_send_delivery_receipt_dm() {
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        let info = MessageInfo {
            id: "TEST-ID-123".to_string(),
            source: MessageSource {
                chat: "12345@s.whatsapp.net"
                    .parse()
                    .expect("test JID should be valid"),
                sender: "12345@s.whatsapp.net"
                    .parse()
                    .expect("test JID should be valid"),
                is_from_me: false,
                is_group: false,
                ..Default::default()
            },
            ..Default::default()
        };

        // This should complete without panicking. The actual node sending
        // would fail since we're not connected, but the function should
        // handle that gracefully and log a warning.
        client.send_delivery_receipt(&info).await;

        // If we got here, the function executed successfully.
        // In a real scenario, we'd need to mock the transport to verify
        // the exact node sent, but basic functionality testing confirms
        // the method doesn't panic and logs appropriately.
    }

    #[tokio::test]
    async fn test_send_delivery_receipt_group() {
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        let info = MessageInfo {
            id: "GROUP-MSG-ID".to_string(),
            source: MessageSource {
                chat: "120363021033254949@g.us"
                    .parse()
                    .expect("test JID should be valid"),
                sender: "15551234567@s.whatsapp.net"
                    .parse()
                    .expect("test JID should be valid"),
                is_from_me: false,
                is_group: true,
                ..Default::default()
            },
            ..Default::default()
        };

        // Should complete without panicking for group messages too.
        client.send_delivery_receipt(&info).await;
    }

    #[tokio::test]
    async fn test_skip_delivery_receipt_for_own_messages() {
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        let info = MessageInfo {
            id: "OWN-MSG-ID".to_string(),
            source: MessageSource {
                chat: "12345@s.whatsapp.net"
                    .parse()
                    .expect("test JID should be valid"),
                sender: "12345@s.whatsapp.net"
                    .parse()
                    .expect("test JID should be valid"),
                is_from_me: true, // Own message
                is_group: false,
                ..Default::default()
            },
            ..Default::default()
        };

        // Should return early without attempting to send.
        // We can't easily assert that send_node was not called without
        // refactoring, but at least verify the function completes.
        client.send_delivery_receipt(&info).await;
    }

    #[tokio::test]
    async fn test_skip_delivery_receipt_for_empty_id() {
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        let info = MessageInfo {
            id: "".to_string(), // Empty ID
            source: MessageSource {
                chat: "12345@s.whatsapp.net"
                    .parse()
                    .expect("test JID should be valid"),
                sender: "12345@s.whatsapp.net"
                    .parse()
                    .expect("test JID should be valid"),
                is_from_me: false,
                is_group: false,
                ..Default::default()
            },
            ..Default::default()
        };

        // Should return early without attempting to send.
        client.send_delivery_receipt(&info).await;
    }

    #[tokio::test]
    async fn test_skip_delivery_receipt_for_status_broadcast() {
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        let info = MessageInfo {
            id: "STATUS-MSG-ID".to_string(),
            source: MessageSource {
                chat: "status@broadcast"
                    .parse()
                    .expect("test JID should be valid"), // Status broadcast
                sender: "12345@s.whatsapp.net"
                    .parse()
                    .expect("test JID should be valid"),
                is_from_me: false,
                is_group: true,
                ..Default::default()
            },
            ..Default::default()
        };

        // Should return early without attempting to send for status broadcasts.
        client.send_delivery_receipt(&info).await;
    }
}
