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
        let id = attrs.string("id");
        let receipt_type_str = attrs.optional_string("type").unwrap_or("delivery");
        let participant = attrs.optional_jid("participant");

        let receipt_type = ReceiptType::from(receipt_type_str.to_string());

        info!("Received receipt type '{receipt_type:?}' for message {id} from {from}");

        let sender = if from.is_group() {
            participant.unwrap_or_else(|| from.clone())
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

    /// Sends read receipts to mark messages as read.
    ///
    /// This function batches multiple message IDs for the same sender and sends
    /// a single receipt stanza per sender. This is used when a user opens a chat
    /// and views messages.
    ///
    /// # Arguments
    /// * `chat_jid` - The JID of the chat (group or individual)
    /// * `messages` - List of (message_id, sender_jid) tuples to mark as read
    pub async fn send_read_receipts(&self, chat_jid: &Jid, messages: &[(String, Jid)]) {
        use wacore_binary::jid::STATUS_BROADCAST_USER;

        // Don't send receipts for status broadcasts
        if chat_jid.user == STATUS_BROADCAST_USER {
            return;
        }

        if messages.is_empty() {
            return;
        }

        let is_group = chat_jid.is_group();

        // Group messages by sender for batching
        let mut by_sender: HashMap<Jid, Vec<String>> = HashMap::new();
        for (msg_id, sender) in messages {
            by_sender
                .entry(sender.clone())
                .or_default()
                .push(msg_id.clone());
        }

        // Send one receipt per sender
        for (sender, msg_ids) in by_sender {
            if msg_ids.is_empty() {
                continue;
            }

            // First message ID goes in the 'id' attribute
            let first_id = msg_ids[0].clone();
            let additional_ids: Vec<_> = msg_ids.into_iter().skip(1).collect();

            let mut attrs = HashMap::new();
            attrs.insert("id".to_string(), first_id.clone());
            attrs.insert("to".to_string(), chat_jid.to_string());
            attrs.insert("type".to_string(), "read".to_string());

            // For group messages, include the participant (original sender)
            if is_group {
                attrs.insert("participant".to_string(), sender.to_string());
            }

            // Build the receipt node
            let mut builder = NodeBuilder::new("receipt").attrs(attrs);

            // If there are additional message IDs, add them in a <list> element
            if !additional_ids.is_empty() {
                let items: Vec<Node> = additional_ids
                    .iter()
                    .map(|id: &String| NodeBuilder::new("item").attr("id", id.clone()).build())
                    .collect();
                let list_node = NodeBuilder::new("list").children(items).build();
                builder = builder.children(vec![list_node]);
            }

            let receipt_node = builder.build();

            let total_count = 1 + additional_ids.len();
            info!(
                target: "Client/Receipt",
                "Sending read receipt for {} message(s) in {} (sender: {})",
                total_count, chat_jid, sender
            );

            if let Err(e) = self.send_node(receipt_node).await {
                log::warn!(
                    target: "Client/Receipt",
                    "Failed to send read receipt for {} messages: {:?}",
                    total_count, e
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SqliteStore;
    use crate::store::persistence_manager::PersistenceManager;
    use crate::test_utils::MockHttpClient;
    use crate::types::message::{MessageInfo, MessageSource};

    #[tokio::test]
    async fn test_send_delivery_receipt_dm() {
        let backend = Arc::new(
            SqliteStore::new(":memory:")
                .await
                .expect("test backend should initialize"),
        );
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
        let backend = Arc::new(
            SqliteStore::new(":memory:")
                .await
                .expect("test backend should initialize"),
        );
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
        let backend = Arc::new(
            SqliteStore::new(":memory:")
                .await
                .expect("test backend should initialize"),
        );
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
        let backend = Arc::new(
            SqliteStore::new(":memory:")
                .await
                .expect("test backend should initialize"),
        );
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
        let backend = Arc::new(
            SqliteStore::new(":memory:")
                .await
                .expect("test backend should initialize"),
        );
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
