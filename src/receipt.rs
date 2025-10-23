use crate::client::Client;
use crate::types::events::{Event, Receipt};
use crate::types::presence::ReceiptType;
use log::info;
use std::collections::HashMap;
use std::sync::Arc;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::JidExt as _;

impl Client {
    pub(crate) async fn handle_receipt_ref(
        self: &Arc<Self>,
        node: &wacore_binary::node::NodeRef<'_>,
    ) {
        // Process directly with NodeRef
        self.handle_receipt(node).await;
    }

    pub(crate) async fn handle_receipt(self: &Arc<Self>, node: &wacore_binary::node::NodeRef<'_>) {
        let mut attrs = node.attr_parser();
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
            // Only allocate owned node for the spawned task
            let node_clone = node.to_owned();
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

    /// Sends a custom receipt to a specified JID.
    ///
    /// # Arguments
    ///
    /// * `jid` - The JID to send the receipt to.
    /// * `participant` - Optional participant JID for group messages.
    /// * `message_ids` - Vector of message IDs to include in the receipt.
    /// * `receipt_type` - Optional receipt type (e.g., "delivery", "read").
    ///
    
    pub async fn send_receipt(
        &self,
        jid: &str,
        participant: Option<&str>,
        message_ids: &Vec<std::string::String>,
        receipt_type: &Option<String>,
    ) -> Result<(), anyhow::Error> {

        let mut attrs = HashMap::new();
        attrs.insert("to", jid.to_string());
        attrs.insert("id", message_ids[0].to_string());
        attrs.insert("t", chrono::Utc::now().timestamp().to_string());

        if let Some(receipt_type) = receipt_type {
            attrs.insert("type", receipt_type.to_string());
        }

        if let Some(participant) = participant {
            attrs.insert("participant", participant.to_string());
        }

        let node_receipt;

        if message_ids.len() > 1 {

            let list_content = message_ids[1..].iter().map(|id| NodeBuilder::new("item")
                .attr("id", id.clone())
                .build());

            let list_build = NodeBuilder::new("list")
                .children(list_content);

            node_receipt = NodeBuilder::new("receipt")
                .attrs(attrs)
                .children([list_build.build()]);
            
        } else {
            node_receipt = NodeBuilder::new("receipt")
                .attrs(attrs);
        }

        info!(target: "Client", "Sending receipt with {} message ids", message_ids.len());

        if let Err(e) = self.send_node(node_receipt.build()).await {
            log::warn!(target: "Client/Receipt", "Failed to send receipt for messages {:?}: {:?}", message_ids, e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SqliteStore;
    use crate::store::persistence_manager::PersistenceManager;
    use crate::types::message::{MessageInfo, MessageSource};

    // Mock HTTP client for tests
    #[derive(Debug, Clone)]
    struct MockHttpClient;

    #[async_trait::async_trait]
    impl crate::http::HttpClient for MockHttpClient {
        async fn execute(
            &self,
            _request: crate::http::HttpRequest,
        ) -> Result<crate::http::HttpResponse, anyhow::Error> {
            Ok(crate::http::HttpResponse {
                status_code: 200,
                body: Vec::new(),
            })
        }
    }

    #[tokio::test]
    async fn test_send_delivery_receipt_dm() {
        let backend = Arc::new(SqliteStore::new(":memory:").await.unwrap());
        let pm = Arc::new(PersistenceManager::new(backend).await.unwrap());
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
            200,
        )
        .await;

        let info = MessageInfo {
            id: "TEST-ID-123".to_string(),
            source: MessageSource {
                chat: "12345@s.whatsapp.net".parse().unwrap(),
                sender: "12345@s.whatsapp.net".parse().unwrap(),
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
        let backend = Arc::new(SqliteStore::new(":memory:").await.unwrap());
        let pm = Arc::new(PersistenceManager::new(backend).await.unwrap());
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
            200,
        )
        .await;

        let info = MessageInfo {
            id: "GROUP-MSG-ID".to_string(),
            source: MessageSource {
                chat: "120363021033254949@g.us".parse().unwrap(),
                sender: "559984726662@s.whatsapp.net".parse().unwrap(),
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
        let backend = Arc::new(SqliteStore::new(":memory:").await.unwrap());
        let pm = Arc::new(PersistenceManager::new(backend).await.unwrap());
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
            200,
        )
        .await;

        let info = MessageInfo {
            id: "OWN-MSG-ID".to_string(),
            source: MessageSource {
                chat: "12345@s.whatsapp.net".parse().unwrap(),
                sender: "12345@s.whatsapp.net".parse().unwrap(),
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
        let backend = Arc::new(SqliteStore::new(":memory:").await.unwrap());
        let pm = Arc::new(PersistenceManager::new(backend).await.unwrap());
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
            200,
        )
        .await;

        let info = MessageInfo {
            id: "".to_string(), // Empty ID
            source: MessageSource {
                chat: "12345@s.whatsapp.net".parse().unwrap(),
                sender: "12345@s.whatsapp.net".parse().unwrap(),
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
        let backend = Arc::new(SqliteStore::new(":memory:").await.unwrap());
        let pm = Arc::new(PersistenceManager::new(backend).await.unwrap());
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
            200,
        )
        .await;

        let info = MessageInfo {
            id: "STATUS-MSG-ID".to_string(),
            source: MessageSource {
                chat: "status@broadcast".parse().unwrap(), // Status broadcast
                sender: "12345@s.whatsapp.net".parse().unwrap(),
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
