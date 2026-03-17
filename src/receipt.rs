use crate::client::Client;
use crate::types::events::{Event, Receipt};
use crate::types::presence::ReceiptType;
use log::info;
use std::sync::Arc;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, JidExt as _};

use wacore_binary::node::Node;

impl Client {
    fn should_send_delivery_receipt(info: &crate::types::message::MessageInfo) -> bool {
        use wacore_binary::jid::STATUS_BROADCAST_USER;

        if info.id.is_empty()
            || info.source.chat.user == STATUS_BROADCAST_USER
            || info.source.chat.is_newsletter()
        {
            return false;
        }

        // WA Web sends type="peer_msg" delivery receipts for self-synced
        // messages (category="peer").  These tell the primary phone that
        // this companion device received the message.
        // For all other messages, skip receipts for our own messages.
        info.category == "peer" || !info.source.is_from_me
    }

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
        } else if receipt_type == ReceiptType::EncRekeyRetry {
            // WA Web: both "retry" and "enc_rekey_retry" route through
            // handleMessageRetryRequest, but enc_rekey_retry branches to the
            // VoIP stack's resendEncRekeyRetry(peerJid, retryCount).
            // Since we don't have a VoIP stack yet, log and dispatch as a
            // Receipt event so consumers can observe it. When VoIP is
            // implemented (#345), this will route to the VoIP re-key handler.
            if let Some(child) = node.get_optional_child("enc_rekey") {
                let mut attrs = child.attrs();
                log::debug!(
                    "Received enc_rekey_retry receipt for call-id={} from {} \
                     (call-creator={}, count={}). VoIP not implemented, forwarding as event.",
                    attrs.optional_string("call-id").unwrap_or_default(),
                    from,
                    attrs.optional_string("call-creator").unwrap_or_default(),
                    attrs
                        .optional_string("count")
                        .and_then(|s| s.parse::<u8>().ok())
                        .unwrap_or(1),
                );
            }
            self.core.event_bus.dispatch(&Event::Receipt(receipt));
        } else {
            self.core.event_bus.dispatch(&Event::Receipt(receipt));
        }
    }

    /// Sends a delivery receipt to the sender of a message.
    ///
    /// This function handles:
    /// - Direct messages (DMs) - sends receipt to the sender's JID.
    /// - Group messages - sends receipt to the group JID with the sender as a participant.
    /// - Peer device messages (category="peer") - sends `type="peer_msg"` receipt to
    ///   acknowledge self-synced messages from the primary phone.
    /// - It correctly skips sending receipts for status broadcasts, newsletters,
    ///   or messages without an ID.
    pub(crate) async fn send_delivery_receipt(&self, info: &crate::types::message::MessageInfo) {
        if !Self::should_send_delivery_receipt(info) {
            return;
        }

        let mut builder = NodeBuilder::new("receipt")
            .attr("id", &info.id)
            .jid_attr("to", info.source.chat.clone());

        // WA Web: peer device messages (category="peer") use type="peer_msg".
        // Normal delivery receipts omit the type attribute (DROP_ATTR).
        if info.category == "peer" {
            builder = builder.attr("type", "peer_msg");
        }

        // For group messages, the 'participant' attribute is required to identify the sender.
        if info.source.is_group {
            builder = builder.jid_attr("participant", info.source.sender.clone());
        }

        let receipt_node = builder.build();

        info!(target: "Client/Receipt", "Sending {} receipt for message {} to {}",
            if info.category == "peer" { "peer_msg" } else { "delivery" },
            info.id, info.source.sender);

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
    use std::sync::Mutex;
    use wacore::types::events::EventHandler;

    #[derive(Default)]
    struct TestEventCollector {
        events: Mutex<Vec<Event>>,
    }

    impl EventHandler for TestEventCollector {
        fn handle_event(&self, event: &Event) {
            self.events
                .lock()
                .expect("collector mutex should not be poisoned")
                .push(event.clone());
        }
    }

    impl TestEventCollector {
        fn events(&self) -> Vec<Event> {
            self.events
                .lock()
                .expect("collector mutex should not be poisoned")
                .clone()
        }
    }

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

    #[test]
    fn test_should_skip_delivery_receipt_for_newsletter() {
        let info = MessageInfo {
            id: "NEWSLETTER-MSG-ID".to_string(),
            source: MessageSource {
                chat: "120363173003902460@newsletter"
                    .parse()
                    .expect("newsletter JID should be valid"),
                sender: "120363173003902460@newsletter"
                    .parse()
                    .expect("newsletter JID should be valid"),
                is_from_me: false,
                is_group: false,
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(
            !Client::should_send_delivery_receipt(&info),
            "generic delivery receipts must be skipped for newsletters"
        );
    }

    #[test]
    fn test_should_send_peer_msg_receipt_for_self_synced_messages() {
        // Self-synced messages (category="peer") should get delivery receipts
        // even though is_from_me is true.  WA Web sends type="peer_msg" for these.
        let info = MessageInfo {
            id: "PEER-MSG-ID".to_string(),
            source: MessageSource {
                chat: "155500012345@s.whatsapp.net"
                    .parse()
                    .expect("own PN JID should be valid"),
                sender: "155500012345@s.whatsapp.net"
                    .parse()
                    .expect("own PN JID should be valid"),
                is_from_me: true,
                is_group: false,
                ..Default::default()
            },
            category: "peer".to_string(),
            ..Default::default()
        };

        assert!(
            Client::should_send_delivery_receipt(&info),
            "peer device messages must get delivery receipts even when is_from_me"
        );
    }

    /// Create a test client with an event collector registered.
    async fn setup_client_with_collector() -> (Arc<Client>, Arc<TestEventCollector>) {
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

        let collector = Arc::new(TestEventCollector::default());
        client.register_handler(collector.clone());
        (client, collector)
    }

    /// Verify that enc_rekey_retry receipt is dispatched as a Receipt event
    /// with EncRekeyRetry type so consumers can observe it.
    #[tokio::test]
    async fn test_enc_rekey_retry_receipt_dispatches_event() {
        let (client, collector) = setup_client_with_collector().await;

        // Build an enc_rekey_retry receipt node matching WA Web structure
        let node = Arc::new(
            NodeBuilder::new("receipt")
                .attr("from", "5511999999999@s.whatsapp.net")
                .attr("id", "3EB0AABBCCDD")
                .attr("type", "enc_rekey_retry")
                .children([
                    NodeBuilder::new("enc_rekey")
                        .attr("call-creator", "5511888888888@s.whatsapp.net")
                        .attr("call-id", "CALL-123")
                        .attr("count", "1")
                        .build(),
                    NodeBuilder::new("registration")
                        .bytes(12345u32.to_be_bytes().to_vec())
                        .build(),
                ])
                .build(),
        );

        client.handle_receipt(node).await;

        // Must dispatch exactly one Receipt event with EncRekeyRetry type
        let events = collector.events();
        let receipt_events: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                Event::Receipt(r) => Some(r),
                _ => None,
            })
            .collect();
        assert_eq!(
            receipt_events.len(),
            1,
            "enc_rekey_retry must dispatch exactly one Receipt event"
        );
        assert_eq!(
            receipt_events[0].r#type,
            ReceiptType::EncRekeyRetry,
            "dispatched receipt must have EncRekeyRetry type"
        );
        assert_eq!(receipt_events[0].message_ids, vec!["3EB0AABBCCDD"]);
    }

    /// Verify that enc_rekey_retry without <enc_rekey> child still dispatches
    /// the Receipt event (graceful degradation, no crash).
    #[tokio::test]
    async fn test_enc_rekey_retry_receipt_without_child_still_dispatches() {
        let (client, collector) = setup_client_with_collector().await;

        // Malformed: no <enc_rekey> child
        let node = Arc::new(
            NodeBuilder::new("receipt")
                .attr("from", "5511999999999@s.whatsapp.net")
                .attr("id", "3EB0AABBCCDD")
                .attr("type", "enc_rekey_retry")
                .build(),
        );

        client.handle_receipt(node).await;

        // Should still dispatch the Receipt event even without <enc_rekey> child
        let events = collector.events();
        let receipt_events: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                Event::Receipt(r) => Some(r),
                _ => None,
            })
            .collect();
        assert_eq!(
            receipt_events.len(),
            1,
            "malformed enc_rekey_retry must still dispatch Receipt event"
        );
        assert_eq!(receipt_events[0].r#type, ReceiptType::EncRekeyRetry);
    }

    #[test]
    fn test_should_skip_non_peer_self_messages() {
        // Normal self messages (no category) should still be skipped.
        let info = MessageInfo {
            id: "SELF-MSG-ID".to_string(),
            source: MessageSource {
                chat: "155500012345@s.whatsapp.net"
                    .parse()
                    .expect("own PN JID should be valid"),
                sender: "155500012345@s.whatsapp.net"
                    .parse()
                    .expect("own PN JID should be valid"),
                is_from_me: true,
                is_group: false,
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(
            !Client::should_send_delivery_receipt(&info),
            "non-peer self messages must not get delivery receipts"
        );
    }

    /// Verify that receipt nodes use JID-typed attrs for `to` and `participant`,
    /// ensuring the jid_attr optimization is not accidentally regressed to to_string.
    #[test]
    fn test_receipt_node_uses_jid_attrs() {
        use wacore_binary::node::NodeValue;

        let chat_jid: Jid = "120363021033254949@g.us"
            .parse()
            .expect("test JID should be valid");
        let sender_jid: Jid = "15551234567@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");

        // Build a group receipt node using the same pattern as send_delivery_receipt
        let node = NodeBuilder::new("receipt")
            .attr("id", "MSG-123")
            .jid_attr("to", chat_jid.clone())
            .jid_attr("participant", sender_jid.clone())
            .build();

        // "to" must be stored as NodeValue::Jid, not NodeValue::String
        let to_attr = node.attrs.get("to").expect("receipt must have 'to' attr");
        assert!(
            matches!(to_attr, NodeValue::Jid(_)),
            "'to' attr should be JID-typed, got: {:?}",
            to_attr
        );
        assert_eq!(to_attr.as_jid().unwrap(), &chat_jid);

        // "participant" must also be JID-typed
        let participant_attr = node
            .attrs
            .get("participant")
            .expect("group receipt must have 'participant' attr");
        assert!(
            matches!(participant_attr, NodeValue::Jid(_)),
            "'participant' attr should be JID-typed, got: {:?}",
            participant_attr
        );
        assert_eq!(participant_attr.as_jid().unwrap(), &sender_jid);
    }
}
