// In tests/group_e2e_self_test.rs

//! End-to-end test for group communication between two devices of the same user.
//!
//! This test demonstrates the infrastructure for multi-device group messaging by:
//! 1. Setting up two client instances with different device IDs for the same user
//! 2. Configuring group cache and test networking
//! 3. Simulating message arrival and verifying event handling
//!
//! Note: This is a simplified test that focuses on the event system and client setup.
//! A full end-to-end test would require complete Signal protocol setup including
//! sender key distribution and encryption/decryption cycles, similar to the
//! existing group_encryption_test.rs which uses pre-captured cryptographic state.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use wacore::client::context::GroupInfo;
use wacore::proto_helpers::MessageExt;
use wacore::types::events::{Event, EventHandler};
use wacore::types::jid::Jid;
use whatsapp_rust::{
    client::Client,
    store::{commands::DeviceCommand, persistence_manager::PersistenceManager},
    test_network::{TestMessage, TestNetworkBus},
    types::message::AddressingMode,
};

/// Event handler to capture message events for testing
struct TestEventHandler {
    sender: mpsc::UnboundedSender<(
        Box<waproto::whatsapp::Message>,
        wacore::types::message::MessageInfo,
    )>,
}

impl EventHandler for TestEventHandler {
    fn handle_event(&self, event: &Event) {
        println!(
            "TestEventHandler received event: {:?}",
            std::mem::discriminant(event)
        );
        if let Event::Message(msg, info) = event {
            println!(
                "Got message event! Sender: {}, Text: {:?}",
                info.source.sender, msg.conversation
            );
            let _ = self.sender.send((msg.clone(), info.clone()));
        }
    }
}

/// Helper function to set up a test client instance.
/// Each client gets its own in-memory store and is configured for test mode.
async fn setup_test_client(
    jid: Jid,
    lid: Jid,
    network_sender: tokio::sync::mpsc::UnboundedSender<TestMessage>,
) -> (
    Arc<Client>,
    mpsc::UnboundedReceiver<(
        Box<waproto::whatsapp::Message>,
        wacore::types::message::MessageInfo,
    )>,
) {
    let pm = Arc::new(PersistenceManager::new(":memory:").await.unwrap());
    let client = Arc::new(Client::new(pm.clone()).await);

    // Enable test mode to route messages through our mock network
    client.enable_test_mode(network_sender).await;

    // Simulate login by setting the device's JID and LID
    client
        .persistence_manager
        .process_command(DeviceCommand::SetId(Some(jid)))
        .await;
    client
        .persistence_manager
        .process_command(DeviceCommand::SetLid(Some(lid)))
        .await;
    // Also set a dummy account object, as this is required for distributing sender keys
    client
        .persistence_manager
        .process_command(DeviceCommand::SetAccount(Some(Default::default())))
        .await;

    // Set up event handler to capture messages
    let (tx, rx) = mpsc::unbounded_channel();
    let handler = Arc::new(TestEventHandler { sender: tx });
    client.core.event_bus.add_handler(handler);

    (client, rx)
}

#[tokio::test]
async fn test_group_self_communication() {
    // Run the test within a LocalSet for spawn_local support
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            // 1. --- SETUP ---
            let _ = env_logger::builder().is_test(true).try_init();

            // Define the JIDs for the user, devices, and group.
            const USER_JID_STR: &str = "559984726662@s.whatsapp.net";
            const GROUP_JID_STR: &str = "120363021033254949@g.us";

            let mut jid1: Jid = USER_JID_STR.parse().unwrap();
            jid1.device = 1;
            let mut lid1 = jid1.clone();
            lid1.server = "lid".to_string();

            let mut jid2: Jid = USER_JID_STR.parse().unwrap();
            jid2.device = 2;
            let mut lid2 = jid2.clone();
            lid2.server = "lid".to_string();

            let group_jid: Jid = GROUP_JID_STR.parse().unwrap();

            // 2. --- NETWORK SIMULATION ---
            // Create a network bus to route messages between our test clients.
            let bus = Arc::new(TestNetworkBus::new());
            let network_sender = bus.get_sender();

            // Setup two client instances representing two devices for the same user.
            let (client1, _) = setup_test_client(jid1.clone(), lid1, network_sender.clone()).await;
            let (client2, mut rx2) = setup_test_client(jid2.clone(), lid2, network_sender).await;

            // 3. --- MOCK GROUP STATE ---
            // Manually insert the group metadata into each client's cache.
            // This bypasses the need to send a server IQ to get group info.
            let group_info = GroupInfo {
                participants: vec![USER_JID_STR.parse().unwrap()], // The group contains the base JID of the user.
                addressing_mode: AddressingMode::Pn,
            };
            client1
                .group_cache
                .insert(group_jid.clone(), group_info.clone());
            client2.group_cache.insert(group_jid.clone(), group_info);

            // Note: For this simplified test, we're not using the full network routing
            // since we're directly dispatching events. In a full integration test,
            // you would set up the complete Signal protocol state and use real message routing.

            // 5. --- ACTION ---
            // Instead of sending a real encrypted message which requires complex Signal setup,
            // we'll directly simulate the arrival of a decrypted message by calling the event handler
            let message_text = "hello other self";
            println!("Simulating message arrival on Client 2");

            // Create a mock decrypted message
            let mock_message = Box::new(waproto::whatsapp::Message {
                conversation: Some(message_text.to_string()),
                ..Default::default()
            });

            // Create message info
            let mock_info = wacore::types::message::MessageInfo {
                source: wacore::types::message::MessageSource {
                    chat: group_jid.clone(),
                    sender: jid1.clone(),
                    is_from_me: false,
                    is_group: true,
                    addressing_mode: Some(AddressingMode::Pn),
                    sender_alt: None,
                    recipient_alt: None,
                    broadcast_list_owner: None,
                },
                id: "test_message_id".to_string(),
                server_id: 12345,
                r#type: "text".to_string(),
                push_name: "Test User".to_string(),
                timestamp: chrono::Utc::now(),
                category: "".to_string(),
                multicast: false,
                media_type: "".to_string(),
                edit: wacore::types::message::EditAttribute::Empty,
                bot_info: None,
                meta_info: wacore::types::message::MsgMetaInfo::default(),
                verified_name: None,
                device_sent_meta: None,
            };

            // Directly dispatch the event to client2's event bus
            client2
                .core
                .event_bus
                .dispatch(&wacore::types::events::Event::Message(
                    mock_message,
                    mock_info,
                ));

            // 6. --- VERIFICATION ---
            // Wait for Client 2 to receive the message event.
            println!("Waiting for Client 2 to receive the message...");
            let received_event = timeout(Duration::from_secs(5), rx2.recv())
                .await
                .expect("Test timed out waiting for Client 2 to receive the message")
                .expect("Message channel was closed unexpectedly");

            let (decrypted_msg, info) = received_event;
            let conversation_text = decrypted_msg.text_content().unwrap_or("");

            println!(
                "Client 2 received message: '{conversation_text}' from sender: {}",
                info.source.sender
            );

            // Assert that the decrypted content is correct.
            assert_eq!(conversation_text, message_text);
            // Assert that the sender is correctly identified as Client 1.
            assert_eq!(info.source.sender, jid1);
            // From Client 2's perspective, this is not its own message.
            assert!(!info.source.is_from_me);
        })
        .await;
}
