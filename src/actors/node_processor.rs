use super::messages::{NodeProcessorCommand, NodeProcessorEvent, ConnectionManagerCommand, ActorEvent};
use crate::{
    binary::node::Node,
    store::{commands::DeviceCommand, persistence_manager::PersistenceManager},
    types::{events::Event as WhatsAppEvent, jid::Jid}, // Renamed to avoid conflict
    ClientError, // Assuming ClientError might be useful for some responses
};
use dashmap::DashMap;
use log::{debug, error, info, warn};
use std::{
    collections::{HashMap, VecDeque},
    sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc},
};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use whatsapp_proto::whatsapp as wa;


// Copied from client.rs, might need adjustment or to be part of a shared state struct
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RecentMessageKey {
    to: Jid,
    id: String,
}


pub struct NodeProcessor {
    // Command channel to receive instructions
    command_rx: mpsc::Receiver<NodeProcessorCommand>,
    // Event channel to send results/events back to the Client Facade
    client_event_tx: mpsc::Sender<ActorEvent>, // Sends events to the main client/facade
    // Sender channel to ConnectionManager
    conn_manager_tx: mpsc::Sender<ConnectionManagerCommand>,

    // Owned state
    persistence_manager: Arc<PersistenceManager>,
    response_waiters: Arc<Mutex<HashMap<String, oneshot::Sender<Result<Node, anyhow::Error>>>>>,
    id_counter: Arc<AtomicU64>, // For generating unique request IDs
    chat_locks: Arc<DashMap<Jid, Arc<tokio::sync::Mutex<()>>>>,
    lid_pn_map: Arc<Mutex<HashMap<Jid, Jid>>>,
    recent_messages_map: Arc<Mutex<HashMap<RecentMessageKey, wa::Message>>>,
    recent_messages_list: Arc<Mutex<VecDeque<RecentMessageKey>>>,

    // State related to login, managed by NodeProcessor based on WhatsApp protocol nodes
    is_logged_in: Arc<AtomicBool>,
    // TODO: Consider where event handlers live. If here, NodeProcessor dispatches directly.
    // If in Client facade, NodeProcessor sends events via client_event_tx.
    // For now, let's assume it sends events to the facade.
}

impl NodeProcessor {
    pub fn new(
        command_rx: mpsc::Receiver<NodeProcessorCommand>,
        client_event_tx: mpsc::Sender<ActorEvent>,
        conn_manager_tx: mpsc::Sender<ConnectionManagerCommand>,
        persistence_manager: Arc<PersistenceManager>,
        is_logged_in_status: Arc<AtomicBool>, // Pass this in from the facade
    ) -> Self {
        Self {
            command_rx,
            client_event_tx,
            conn_manager_tx,
            persistence_manager,
            response_waiters: Arc::new(Mutex::new(HashMap::new())),
            id_counter: Arc::new(AtomicU64::new(0)), // Initialize as needed
            chat_locks: Arc::new(DashMap::new()),
            lid_pn_map: Arc::new(Mutex::new(HashMap::new())),
            recent_messages_map: Arc::new(Mutex::new(HashMap::with_capacity(256))),
            recent_messages_list: Arc::new(Mutex::new(VecDeque::with_capacity(256))),
            is_logged_in: is_logged_in_status,
        }
    }

    pub async fn run(&mut self) {
        info!("NodeProcessor started");
        while let Some(command) = self.command_rx.recv().await {
            match command {
                NodeProcessorCommand::ProcessDecryptedNode { node, response_tx } => {
                    // This is for direct processing, e.g. from ConnectionManager after decryption
                    // If it's an IQ response, it needs to be routed to `handle_iq_response`
                    if node.tag == "iq" {
                        if self.handle_iq_response_internal(node.clone()).await {
                            // IQ response was handled, no further processing needed by general logic.
                            // If a specific oneshot sender was provided for *this* incoming IQ (unlikely for unsolicited IQs),
                            // it should be used. This `response_tx` is more for when `SendNode` expects a reply.
                            if let Some(tx) = response_tx {
                                // This scenario is a bit mixed. An incoming node usually doesn't have a response_tx
                                // unless it's the reply to something this actor sent.
                                // For now, assuming incoming IQ responses are handled by `response_waiters`
                                // and this `response_tx` is not used here.
                                warn!("ProcessDecryptedNode received an IQ with a response_tx, this path needs review.");
                            }
                            continue;
                        }
                    }
                    // For other nodes or unhandled IQs, pass to general processing
                    self.process_node_internal(node).await;
                }
                NodeProcessorCommand::ProcessIncomingNode(node) => {
                    // General processing for nodes that are not direct IQ responses
                    // or have already been filtered by `handle_iq_response_internal`.
                    self.process_node_internal(node).await;
                }
                NodeProcessorCommand::SendOutgoingNode { node, response_tx } => {
                    let node_id = node.attrs().optional_string("id");
                    if node.tag == "iq" && response_tx.is_some() && node_id.is_some() {
                        let id = node_id.unwrap();
                        // Store the sender if this is an IQ request expecting a response
                        self.response_waiters.lock().await.insert(id, response_tx.unwrap());
                    } else if response_tx.is_some() {
                        warn!("SendOutgoingNode received a non-IQ node with a response_tx. This is unusual.");
                        // We should probably complete the future with an error immediately.
                        let _ = response_tx.unwrap().send(Err(anyhow::anyhow!("Cannot await response for non-IQ node")));
                    }

                    // Marshal and send to ConnectionManager
                    match crate::binary::marshal(&node) {
                        Ok(payload_bytes) => {
                            if self.conn_manager_tx.send(ConnectionManagerCommand::SendFrame(payload_bytes)).await.is_err() {
                                error!("Failed to send SendFrame command to ConnectionManager: receiver dropped.");
                                // If we had a response_tx, we need to complete it with an error.
                                if let Some(id_key) = node.attrs().optional_string("id") {
                                   if let Some(tx) = self.response_waiters.lock().await.remove(&id_key) {
                                       let _ = tx.send(Err(ClientError::NotConnected.into()));
                                   }
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to marshal node for sending: {:?}", e);
                             if let Some(id_key) = node.attrs().optional_string("id") {
                               if let Some(tx) = self.response_waiters.lock().await.remove(&id_key) {
                                   let _ = tx.send(Err(e.into()));
                               }
                            }
                        }
                    }
                }
                NodeProcessorCommand::Shutdown => {
                    info!("NodeProcessor shutting down...");
                    break;
                }
                // Remove the SendNode variant as SendOutgoingNode is more descriptive
                // NodeProcessorCommand::SendNode(node) => { ... }
            }
        }
        info!("NodeProcessor stopped");
    }

    /// Mimics the old Client's handle_iq_response.
    /// Returns true if the IQ was a response and handled, false otherwise.
    async fn handle_iq_response_internal(&self, node: Node) -> bool {
        if let Some(id) = node.attrs().optional_string("id") {
            if let Some(waiter) = self.response_waiters.lock().await.remove(&id) {
                debug!(target: "NodeProcessor", "Handling IQ response for id={}", id);
                if let Err(_node_still_needed_for_error) = waiter.send(Ok(node)) {
                    warn!(target: "NodeProcessor", "IQ response waiter for id={} was dropped before response", id);
                }
                return true;
            }
        }
        false
    }

    /// This is the main dispatcher for incoming nodes, similar to `Client::process_node`.
    /// It should use helper methods for different node types.
    async fn process_node_internal(&self, node: Node) {
        // Logging similar to current client
        if node.tag == "iq" {
            if let Some(sync_node) = node.get_optional_child("sync") {
                if let Some(collection_node) = sync_node.get_optional_child("collection") {
                    let name = collection_node.attrs().string("name");
                    debug!(target: "NodeProcessor/Recv", "Received app state sync response for '{name}' (hiding content).");
                } else {
                    debug!(target: "NodeProcessor/Recv", "{node}");
                }
            } else {
                debug!(target: "NodeProcessor/Recv", "{node}");
            }
        } else {
            debug!(target: "NodeProcessor/Recv", "{node}");
        }

        if node.tag == "xmlstreamend" {
            warn!(target: "NodeProcessor", "Received <xmlstreamend/>, treating as disconnect by server.");
            // This actor doesn't directly control connection, but should notify facade.
            // The ConnectionManager's read_from_socket_loop should also detect socket close.
            // This is more of an application-level signal.
            let _ = self.client_event_tx.send(ActorEvent::ConnectionEvent(ConnectionManagerEvent::Disconnected(false))).await;
            return;
        }

        // IQ responses are handled by `handle_iq_response_internal` before this typically.
        // If an IQ gets here, it's likely an IQ request (type=get/set) from the server.
        // `handle_iq_response_internal` is called from `ProcessDecryptedNode` for direct routing.

        match node.tag.as_str() {
            "success" => self.handle_success_node(&node).await,
            "failure" => self.handle_failure_node(&node).await, // Connect failure
            "stream:error" => self.handle_stream_error_node(&node).await,
            // "ib" => self.handle_ib_node(&node).await, // TODO
            // "notification" => self.handle_notification_node(&node).await, // TODO
            "receipt" => self.handle_receipt_node(&node).await,
            "message" => self.handle_message_node(node).await, // Note: takes ownership of node
            "iq" => {
                // If it's an IQ and wasn't a response handled earlier, it's an incoming request.
                if !self.handle_incoming_iq_request(&node).await {
                     warn!(target: "NodeProcessor", "Received unhandled IQ request: {node}");
                }
            }
            "ack" => { /* Usually no action needed for plain ack */ }
            _ => {
                warn!(target: "NodeProcessor", "Received unknown top-level node: {node}");
            }
        }
    }

    async fn handle_success_node(&self, node: &Node) {
        info!("NodeProcessor: Successfully authenticated with WhatsApp servers!");
        self.is_logged_in.store(true, Ordering::Relaxed);

        // Send LoggedIn event to facade
        let _ = self.client_event_tx.send(ActorEvent::NodeEvent(NodeProcessorEvent::LoggedIn)).await;

        // TODO: Extract LID, pushname updates and dispatch DeviceCommands to PersistenceManager
        // Example:
        // if let Some(lid_str) = node.attrs.get("lid") { ... }
        // self.persistence_manager.process_command(DeviceCommand::SetLid(lid)).await;
        // Dispatch WhatsAppEvent::SelfPushNameUpdated etc. via client_event_tx

        // Spawn a task for post-login actions like sending presence, setting passive mode.
        // These actions will involve sending nodes via self.conn_manager_tx.
        let self_clone_pm = self.persistence_manager.clone();
        let self_clone_conn_tx = self.conn_manager_tx.clone();
        // let self_clone_id_gen = self.id_counter.clone(); // If needed for generating request IDs
        // let self_clone_resp_waiters = self.response_waiters.clone(); // If sending IQs and waiting

        // The following is a simplified version of what Client::handle_success does.
        // It needs to be adapted to send nodes through the conn_manager_tx.
        // For example, set_passive would construct an IQ node and then use
        // conn_manager_tx.send(ConnectionManagerCommand::SendFrame(marshaled_node)).await.

        // Example: self.send_iq_via_conn_manager(passive_iq_node).await;
        // Example: self.send_node_via_conn_manager(presence_node).await;

        // Dispatch Connected event (WhatsApp specific)
        let _ = self.client_event_tx.send(ActorEvent::NodeEvent(NodeProcessorEvent::Event(Arc::new(WhatsAppEvent::Connected(crate::types::events::Connected)))))
            .await;
        info!("NodeProcessor: Dispatched Connected and LoggedIn events.");
    }

    async fn handle_failure_node(&self, node: &Node) {
        // This corresponds to <failure> after login attempt.
        warn!(target: "NodeProcessor", "Received <failure> node: {}", node);
        self.is_logged_in.store(false, Ordering::Relaxed);
        // Notify facade about login failure. ConnectionManager might also send a Disconnected event.
        // The facade will need to coordinate these.
        // Example: Parsing reason code from node.attrs
        let reason_code = node.attrs().optional_u64("reason").unwrap_or(0) as i32;
        let reason = crate::types::events::ConnectFailureReason::from(reason_code);

        let event = if reason.is_logged_out() {
            WhatsAppEvent::LoggedOut(crate::types::events::LoggedOut {
                on_connect: true, // This was a connection attempt failure
                reason,
            })
        } else {
            // Handle other specific failure reasons like TempBanned, ClientOutdated
            // For now, a generic ConnectFailure
            WhatsAppEvent::ConnectFailure(crate::types::events::ConnectFailure {
                reason,
                message: node.attrs().optional_string("message").unwrap_or_default(),
                raw: Some(node.clone()),
            })
        };
        let _ = self.client_event_tx.send(ActorEvent::NodeEvent(NodeProcessorEvent::Event(Arc::new(event)))).await;

        // Also signal a more general "logged out" state if applicable
        if reason.is_logged_out() {
             let _ = self.client_event_tx.send(ActorEvent::NodeEvent(NodeProcessorEvent::LoggedOut)).await;
        }
    }

    async fn handle_stream_error_node(&self, node: &Node) {
        warn!(target: "NodeProcessor", "Received <stream:error> node: {}", node);
        self.is_logged_in.store(false, Ordering::Relaxed);

        // Parse error details
        let code = node.attrs().optional_string("code").unwrap_or_default();
        let conflict_type = node
            .get_optional_child("conflict")
            .map(|n| n.attrs().optional_string("type").unwrap_or_default())
            .unwrap_or_default();

        let mut dispatch_logout_event = false;
        let mut specific_event = None;

        match (code.as_str(), conflict_type.as_str()) {
            ("401", "device_removed") | (_, "replaced") => {
                info!(target: "NodeProcessor", "Stream error: client removed or replaced. Signaling logout.");
                dispatch_logout_event = true;
                specific_event = Some(if conflict_type == "replaced" {
                    WhatsAppEvent::StreamReplaced(crate::types::events::StreamReplaced)
                } else {
                    WhatsAppEvent::LoggedOut(crate::types::events::LoggedOut {
                        on_connect: false, // Not during a connect attempt, but an active stream
                        reason: crate::types::events::ConnectFailureReason::LoggedOut, // Or a more specific reason
                    })
                });
            }
            // Other stream errors can be handled here
            _ => {
                 specific_event = Some(WhatsAppEvent::StreamError(crate::types::events::StreamError{
                    code,
                    raw: Some(node.clone()),
                 }));
            }
        }

        if let Some(evt) = specific_event {
            let _ = self.client_event_tx.send(ActorEvent::NodeEvent(NodeProcessorEvent::Event(Arc::new(evt)))).await;
        }
        if dispatch_logout_event {
            let _ = self.client_event_tx.send(ActorEvent::NodeEvent(NodeProcessorEvent::LoggedOut)).await;
        }

        // Stream error implies the connection will be/is closed.
        // ConnectionManager's read loop should detect this and send Disconnected.
        // NodeProcessor might also inform the facade.
        let _ = self.client_event_tx.send(ActorEvent::ConnectionEvent(ConnectionManagerEvent::Disconnected(false))).await;
    }


    async fn handle_receipt_node(&self, node: &Node) {
        // Basic parsing, similar to Client::handle_receipt
        let mut attrs = node.attrs();
        let from = attrs.jid("from");
        let id = attrs.string("id");
        let receipt_type_str = attrs.optional_string("type").unwrap_or("delivery");
        let participant = attrs.optional_jid("participant");
        let receipt_type = crate::types::presence::ReceiptType::from(receipt_type_str.to_string());

        info!("NodeProcessor: Received receipt type '{receipt_type:?}' for message {id} from {from}");

        let sender = if from.is_group() && participant.is_some() {
            participant.unwrap()
        } else {
            from.clone()
        };

        let receipt_event = WhatsAppEvent::Receipt(crate::types::events::Receipt {
            message_ids: vec![id.clone()],
            source: crate::types::message::MessageSource {
                chat: from.clone(),
                sender: sender.clone(),
                ..Default::default()
            },
            timestamp: chrono::Utc::now(),
            r#type: receipt_type.clone(),
            message_sender: sender.clone(),
        });

        // TODO: Handle retry receipts by resending the message.
        // This would involve:
        // 1. Getting the original message (e.g., from recent_messages_map).
        // 2. Clearing the Signal session for the recipient.
        // 3. Re-encrypting and sending the message via ConnectionManager.

        let _ = self.client_event_tx.send(ActorEvent::NodeEvent(NodeProcessorEvent::Event(Arc::new(receipt_event)))).await;
    }

    async fn handle_message_node(&self, node: Node) {
        // This is a simplified placeholder. The actual message handling involves:
        // - Parsing message info (sender, recipient, etc.)
        // - Acquiring chat lock (using self.chat_locks)
        // - Decrypting the message (Signal protocol, using PersistenceManager for store access)
        // - Handling app state sync messages if they arrive as <message>
        // - Dispatching WhatsAppEvent::Message or other relevant events.

        // Example: (Very simplified, actual decryption is complex)
        info!("NodeProcessor: Received <message> node. Content (if any) needs decryption.");
        // let info = match self.parse_message_info(&node).await { ... }
        // let chat_jid = info.source.chat;
        // let _lock_guard = self.chat_locks.entry(chat_jid).or_default().clone().lock().await;

        // Actual decryption logic would go here, using methods that might now live in a
        // helper module or within NodeProcessor, accessing store via self.persistence_manager.
        // For now, we'll just dispatch a placeholder event.

        // Placeholder: Assume we parsed/decrypted and have a WhatsAppMessage
        // let decrypted_message_event = WhatsAppEvent::Message( ... );
        // let _ = self.client_event_tx.send(ActorEvent::NodeEvent(NodeProcessorEvent::Event(Arc::new(decrypted_message_event)))).await;

        warn!("NodeProcessor: Full message handling (decryption, etc.) for <message> node is not yet implemented in the actor model.");
        // For now, just forward the raw node as a generic event for debugging or partial handling
        let generic_event = WhatsAppEvent::RawNode(node);
         let _ = self.client_event_tx.send(ActorEvent::NodeEvent(NodeProcessorEvent::Event(Arc::new(generic_event)))).await;
    }

    async fn handle_incoming_iq_request(&self, node: &Node) -> bool {
        // Handle IQ requests from the server (e.g., ping)
        if let Some("get") = node.attrs().optional_string("type") {
            if let Some(_ping_node) = node.get_optional_child("ping") {
                info!(target: "NodeProcessor", "Received ping, sending pong.");
                let mut parser = node.attrs();
                let from_jid = parser.jid("from");
                let id = parser.string("id");
                let pong = Node {
                    tag: "iq".into(),
                    attrs: [
                        ("to".into(), from_jid.to_string()),
                        ("id".into(), id),
                        ("type".into(), "result".into()),
                    ]
                    .iter()
                    .cloned()
                    .collect(),
                    content: None,
                };
                // Send pong via ConnectionManager
                match crate::binary::marshal(&pong) {
                    Ok(payload) => {
                        if self.conn_manager_tx.send(ConnectionManagerCommand::SendFrame(payload)).await.is_err() {
                            error!("Failed to send pong to ConnectionManager");
                        }
                    }
                    Err(e) => error!("Failed to marshal pong: {:?}", e),
                }
                return true; // Handled
            }
            // TODO: Handle other GET IQs from server if necessary
        }
        // TODO: Handle SET IQs from server if necessary

        // Handle pair IQs (this logic was in client.rs pair::handle_iq)
        // This needs to be refactored to work within the actor model.
        // It will likely involve sending DeviceCommands and dispatching events.
        // For now, returning false to indicate it's not handled here.
        // if crate::pair::handle_iq_actor(self, node).await { // Imaginary refactored version
        //     return true;
        // }

        false // Not handled by this basic logic
    }

    // TODO: Implement methods for:
    // - handle_ib_node
    // - handle_notification_node
    // - parse_message_info (if message decryption happens here)
    // - handle_encrypted_message (actual decryption logic)
    // - add_recent_message / get_recent_message
    // - handle_retry_receipt (complex, involves resending)
    // - query_group_info (sends IQ, waits for response)
    // - get_user_devices (sends IQ, waits for response)

    // Helper to generate unique IDs for requests
    #[allow(dead_code)] // Will be used when sending IQs
    fn generate_request_id_internal(&self) -> String {
        // This needs to be unique per client instance, not globally unique if multiple clients run
        let count = self.id_counter.fetch_add(1, Ordering::Relaxed);
        // Prefix with something to make it more unique if multiple NodeProcessors exist,
        // though typically there's one per Client.
        // For now, let's assume the original client's unique_id is not directly available here.
        // A simple counter might be sufficient if IDs only need to be unique for outstanding requests.
        // The original client used: format!("{}.{}-{}", self.unique_id, base_id, count)
        // We might need a unique prefix for the NodeProcessor instance if that level of uniqueness is required.
        // For now, a simple incrementing counter.
        format!("np-{}", count)
    }
}


// Helper to spawn the NodeProcessor in its own task
pub fn spawn_node_processor(
    buffer_size: usize,
    client_event_tx: mpsc::Sender<ActorEvent>,
    conn_manager_tx: mpsc::Sender<ConnectionManagerCommand>,
    persistence_manager: Arc<PersistenceManager>,
    is_logged_in_status: Arc<AtomicBool>,
) -> mpsc::Sender<NodeProcessorCommand> {
    let (cmd_tx, cmd_rx) = mpsc::channel(buffer_size);
    let mut processor = NodeProcessor::new(
        cmd_rx,
        client_event_tx,
        conn_manager_tx,
        persistence_manager,
        is_logged_in_status,
    );

    tokio::spawn(async move {
        processor.run().await;
    });

    cmd_tx
}
