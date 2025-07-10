use crate::actors::{
    self, // Import the actors module itself
    connection_manager::{spawn_connection_manager, ConnectionManagerCommand, ConnectionManagerEvent},
    messages::{ActorEvent, ClientActorCommand, NodeProcessorCommand, NodeProcessorEvent},
    node_processor::spawn_node_processor,
};
use crate::binary::node::Node;
// use crate::handshake; // Handled by ConnectionManager
use crate::pair; // TODO: Refactor pair logic or move to NodeProcessor
use crate::qrcode;
use crate::store::{commands::DeviceCommand, persistence_manager::PersistenceManager};
// use crate::handlers; // Handled by NodeProcessor
use crate::types::events::{ConnectFailureReason, Event as WhatsAppEvent}; // Renamed Event to WhatsAppEvent
use crate::types::presence::Presence;
use crate::request::IqError; // For send_iq


// use dashmap::DashMap; // Moved to NodeProcessor
use log::{debug, error, info, warn};
// use rand::RngCore; // Used for unique_id, may not be needed if actors manage their own IDs or if not used externally
// use scopeguard; // Used in old connect, not directly here
// use std::collections::{HashMap, VecDeque}; // Moved to NodeProcessor
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering}; // Removed AtomicU64, AtomicUsize if NEXT_HANDLER_ID moves
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex, Notify, RwLock, oneshot}; // Added oneshot
use tokio::time::{sleep, Duration};

// use crate::socket::{FrameSocket, NoiseSocket, SocketError}; // Abstracted by ConnectionManager
use crate::socket::SocketError; // Still needed for ClientError
// use whatsapp_proto::whatsapp as wa; // Used in recent_messages, moved to NodeProcessor

pub type EventHandler = Box<dyn Fn(Arc<WhatsAppEvent>) + Send + Sync>; // Changed Event to WhatsAppEvent
pub(crate) struct WrappedHandler {
    pub(crate) id: usize,
    handler: EventHandler,
}
static NEXT_HANDLER_ID: AtomicUsize = AtomicUsize::new(1); // TODO: Consider if event handling moves entirely to NodeProcessor

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("client is not connected")]
    NotConnected,
    #[error("socket error: {0}")]
    Socket(#[from] SocketError), // This might change if SocketError is not exposed directly
    #[error("client is already connected")]
    AlreadyConnected,
    #[error("client is not logged in")]
    NotLoggedIn,
    #[error("failed to send command to actor: {0}")]
    ActorSendError(String),
    #[error("actor command failed: {0}")]
    ActorCommandFailed(String),
    #[error("IQ request timed out or failed")]
    IqRequestFailed(#[from] IqError), // Added for send_iq
}

impl<T> From<mpsc::error::SendError<T>> for ClientError {
    fn from(e: mpsc::error::SendError<T>) -> Self {
        ClientError::ActorSendError(e.to_string())
    }
}


// RecentMessageKey moved to NodeProcessor

pub struct Client {
    // --- Actor Communication Channels ---
    conn_manager_cmd_tx: mpsc::Sender<ConnectionManagerCommand>,
    node_processor_cmd_tx: mpsc::Sender<NodeProcessorCommand>,
    // actor_event_rx is handled in the run_actor_event_loop

    // --- Client State ---
    pub persistence_manager: Arc<PersistenceManager>, // Remains, as actors might need it passed in commands
    pub media_conn: Arc<Mutex<Option<crate::mediaconn::MediaConn>>>, // TODO: Actor-ize this too? For now, keep.

    // High-level status flags, potentially updated by actor events
    pub(crate) is_logged_in: Arc<AtomicBool>, // Shared with NodeProcessor, updated by it
    pub(crate) is_connecting: Arc<AtomicBool>, // Managed by Client facade during connect sequence
    pub(crate) is_running: Arc<AtomicBool>,    // Overall status of the client facade's run loop
    pub(crate) shutdown_notifier: Arc<Notify>, // To signal shutdown to the main run loop and actors

    pub(crate) event_handlers: Arc<RwLock<Vec<WrappedHandler>>>, // Event handlers for WhatsAppEvent

    // Connection retry logic state
    pub enable_auto_reconnect: Arc<AtomicBool>,
    pub auto_reconnect_errors: Arc<AtomicU32>, // Number of consecutive errors
    pub last_successful_connect: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,
    // pub(crate) last_buffer_cleanup: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>, // TODO: Move to NodeProcessor or a relevant actor

    // Unique ID for the client, might be useful for logging or actor identification if needed
    // pub(crate) unique_id: String, // If needed, generate in new()
}

impl Client {
    pub fn new(persistence_manager: Arc<PersistenceManager>) -> Arc<Self> {
        // Buffer size for actor channels
        const ACTOR_CHANNEL_BUFFER: usize = 32;

        let (conn_cmd_tx, mut conn_evt_rx) = spawn_connection_manager(ACTOR_CHANNEL_BUFFER);

        // This Arc<AtomicBool> will be shared with NodeProcessor so it can update login status
        let is_logged_in_status = Arc::new(AtomicBool::new(false));

        let (actor_event_tx_for_np, mut actor_event_rx_from_np) = mpsc::channel::<ActorEvent>(ACTOR_CHANNEL_BUFFER);


        let node_processor_cmd_tx = spawn_node_processor(
            ACTOR_CHANNEL_BUFFER,
            actor_event_tx_for_np.clone(), // NodeProcessor sends events back to client facade
            conn_cmd_tx.clone(),
            persistence_manager.clone(),
            is_logged_in_status.clone(),
        );

        let client_arc = Arc::new(Self {
            conn_manager_cmd_tx: conn_cmd_tx,
            node_processor_cmd_tx,
            persistence_manager,
            media_conn: Arc::new(Mutex::new(None)), // Keep for now
            is_logged_in: is_logged_in_status,
            is_connecting: Arc::new(AtomicBool::new(false)),
            is_running: Arc::new(AtomicBool::new(false)),
            shutdown_notifier: Arc::new(Notify::new()),
            event_handlers: Arc::new(RwLock::new(Vec::new())),
            enable_auto_reconnect: Arc::new(AtomicBool::new(true)),
            auto_reconnect_errors: Arc::new(AtomicU32::new(0)),
            last_successful_connect: Arc::new(Mutex::new(None)),
            // last_buffer_cleanup: Arc::new(Mutex::new(None)), // Moved
            // unique_id: format!("{}.{}", unique_id_bytes[0], unique_id_bytes[1]), // Generate if needed
        });

        // Spawn the event loop for this client instance
        let self_clone_for_event_loop = client_arc.clone();
        tokio::spawn(async move {
            self_clone_for_event_loop.run_actor_event_loop(conn_evt_rx, actor_event_rx_from_np).await;
        });

        client_arc
    }

    /// Main loop for the Client facade. Spawns actors and manages overall lifecycle.
    pub async fn run(self: &Arc<Self>) {
        if self.is_running.swap(true, Ordering::SeqCst) {
            warn!("Client `run` method called while already running.");
            return;
        }
        info!("Client facade started. Actors are running in background tasks.");

        // The primary role of this run loop is now to manage the auto-reconnection logic
        // and respond to shutdown signals. The actual work is done by actors.
        // It could also be responsible for initiating the first connection attempt.

        // Initial connection attempt
        if self.enable_auto_reconnect.load(Ordering::Relaxed) {
            info!("Initiating first connection attempt...");
            if let Err(e) = self.connect().await {
                error!("Initial connection attempt failed: {:?}", e);
                // Reconnection logic below will handle retries if enabled.
            }
        }

        loop {
            tokio::select! {
                biased;
                _ = self.shutdown_notifier.notified() => {
                    info!("Client facade shutdown signaled. Stopping run loop.");
                    self.is_running.store(false, Ordering::Relaxed);
                    // TODO: Signal actors to shut down gracefully if they haven't already.
                    // For example, send a Shutdown command to NodeProcessor.
                    // ConnectionManager might just close its command channel.
                    let _ = self.node_processor_cmd_tx.send(NodeProcessorCommand::Shutdown).await;
                    // Dropping conn_manager_cmd_tx will cause its loop to exit.
                    break;
                }
                // Reconnection logic is now primarily driven by events from ConnectionManager
                // (ConnectionFailed, Disconnected) handled in `run_actor_event_loop`.
                // This loop mostly just keeps running until shutdown.
                // We might add a periodic check or wait for a specific condition if needed.
                _ = tokio::time::sleep(Duration::from_secs(60)) => { // Keep alive / check
                    if !self.is_running.load(Ordering::Relaxed) {
                        break; // Exit if is_running was set to false elsewhere
                    }
                }
            }
        }
        self.is_running.store(false, Ordering::Relaxed);
        info!("Client facade run loop has shut down.");
    }


    /// This loop processes events from ConnectionManager and NodeProcessor.
    async fn run_actor_event_loop(
        self: &Arc<Self>,
        mut conn_manager_events: mpsc::Receiver<ConnectionManagerEvent>,
        mut node_processor_events: mpsc::Receiver<ActorEvent>, // Assuming NodeProcessor sends ActorEvent
    ) {
        info!("Client event loop started, listening for actor events.");
        loop {
            tokio::select! {
                Some(event) = conn_manager_events.recv() => {
                    debug!("Received ConnectionManagerEvent: {:?}", event);
                    match event {
                        ConnectionManagerEvent::Connected => {
                            info!("Event: Connected (from ConnectionManager)");
                            self.is_connecting.store(false, Ordering::Relaxed);
                            // self.is_logged_in is set by NodeProcessor based on <success> node
                            *self.last_successful_connect.lock().await = Some(chrono::Utc::now());
                            self.auto_reconnect_errors.store(0, Ordering::Relaxed);
                            // NodeProcessor will send WhatsAppEvent::Connected after <success>
                        }
                        ConnectionManagerEvent::ConnectionFailed(reason) => {
                            error!("Event: ConnectionFailed (from ConnectionManager): {:?}", reason);
                            self.is_connecting.store(false, Ordering::Relaxed);
                            self.is_logged_in.store(false, Ordering::Relaxed); // Explicitly set here too
                            self.dispatch_event(WhatsAppEvent::ConnectFailure(crate::types::events::ConnectFailure{
                                reason,
                                message: "Connection failed at socket/handshake level".to_string(),
                                raw: None,
                            })).await;
                            self.try_reconnect("connection_failed_cm").await;
                        }
                        ConnectionManagerEvent::Disconnected(expected) => {
                            info!("Event: Disconnected (from ConnectionManager), expected: {}", expected);
                            let was_logged_in = self.is_logged_in.swap(false, Ordering::Relaxed);
                            self.is_connecting.store(false, Ordering::Relaxed);

                            if !expected {
                                self.dispatch_event(WhatsAppEvent::Disconnected(crate::types::events::Disconnected)).await;
                                if was_logged_in { // Only try to reconnect if we were actually logged in and it wasn't expected
                                    self.try_reconnect("disconnected_cm_unexpected").await;
                                }
                            } else {
                                // If expected, likely initiated by self.disconnect() or server XML stream end
                                info!("Expected disconnect, not attempting auto-reconnect from CM event.");
                            }
                        }
                        ConnectionManagerEvent::FrameReceived(decrypted_frame) => {
                            // Pass decrypted frame to NodeProcessor
                            match crate::binary::util::unpack(&decrypted_frame) {
                                Ok(unpacked_data_cow) => {
                                    match crate::binary::unmarshal_ref(unpacked_data_cow.as_ref()) {
                                        Ok(node_ref) => {
                                            let node = node_ref.to_owned();
                                            // TODO: Consider if a response_tx is needed here.
                                            // For unsolicited frames, probably not.
                                            if self.node_processor_cmd_tx.send(NodeProcessorCommand::ProcessDecryptedNode { node, response_tx: None }).await.is_err() {
                                                error!("Failed to send ProcessDecryptedNode to NodeProcessor: channel closed.");
                                            }
                                        }
                                        Err(e) => log::warn!(target: "Client/ActorLoop", "Failed to unmarshal node: {e}"),
                                    }
                                }
                                Err(e) => log::warn!(target: "Client/ActorLoop", "Failed to decompress frame: {e}"),
                            }
                        }
                    }
                }
                Some(actor_event) = node_processor_events.recv() => {
                    debug!("Received ActorEvent from NodeProcessor: {:?}", actor_event);
                    match actor_event {
                        ActorEvent::NodeEvent(np_event) => match np_event {
                            NodeProcessorEvent::Event(wa_event) => {
                                self.dispatch_event_arc(wa_event).await; // Dispatch WhatsApp specific events
                            }
                            NodeProcessorEvent::LoggedIn => {
                                info!("Event: LoggedIn (from NodeProcessor)");
                                // is_logged_in Arc is already updated by NodeProcessor
                                // No need to dispatch WhatsAppEvent::Connected here, NP does it.
                            }
                            NodeProcessorEvent::LoggedOut => {
                                info!("Event: LoggedOut (from NodeProcessor, e.g. due to stream error)");
                                self.is_logged_in.store(false, Ordering::Relaxed);
                                // NodeProcessor might have already dispatched a specific logout event (e.g. StreamReplaced)
                                // This is a more general state update.
                                // Consider if reconnection is needed based on *why* it logged out.
                                // For now, if auto-reconnect is on, a subsequent Disconnected event might trigger it.
                            }
                        },
                        ActorEvent::ConnectionEvent(cm_event) => {
                            // This allows NodeProcessor to signal connection changes if it detects them at protocol level
                             match cm_event {
                                ConnectionManagerEvent::Disconnected(expected) => {
                                    info!("Event: Disconnected (from NodeProcessor, e.g. xmlstreamend), expected: {}", expected);
                                    let was_logged_in = self.is_logged_in.swap(false, Ordering::Relaxed);
                                    self.is_connecting.store(false, Ordering::Relaxed);
                                    if !expected {
                                         self.dispatch_event(WhatsAppEvent::Disconnected(crate::types::events::Disconnected)).await;
                                         if was_logged_in {
                                            self.try_reconnect("disconnected_np_unexpected").await;
                                         }
                                    } else {
                                        info!("Expected disconnect signaled by NodeProcessor.");
                                        // This might be redundant if ConnectionManager also sends one.
                                        // The important part is that we don't try to reconnect if it's expected.
                                    }
                                },
                                _ => warn!("Received unhandled ConnectionEvent {:?} from NodeProcessor", cm_event),
                             }
                        }
                    }
                }
                // Graceful shutdown: if the client's main `run` loop signals shutdown via `shutdown_notifier`
                // or if `is_running` becomes false.
                _ = self.shutdown_notifier.notified(), if self.is_running.load(Ordering::Relaxed) => {
                    info!("Client event loop: shutdown signaled via notifier.");
                    break;
                }
                else => {
                    // All channels closed or some other issue.
                    if !self.is_running.load(Ordering::Relaxed) {
                         info!("Client event loop: is_running is false, shutting down.");
                    } else {
                        warn!("Client event loop: all actor event channels seem closed. Shutting down loop.");
                        self.is_running.store(false, Ordering::Relaxed); // Ensure main loop also stops
                        self.shutdown_notifier.notify_waiters(); // Signal main loop
                    }
                    break;
                }
            }
        }
        info!("Client actor event loop has shut down.");
    }


    async fn try_reconnect(self: &Arc<Self>, reason_tag: &str) {
        if !self.is_running.load(Ordering::Relaxed) || !self.enable_auto_reconnect.load(Ordering::Relaxed) {
            info!("Reconnection attempt skipped (reason: {}, not running or auto-reconnect disabled).", reason_tag);
            return;
        }

        if self.is_connecting.load(Ordering::Relaxed) {
            info!("Reconnection attempt skipped (reason: {}), already connecting.", reason_tag);
            return;
        }

        let error_count = self.auto_reconnect_errors.fetch_add(1, Ordering::SeqCst);
        let delay_secs = u64::from(error_count * 2).min(30); // Exponential backoff up to 30s
        let delay = Duration::from_secs(delay_secs);

        info!(
            "Will attempt to reconnect (reason: {}) in {:?} (attempt {})",
            reason_tag,
            delay,
            error_count + 1
        );

        tokio::select! {
            _ = sleep(delay) => {
                if self.is_running.load(Ordering::Relaxed) && self.enable_auto_reconnect.load(Ordering::Relaxed) {
                    info!("Attempting reconnection now (reason: {})...", reason_tag);
                    if let Err(e) = self.connect().await {
                        error!("Reconnection attempt failed (reason: {}): {:?}", reason_tag, e);
                        // The ConnectionFailed event from this attempt will trigger another `try_reconnect` if needed.
                    } else {
                        info!("Reconnection attempt initiated successfully (reason: {}).", reason_tag);
                        // Success means ConnectionManagerEvent::Connected will be received, resetting error count.
                    }
                } else {
                    info!("Reconnection aborted (reason: {}), client stopped or auto-reconnect disabled during delay.", reason_tag);
                }
            },
            _ = self.shutdown_notifier.notified() => {
                info!("Reconnection aborted (reason: {}), shutdown signaled during delay.", reason_tag);
                self.is_running.store(false, Ordering::Relaxed);
            }
        }
    }


    pub async fn connect(self: &Arc<Self>) -> Result<(), ClientError> {
        if self.is_connecting.swap(true, Ordering::SeqCst) {
            warn!("Connect called while already attempting to connect.");
            return Err(ClientError::AlreadyConnected);
        }
        // Ensure is_connecting is reset on any exit from this scope (normal or panic)
        // scopeguard might be an option if there are complex early returns.
        // For now, manual reset in success/error paths of the event loop.

        info!("Sending Connect command to ConnectionManager...");
        self.conn_manager_cmd_tx
            .send(ConnectionManagerCommand::Connect {
                persistence_manager: self.persistence_manager.clone(),
            })
            .await?;
        // The actual connection result will come as an event (Connected or ConnectionFailed)
        // and update is_connecting, is_logged_in state there.
        Ok(())
    }

    pub async fn disconnect(&self) -> Result<(), ClientError> {
        info!("Client facade: Disconnecting intentionally.");
        // self.expected_disconnect.store(true, Ordering::Relaxed); // TODO: How to signal this to event loop/actors?
        // Actors should ideally not auto-reconnect if this is called.
        // Perhaps a specific Disconnect(expected: true) command?
        // For now, ConnectionManager's Disconnect command implies it's expected.
        self.enable_auto_reconnect.store(false, Ordering::Relaxed); // Prevent auto-reconnect after this
        self.is_running.store(false, Ordering::Relaxed); // Stop main client run loop if it's separate
        self.shutdown_notifier.notify_waiters(); // Signal all loops to wind down

        self.conn_manager_cmd_tx
            .send(ConnectionManagerCommand::Disconnect)
            .await?;

        // Also tell NodeProcessor to shut down
        let _ = self.node_processor_cmd_tx.send(NodeProcessorCommand::Shutdown).await;

        Ok(())
    }

    // cleanup_connection_state is now handled by actors internally or via events.

    // read_messages_loop is replaced by ConnectionManager's internal loop and event forwarding.

    // process_encrypted_frame is handled by ConnectionManager and NodeProcessor.

    // process_node is handled by NodeProcessor.

    // handle_success, handle_failure, handle_stream_error, etc. are all NodeProcessor's responsibility.

    // handle_iq (for server pings) is NodeProcessor's responsibility.

    // `handle_iq_response` is implicitly handled by NodeProcessor's `response_waiters` when using `send_iq`.

    pub async fn add_event_handler(&self, handler: EventHandler) -> usize {
        let id = NEXT_HANDLER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let wrapped = WrappedHandler { id, handler };
        self.event_handlers.write().await.push(wrapped);
        id
    }

    pub async fn remove_event_handler(&self, id: usize) -> bool {
        let mut handlers = self.event_handlers.write().await;
        let initial_len = handlers.len();
        handlers.retain(|h| h.id != id);
        handlers.len() < initial_len
    }

    /// Dispatches an event to all registered handlers.
    /// Takes ownership of the event.
    pub async fn dispatch_event(&self, event: WhatsAppEvent) {
        let event_arc = Arc::new(event);
        self.dispatch_event_arc(event_arc).await;
    }

    /// Dispatches an event (as Arc) to all registered handlers.
    async fn dispatch_event_arc(&self, event_arc: Arc<WhatsAppEvent>) {
        let handlers = self.event_handlers.read().await;
        for wrapped_handler in handlers.iter() {
            (wrapped_handler.handler)(event_arc.clone());
        }
    }


    pub async fn get_qr_channel(
        self: &Arc<Self>, // Changed to Arc<Self> to match original, though actors might change this
    ) -> Result<mpsc::Receiver<qrcode::QrCodeEvent>, qrcode::QrError> {
        // QR logic involves sending IQs and handling specific notifications.
        // This needs to be refactored to use the actor model.
        // For now, this is a placeholder. The original `qrcode::get_qr_channel_logic`
        // takes `client: &Client`, which has the old structure.
        // It would need to be adapted to send commands to NodeProcessor.
        warn!("get_qr_channel is not fully refactored for actor model yet.");
        // qrcode::get_qr_channel_logic_actor_based(self.node_processor_cmd_tx.clone(), ...).await
        Err(qrcode::QrError::NotLoggedIn) // Placeholder
    }

    pub fn is_connected(&self) -> bool {
        // "Connected" means the transport (WebSocket/Noise) is up.
        // This state is primarily known by ConnectionManager.
        // The Client facade can reflect this based on events.
        // A simple check could be if `is_logged_in` is true, implies connected.
        // However, one can be connected but not logged in (e.g. during QR pairing).
        // For now, rely on is_logged_in as a proxy, or enhance state tracking.
        // A more accurate way would be to have ConnectionManager update an AtomicBool here.
        // For now, if we are logged in, we must be connected.
        // If not logged in, we might be connected (pairing) or not.
        // This is less certain than before.
        self.is_logged_in.load(Ordering::Relaxed) // This is a simplification.
                                                   // A more robust way is to track CM's Connected/Disconnected events.
    }

    pub fn is_logged_in(&self) -> bool {
        self.is_logged_in.load(Ordering::Relaxed)
    }


    /// Sends a pre-constructed Node.
    /// This will be processed by NodeProcessor, then marshaled and sent via ConnectionManager.
    pub async fn send_node(&self, node: Node) -> Result<(), ClientError> {
        if !self.is_logged_in() && node.tag != "iq" { // Allow IQs even if not fully logged in (e.g. for pairing)
            warn!("Attempted to send node of type '{}' while not logged in.", node.tag);
            return Err(ClientError::NotLoggedIn);
        }
        self.node_processor_cmd_tx
            .send(NodeProcessorCommand::SendOutgoingNode { node, response_tx: None })
            .await?;
        Ok(())
    }

    /// Sends an IQ node and waits for a response.
    /// This is a common pattern that requires specific handling for matching request/response by ID.
    pub async fn send_iq(&self, iq_node: Node) -> Result<Node, IqError> {
        // Ensure it's an IQ node
        if iq_node.tag != "iq" {
            return Err(IqError::Client(ClientError::ActorCommandFailed("Node is not an IQ".to_string())));
        }
        if !iq_node.attrs().contains_key("id") {
             return Err(IqError::Client(ClientError::ActorCommandFailed("IQ node requires an ID".to_string())));
        }

        if !self.is_connected() { // Use a more general is_connected check if available
             warn!("Attempted to send IQ while not connected (or not logged in as proxy).");
             return Err(IqError::Client(ClientError::NotConnected));
        }

        let (tx, rx) = oneshot::channel::<Result<Node, anyhow::Error>>();

        self.node_processor_cmd_tx
            .send(NodeProcessorCommand::SendOutgoingNode { node: iq_node, response_tx: Some(tx) })
            .await.map_err(|e| IqError::Client(ClientError::ActorSendError(e.to_string())))?;

        // Wait for the response from NodeProcessor
        // TODO: Add timeout for IQ requests
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(Ok(response_node))) => Ok(response_node),
            Ok(Ok(Err(e))) => Err(IqError::Request(format!("IQ processing error: {}", e))), // Error from NodeProcessor processing
            Ok(Err(_)) => Err(IqError::Request("IQ oneshot channel closed unexpectedly".to_string())), // Receiver error
            Err(_) => Err(IqError::Timeout), // Timeout
        }
    }


    // send_presence, set_push_name, etc. will now construct a Node
    // and use send_node or send_iq.
    // Example for send_presence:
    pub async fn send_presence(&self, presence: Presence) -> Result<(), anyhow::Error> {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        if device_snapshot.push_name.is_empty() {
            return Err(anyhow::anyhow!("Cannot send presence: push_name is empty"));
        }
        let presence_type = match presence {
            Presence::Available => "available",
            Presence::Unavailable => "unavailable",
        };
        let node = crate::binary::node::Node {
            tag: "presence".to_string(),
            attrs: [
                ("type".to_string(), presence_type.to_string()),
                ("name".to_string(), device_snapshot.push_name.clone()),
            ].into(),
            content: None,
        };
        self.send_node(node).await.map_err(|e| e.into())
    }

    pub async fn set_passive(&self, passive: bool) -> Result<(), ClientError> {
        use crate::types::jid::SERVER_JID;
        // This method was originally in client.rs and used self.send_iq.
        // We need to reconstruct that functionality here.
        // First, generate a unique ID for the IQ. NodeProcessor might do this, or we do it here.
        // For now, let's assume NodeProcessor assigns or uses the one we provide.
        // A proper `request::InfoQuery` builder would be better.
        // This is a simplified direct node construction.
        let id = format!("passive-{}", rand::random::<u32>()); // Simple unique ID for this request
        let tag_name = if passive { "passive" } else { "active" };

        let iq_content_node = Node {
            tag: tag_name.to_string(),
            ..Default::default()
        };

        let iq_node = Node {
            tag: "iq".to_string(),
            attrs: [
                ("id".to_string(), id),
                ("type".to_string(), "set".to_string()),
                ("to".to_string(), SERVER_JID.to_string()),
                ("xmlns".to_string(), "passive".to_string()),
            ].into(),
            content: Some(crate::binary::node::NodeContent::Nodes(vec![iq_content_node])),
        };

        self.send_iq(iq_node).await.map(|_| ()).map_err(|e| {
            // Convert IqError to ClientError if that's what this function signature needs.
            // This might indicate a need for more consistent error types.
            warn!("set_passive failed: {:?}", e);
            match e {
                IqError::Client(ce) => ce,
                IqError::Timeout => ClientError::ActorCommandFailed("set_passive IQ timeout".to_string()),
                IqError::Request(s) => ClientError::ActorCommandFailed(format!("set_passive IQ failed: {}",s)),
            }
        })
    }


    pub async fn set_push_name(&self, name: String) -> Result<(), anyhow::Error> {
        // 1. Update local store via PersistenceManager (still happens directly for now)
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let old_name = device_snapshot.push_name.clone();

        if old_name != name {
            self.persistence_manager
                .process_command(DeviceCommand::SetPushName(name.clone()))
                .await; // This directly modifies the store.

            // 2. Dispatch local event
            self.dispatch_event(WhatsAppEvent::SelfPushNameUpdated(
                crate::types::events::SelfPushNameUpdated {
                    from_server: false,
                    old_name,
                    new_name: name.clone(),
                },
            )).await;

            // 3. TODO: If setting pushname involves sending an IQ to the server,
            //    that IQ would be constructed and sent here via self.send_iq.
            //    Currently, pushname seems to be updated via presence or other means.
            //    If a specific IQ is needed:
            //    let pushname_iq = Node { ... construct ... };
            //    self.send_iq(pushname_iq).await?;
        }
        Ok(())
    }

    // add_recent_message / get_recent_message are NodeProcessor's responsibility.

    // handle_retry_receipt is NodeProcessor's responsibility.

    pub async fn get_push_name(&self) -> String {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        device_snapshot.push_name.clone()
    }

    pub async fn is_ready_for_presence(&self) -> bool {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        device_snapshot.id.is_some() && !device_snapshot.push_name.is_empty()
    }

    // get_device_debug_info remains similar, reading from PersistenceManager.
    pub async fn get_device_debug_info(&self) -> String {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        format!(
            "Device Debug Info:\n  - JID: {:?}\n  - LID: {:?}\n  - Push Name: '{}'\n  - Has Account: {}\n  - Ready for Presence: {}\n  - Logged In (facade): {}\n  - Connecting (facade): {}",
            device_snapshot.id,
            device_snapshot.lid,
            device_snapshot.push_name,
            device_snapshot.account.is_some(),
            device_snapshot.id.is_some() && !device_snapshot.push_name.is_empty(),
            self.is_logged_in.load(Ordering::Relaxed),
            self.is_connecting.load(Ordering::Relaxed)
        )
    }

    // query_group_info and get_user_devices involve sending IQs.
    // They need to be adapted to use `self.send_iq` and then parse the response Node.
    // Example for query_group_info:
    pub async fn query_group_info(
        &self,
        jid: &crate::types::jid::Jid,
    ) -> Result<Vec<crate::types::jid::Jid>, anyhow::Error> {
        use crate::binary::node::NodeContent;
        // This is a simplified version of request::InfoQuery
        let id = format!("groupinfo-{}", rand::random::<u32>());
        let query_child_node = Node {
            tag: "query".to_string(),
            attrs: [("request".to_string(), "interactive".to_string())].into(),
            content: None,
        };
        let iq_node = Node {
            tag: "iq".to_string(),
            attrs: [
                ("id".to_string(), id),
                ("type".to_string(), "get".to_string()),
                ("to".to_string(), jid.to_string()),
                ("xmlns".to_string(), "w:g2".to_string()),
            ].into(),
            content: Some(NodeContent::Nodes(vec![query_child_node])),
        };

        let resp_node = self.send_iq(iq_node).await?; // send_iq returns Result<Node, IqError>

        // Parse resp_node (this part is similar to original)
        let group_node = resp_node
            .get_optional_child("group")
            .ok_or_else(|| anyhow::anyhow!("<group> not found in group info response"))?;

        let mut participants = Vec::new();
        // The LID map logic was in the old client, NodeProcessor should own this map now.
        // This function should probably just return JIDs.
        // If LID mapping is needed by the caller, they'd query NodeProcessor or it's exposed some other way.
        // For now, removing the direct LID map update from here.
        // let mut lid_pn_map = self.lid_pn_map.lock().await; // This would be wrong now

        for participant_node in group_node.get_children_by_tag("participant") {
            let mut attrs = participant_node.attrs();
            let participant_jid = attrs.jid("jid");
            // LID mapping logic would be handled by NodeProcessor when it processes this IQ response,
            // or if this client facade is responsible for updating some shared map (less ideal).
            if !attrs.ok() {
                log::warn!("Failed to parse participant attrs: {:?}", attrs.errors);
                continue;
            }
            participants.push(participant_jid);
        }
        Ok(participants)
    }

    // get_user_devices would be refactored similarly to query_group_info.
    // For brevity, not fully refactoring it here but it follows the same pattern:
    // 1. Construct IQ Node.
    // 2. Call self.send_iq(iq_node).await
    // 3. Parse the resulting Node.
    pub async fn get_user_devices(
        &self,
        _jids: &[crate::types::jid::Jid], // Mark as unused for now
    ) -> Result<Vec<crate::types::jid::Jid>, anyhow::Error> {
        warn!("get_user_devices is not fully refactored for actor model yet.");
        // Placeholder:
        // let iq_node = ... construct usync iq ...
        // let resp_node = self.send_iq(iq_node).await?;
        // ... parse resp_node ...
        Ok(Vec::new())
    }

    // Keepalive loop was part of the old client.
    // This responsibility should move to ConnectionManager or a dedicated keepalive actor/task
    // that ConnectionManager might spawn.
    // async fn keepalive_loop(self: Arc<Self>) { ... } // REMOVE

    // generate_request_id was part of the old client.
    // NodeProcessor now has its own ID generator. If Client facade needs to generate IDs
    // for requests it constructs before sending to NodeProcessor, it would need its own.
    // For IQs sent via `send_iq`, the ID is part of the Node passed in.
    // pub(crate) fn generate_request_id(&self) -> String { ... } // REMOVE or make internal if needed

    // --- Methods from old client that are now fully handled by actors or removed ---
    // - read_messages_loop -> ConnectionManager + event loop
    // - process_encrypted_frame -> ConnectionManager + NodeProcessor
    // - process_node -> NodeProcessor
    // - handle_success, handle_failure, handle_stream_error -> NodeProcessor
    // - handle_receipt -> NodeProcessor
    // - handle_iq (ping) -> NodeProcessor
    // - handle_iq_response -> NodeProcessor (internal response_waiters)
    // - Recent message cache methods -> NodeProcessor
    // - handle_retry_receipt -> NodeProcessor (TODO: full impl)
}


// The old main.rs and other example usages of Client will need significant updates:
// 1. Client::new(...) now returns Arc<Client>.
// 2. Client::run() starts the main client facade loop (which includes starting actor event loop).
//    It doesn't block indefinitely in the same way; actors run in background.
//    The `run` method itself might be more about managing the lifecycle and auto-reconnect policies.
// 3. Direct socket/frame manipulation is gone from Client.
// 4. Event handling remains similar (add_event_handler, dispatch_event), but events
//    are now sourced from the actor event loop.
