use crate::binary::node::Node;
use crate::handshake; // May move to ConnectionManager
use crate::pair; // May move to StanzaProcessor or specific handler
use crate::qrcode; // May move to a specific QR manager or stay in Client facade
use crate::signal::store::SignalProtocolStore;
use crate::store::{commands::DeviceCommand, persistence_manager::PersistenceManager}; // Corrected path for SessionManager init

use crate::handlers; // Will be refactored or used by StanzaProcessor
use crate::types::events::{ConnectFailureReason, Event};
use crate::types::presence::Presence;

// New manager imports
use crate::connection_manager::ConnectionManager;
use crate::event_bus::{EventBus, EventHandler, WrappedHandler};
use crate::session_manager::SessionManager;
use crate::stanza_processor::StanzaProcessor; // Moved EventHandler and WrappedHandler here

use dashmap::DashMap;
use log::{debug, error, info, warn};
use rand::RngCore; // For unique_id generation, might move
use scopeguard; // Used in connect, might move
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex, Notify, RwLock};
use tokio::time::{sleep, Duration};

// SocketError might be primarily used by ConnectionManager now
use crate::socket::{FrameSocket, NoiseSocket, SocketError};
use whatsapp_proto::whatsapp as wa;

// Moved to event_bus.rs
// pub type EventHandler = Box<dyn Fn(Arc<Event>) + Send + Sync>;
// pub(crate) struct WrappedHandler {
//     pub(crate) id: usize,
//     handler: EventHandler,
// }
// static NEXT_HANDLER_ID: AtomicUsize = AtomicUsize::new(1); // Also moved

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("client is not connected")] // This might be ConnectionManagerError now
    NotConnected,
    #[error("socket error: {0}")]
    Socket(#[from] SocketError), // ConnectionManagerError can wrap SocketError
    #[error("client is already connected")] // ConnectionManagerError
    AlreadyConnected,
    #[error("client is not logged in")] // This state might be tracked differently
    NotLoggedIn,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RecentMessageKey {
    // May move to StanzaProcessor or a message cache module
    to: crate::types::jid::Jid,
    id: String,
}

/// The Client struct is now a facade, delegating work to specific managers.
pub struct Client {
    pub persistence_manager: Arc<PersistenceManager>,
    pub connection_manager: Arc<ConnectionManager>,
    pub stanza_processor: Arc<StanzaProcessor>,
    pub session_manager: Arc<SessionManager>,
    pub event_bus: Arc<EventBus>,

    // Fields that might remain on the Client facade or be moved/refactored:
    pub media_conn: Arc<Mutex<Option<crate::mediaconn::MediaConn>>>, // Potentially its own manager or part of ConnectionManager

    // Global client state/flags - some of these might be better suited within specific managers
    pub(crate) is_logged_in: Arc<AtomicBool>, // StanzaProcessor or Client might manage this
    pub(crate) is_connecting: Arc<AtomicBool>, // ConnectionManager state
    pub(crate) is_running: Arc<AtomicBool>,   // Client facade's run state
    pub(crate) shutdown_notifier: Arc<Notify>, // For coordinating shutdown across managers

    // These are likely moving to StanzaProcessor or being replaced by its mechanisms
    // pub(crate) response_waiters: Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<crate::binary::Node>>>>,
    pub(crate) unique_id: String, // May be needed by StanzaProcessor for IQ IDs
    pub(crate) id_counter: Arc<AtomicU64>, // May be needed by StanzaProcessor for IQ IDs

    // Moved to EventBus
    // pub(crate) event_handlers: Arc<RwLock<Vec<WrappedHandler>>>,

    // Moved to StanzaProcessor
    // pub(crate) chat_locks: Arc<DashMap<crate::types::jid::Jid, Arc<tokio::sync::Mutex<()>>>>,

    // LID-PN mapping, likely for StanzaProcessor or a dedicated UserInfoManager
    pub(crate) lid_pn_map: Arc<Mutex<HashMap<crate::types::jid::Jid, crate::types::jid::Jid>>>,

    // Related to connection state, ConnectionManager should handle this
    // pub(crate) expected_disconnect: Arc<AtomicBool>,

    // Message caching, likely StanzaProcessor or SessionManager, or a new MessageCache module
    pub(crate) recent_messages_map: Arc<Mutex<HashMap<RecentMessageKey, wa::Message>>>,
    pub(crate) recent_messages_list: Arc<Mutex<VecDeque<RecentMessageKey>>>,

    // Reconnect logic will be coordinated by Client facade, driven by ConnectionManager's state
    pub enable_auto_reconnect: Arc<AtomicBool>,
    pub auto_reconnect_errors: Arc<AtomicU32>, // Tracked by Client facade's run loop
    // last_successful_connect might be managed by ConnectionManager and exposed
    pub last_successful_connect: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,
    // last_buffer_cleanup: This specific logic might move to StanzaProcessor or be handled by PersistenceManager
    pub(crate) last_buffer_cleanup: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,
}

impl Client {
    pub fn new(persistence_manager: Arc<PersistenceManager>) -> Self {
        let mut unique_id_bytes = [0u8; 2];
        rand::thread_rng().fill_bytes(&mut unique_id_bytes);
        let unique_id_str = format!("{}.{}", unique_id_bytes[0], unique_id_bytes[1]);

        let event_bus_arc = Arc::new(EventBus::new());
        let persistence_manager_arc = persistence_manager.clone();

        let (stanza_sender, stanza_receiver) = mpsc::channel::<Node>(256); // TODO: Configurable buffer size

        let shutdown_notifier_arc = Arc::new(Notify::new()); // Create shutdown_notifier for CM

        let connection_manager_arc = Arc::new(ConnectionManager::new(
            persistence_manager_arc.clone(),
            stanza_sender,
            shutdown_notifier_arc.clone(), // Pass it to ConnectionManager
        ));

        // Get the SignalProtocolStore implementation from PersistenceManager.
        // This returns Arc<Mutex<Device>>, which implements SignalProtocolStore.
        let signal_store_arc: Arc<dyn SignalProtocolStore> =
            persistence_manager_arc.get_signal_protocol_store();

        let response_waiters_arc = Arc::new(Mutex::new(HashMap::new()));
        let id_counter_arc = Arc::new(AtomicU64::new(0)); // For generating unique request IDs

        // Initialize StanzaProcessor and SessionManager, handling the Arc cycle using Weak reference
        // SessionManager stores Weak<StanzaProcessor>
        // StanzaProcessor stores Arc<SessionManager>
        // StanzaProcessor is created via Arc::new_cyclic to allow SessionManager to get the Weak<StanzaProcessor>
        let client_is_logged_in_arc = Arc::new(AtomicBool::new(false));
        let client_last_successful_connect_arc = Arc::new(Mutex::new(None));
        let client_auto_reconnect_errors_arc = Arc::new(AtomicU32::new(0));

        let stanza_processor_arc: Arc<StanzaProcessor> = Arc::new_cyclic(|weak_stanza_processor| {
            let session_manager_for_stanza = Arc::new(SessionManager::new(
                signal_store_arc.clone(),
                weak_stanza_processor.clone(),
            ));

            StanzaProcessor::new(
                stanza_receiver,
                session_manager_for_stanza,
                persistence_manager_arc.clone(),
                event_bus_arc.clone(),
                response_waiters_arc.clone(),
                client_is_logged_in_arc.clone(),
                client_last_successful_connect_arc.clone(),
                client_auto_reconnect_errors_arc.clone(),
                connection_manager_arc.clone(),
                unique_id_str.clone(),  // Pass unique_id_str as prefix
                id_counter_arc.clone(), // Pass shared id_counter
            )
        });

        // The SessionManager instance is now owned by the StanzaProcessor.
        // The Client facade also needs an Arc<SessionManager>.
        let session_manager_arc = stanza_processor_arc.session_manager.clone();

        Self {
            persistence_manager, // This is the original Arc passed to Client::new
            connection_manager: connection_manager_arc,
            stanza_processor: stanza_processor_arc,
            session_manager: session_manager_arc,
            event_bus: event_bus_arc,

            media_conn: Arc::new(Mutex::new(None)), // Keep for now
            is_logged_in: client_is_logged_in_arc,  // Use the Arc shared with StanzaProcessor
            // is_connecting field removed
            is_running: Arc::new(AtomicBool::new(false)),
            shutdown_notifier: shutdown_notifier_arc,

            // response_waiters moved to StanzaProcessor
            unique_id: unique_id_str, // Client still holds its unique_id for other potential uses
            id_counter: id_counter_arc, // Client still holds its Arc to the counter

            // event_handlers is now in EventBus

            // chat_locks moved to StanzaProcessor
            lid_pn_map: Arc::new(Mutex::new(HashMap::new())), // Keep for now, StanzaProcessor

            // expected_disconnect is ConnectionManager's concern

            // Message caching, keep for now, may move to StanzaProcessor/SessionManager
            recent_messages_map: Arc::new(Mutex::new(HashMap::with_capacity(256))),
            recent_messages_list: Arc::new(Mutex::new(VecDeque::with_capacity(256))),

            enable_auto_reconnect: Arc::new(AtomicBool::new(true)),
            auto_reconnect_errors: Arc::new(AtomicU32::new(0)),
            last_successful_connect: Arc::new(Mutex::new(None)), // ConnectionManager might update this
            last_buffer_cleanup: Arc::new(Mutex::new(None)), // StanzaProcessor/PersistenceManager concern
        }
    }

    pub async fn run(self: &Arc<Self>) {
        // This will be significantly refactored.
        // It will start ConnectionManager's read loop and StanzaProcessor's processing loop.
        // And handle overall lifecycle / reconnect logic.
        // This method will be heavily refactored in Step 6.
        // For now, it's mostly a placeholder to ensure compilation.
        // The actual connect, read_messages_loop, etc. will be managed by
        // ConnectionManager and StanzaProcessor, orchestrated by this run method.
        if self.is_running.swap(true, Ordering::SeqCst) {
            warn!("Client `run` method called while already running.");
            return;
        }
        info!("Client run loop starting (actual logic to be implemented in later steps).");
        // Placeholder: In a real scenario, this would await completion or errors from managers.
        // self.shutdown_notifier.notified().await;
        // For now, just prevent busy loop if not connected
        // while self.is_running.load(Ordering::Relaxed) {
        //    sleep(Duration::from_secs(1)).await;
        // }
        // info!("Client run loop has shut down (placeholder)."); // Old placeholder
        if self.is_running.swap(true, Ordering::SeqCst) {
            warn!("Client: `run` method called while already running.");
            return;
        }
        info!("Client: Main run loop started.");

        let sp_clone = self.stanza_processor.clone();
        tokio::spawn(async move {
            // StanzaProcessor's loop will run as long as its receiver channel is open
            // or until it decides to stop.
            sp_clone.run_processing_loop().await;
            info!("Client: StanzaProcessor loop has finished.");
            // Optionally, if StanzaProcessor finishing means the client should fully stop:
            // self.shutdown_notifier.notify_one(); // This needs self_clone from Client
        });

        let self_clone_for_main_loop = self.clone(); // Arc<Client> for the main loop logic

        loop {
            if !self_clone_for_main_loop.is_running.load(Ordering::Relaxed) {
                info!("Client: is_running is false, exiting main loop.");
                break;
            }

            // Attempt to connect
            match self_clone_for_main_loop.connection_manager.connect().await {
                Ok(()) => {
                    info!("Client: ConnectionManager connected successfully.");
                    // is_logged_in, last_successful_connect, auto_reconnect_errors are updated by StanzaProcessor
                    // upon receiving <success> stanza.

                    // Start ConnectionManager's read loop
                    let cm_read_loop_result = self_clone_for_main_loop
                        .connection_manager
                        .run_read_loop()
                        .await;

                    match cm_read_loop_result {
                        Ok(()) => {
                            info!("Client: ConnectionManager read_loop exited gracefully (e.g. shutdown signaled).");
                            if self_clone_for_main_loop.shutdown_notifier.is_closed()
                                || !self_clone_for_main_loop.is_running.load(Ordering::Relaxed)
                            {
                                // Check if main shutdown was triggered
                                self_clone_for_main_loop
                                    .is_running
                                    .store(false, Ordering::Relaxed);
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Client: ConnectionManager read_loop exited with error: {:?}",
                                e
                            );
                            // ConnectionManager's disconnect should have been called internally.
                            // Dispatch a generic disconnected event.
                            // StanzaProcessor handles <failure> or <stream:error> from server.
                            // This event is for unexpected socket closures not covered by specific XMPP errors.
                            if self_clone_for_main_loop.is_running.load(Ordering::Relaxed) {
                                // Avoid dispatch if already shutting down
                                self_clone_for_main_loop
                                    .event_bus
                                    .dispatch(Arc::new(Event::Disconnected(
                                        crate::types::events::Disconnected {},
                                    )))
                                    .await;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Client: ConnectionManager failed to connect: {:?}", e);
                    if self_clone_for_main_loop.is_running.load(Ordering::Relaxed) {
                        self_clone_for_main_loop
                            .event_bus
                            .dispatch(Arc::new(Event::ConnectFailure(
                                crate::types::events::ConnectFailure {
                                    reason: ConnectFailureReason::Unknown, // Or map from ConnectionError
                                    message: e.to_string(),
                                    raw: None,
                                },
                            )))
                            .await;
                    }
                }
            }

            // If still running, and auto-reconnect is enabled, attempt reconnect after delay.
            if !self_clone_for_main_loop.is_running.load(Ordering::Relaxed) {
                info!("Client: Shutting down after connection attempt/cycle.");
                break;
            }
            if !self_clone_for_main_loop
                .enable_auto_reconnect
                .load(Ordering::Relaxed)
            {
                info!("Client: Auto-reconnect disabled, stopping run loop.");
                self_clone_for_main_loop
                    .is_running
                    .store(false, Ordering::Relaxed);
                break;
            }

            // Use the shared auto_reconnect_errors counter
            let error_count = self_clone_for_main_loop
                .auto_reconnect_errors
                .fetch_add(1, Ordering::SeqCst)
                + 1;
            let delay_secs = u64::from((error_count - 1) * 2).min(30); // (error_count starts at 1 for display)

            info!(
                "Client: Will attempt to reconnect in {} seconds (attempt {})...",
                delay_secs, error_count
            );

            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(delay_secs)) => {}
                _ = self_clone_for_main_loop.shutdown_notifier.notified() => {
                    info!("Client: Shutdown signaled during reconnect delay.");
                    self_clone_for_main_loop.is_running.store(false, Ordering::Relaxed);
                    break; // Exit main loop
                }
            }
        }

        // Final cleanup
        info!("Client: Main run loop has exited. Performing final cleanup.");
        self_clone_for_main_loop
            .connection_manager
            .disconnect(true)
            .await; // Ensure CM is disconnected
        self_clone_for_main_loop.shutdown_notifier.notify_waiters(); // Notify any other dependent tasks
        info!("Client: Run loop fully shut down.");
    }

    // Public API methods that delegate to managers
    pub async fn connect_client(&self) -> Result<(), crate::connection_manager::ConnectionError> {
        // Renamed to avoid conflict with internal Client::connect
        // This method might not be needed if `run` handles the initial connect.
        // Or it's a way to trigger a one-off connect attempt if not running the main loop.
        // For now, assume `run` is the primary way.
        // If called, it should probably set is_running and interact with the main loop logic,
        // which is complex. Simpler to just delegate if run() is not the entry point.
        // For now, let's assume this is a manual trigger if run() is not used.
        warn!("Client::connect_client is a manual trigger; prefer using Client::run for lifecycle management.");
        self.connection_manager.connect().await
    }

    pub async fn disconnect_client(&self, intentional: bool) {
        // Renamed
        info!(
            "Client: disconnect_client called (intentional: {})",
            intentional
        );
        if !intentional {
            // If not intentional, it's likely due to an error. The run loop handles reconnects.
            // This call might be redundant if an error already triggered CM's internal disconnect.
        } else {
            // Intentional disconnect, should stop the run loop.
            self.is_running.store(false, Ordering::Relaxed);
            self.shutdown_notifier.notify_waiters(); // Signal all loops to stop
        }
        // ConnectionManager's disconnect will be called by the run loop's cleanup
        // or by CM itself if its read_loop terminates.
        // Calling it directly here might race with run loop's logic.
        // For an explicit top-level disconnect, signaling shutdown_notifier is key.
        // The run loop's finalization will call CM.disconnect(true).
    }

    // send_node is now ConnectionManager's responsibility.
    // Client provides higher-level methods like send_text_message.
    // pub async fn send_node_facade(&self, node: Node) -> Result<(), ConnectionError> {
    // self.connection_manager.send_node(node).await
    // }

    // Old Client methods that were here:
    // read_messages_loop() will be ConnectionManager::run_read_loop
    // process_encrypted_frame() will be part of ConnectionManager::run_read_loop
    // process_node() will be StanzaProcessor::process_node
    // handle_... methods will mostly move to StanzaProcessor or specific handlers.

    pub async fn add_event_handler(&self, handler: EventHandler) -> usize {
        self.event_bus.add_handler(handler).await
    }

    pub async fn remove_event_handler(&self, id: usize) -> bool {
        self.event_bus.remove_handler(id).await
    }

    // is_connected and is_logged_in will query the respective managers or internal state
    pub fn is_connected(&self) -> bool {
        // Delegate to ConnectionManager: self.connection_manager.is_connected()
        // For now, to compile:
        if let Ok(guard) = self.connection_manager.state.try_lock() {
            *guard == crate::connection_manager::ConnectionState::Connected
        } else {
            false
        }
    }

    // is_logged_in status might be derived from ConnectionManager state or StanzaProcessor
    pub fn is_logged_in(&self) -> bool {
        self.is_logged_in.load(Ordering::Relaxed) // Keep direct access for now, may change
    }

    // dispatch_event will be called by StanzaProcessor using its Arc<EventBus>
    // Client itself might not call this directly anymore.
    // However, if there are cases where Client facade needs to dispatch an event directly:
    async fn dispatch_event_facade(&self, event: Event) {
        self.event_bus.dispatch(Arc::new(event)).await;
    }

    // send_node will be ConnectionManager::send_node
    // send_presence might use SessionManager (if encryption is needed for presence components)
    // or directly use ConnectionManager. For now, it's a high-level client API.
    // It will likely construct a node and use connection_manager.send_node.

    // set_push_name will likely remain a Client API, interacting with PersistenceManager
    // and possibly sending an IQ via StanzaProcessor/ConnectionManager.

    // Message caching methods (add_recent_message, get_recent_message)
    // will likely move to StanzaProcessor or a dedicated cache used by it/SessionManager.

    // handle_retry_receipt will move to StanzaProcessor/SessionManager.

    // query_group_info and get_user_devices are IQ methods, will be refactored
    // to use StanzaProcessor to send IQs and wait for responses.
    // For now, these complex methods will be left as is and will likely fail
    // as `send_iq` itself will be refactored.

    pub async fn send_text_message(&self, to: Jid, text: &str) -> Result<(), anyhow::Error> {
        info!("Client: send_text_message to {} with text '{}'", to, text);
        // 1. Create wa::Message
        let wa_msg = whatsapp_proto::whatsapp::Message {
            conversation: Some(text.to_string()),
            ..Default::default()
        };

        // 2. Encrypt using SessionManager
        // This returns a fully formed XMPP <message> node with <enc> child.
        let encrypted_node = self.session_manager.encrypt_message(&to, &wa_msg).await?;

        // 3. Generate a message ID for the XMPP <message> node before sending.
        // The send_node_facade expects a complete node.
        // SessionManager::encrypt_message returns a node that might be missing the top-level ID.
        // The original Client::send_message_inner added the ID.
        // Let's assume encrypt_message returns a node that needs an ID.
        // Or, SessionManager adds a placeholder ID, or Client::send_text_message generates it.

        // For now, let's assume ConnectionManager or a lower layer adds the ID if not present,
        // or that SessionManager's returned node is complete enough.
        // If an ID is strictly needed at this XMPP level by send_node_facade:
        // let mut final_node_to_send = encrypted_node;
        // if final_node_to_send.attrs.get("id").is_none() {
        //     let msg_id = self.generate_request_id_client_facade().await; // Needs such a method
        //     final_node_to_send.attrs.insert("id".to_string(), msg_id);
        // }
        // For now, directly send what SessionManager produced.

        // 4. Send using ConnectionManager
        self.connection_manager.send_node(encrypted_node).await?; // Using .send_node directly

        info!("Client: Text message to {} enqueued for sending.", to);
        Ok(())
    }

    // Helper to generate unique IDs if needed at Client facade level
    // async fn generate_request_id_client_facade(&self) -> String {
    //     format!("{}-{}", self.unique_id, self.id_counter.fetch_add(1, Ordering::Relaxed))
    // }

    // Old dispatch_event method from Client - to be removed or callsites updated.
    // pub async fn dispatch_event(&self, event: Event) {
    //     let event_arc = Arc::new(event);
    //     let handlers = self.event_handlers.read().await; // This field is gone
    //     for wrapped in handlers.iter() {
    //         (wrapped.handler)(event_arc.clone());
    //     }
    // }

    // Any direct calls to a Client-owned dispatch_event will need to change.
    // For example, if handle_success (which will move to StanzaProcessor) called self.dispatch_event:
    // It would become: self.event_bus.dispatch(Arc::new(Event::Connected(...))).await;
}
