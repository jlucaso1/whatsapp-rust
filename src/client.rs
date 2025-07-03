// src/client.rs

use crate::binary::node::Node;
use crate::handshake;
use crate::pair;
use crate::socket::{FrameSocket, NoiseSocket, SocketError};
use crate::store;

use crate::binary;
use crate::qrcode;
use crate::types::events::{ConnectFailureReason, Event};
use log::{debug, error, info, warn};
use rand::RngCore;
use scopeguard;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, Mutex, Notify, RwLock};
use tokio::time::{sleep, Duration};

pub type EventHandler = Box<dyn Fn(&Event) + Send + Sync>;
pub(crate) struct WrappedHandler {
    pub(crate) id: usize,
    handler: EventHandler,
}
static NEXT_HANDLER_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("client is not connected")]
    NotConnected,
    #[error("socket error: {0}")]
    Socket(#[from] SocketError),
    #[error("client is already connected")]
    AlreadyConnected,
    #[error("client is not logged in")]
    NotLoggedIn,
}

pub struct Client {
    pub store: store::Device,

    // Concurrency and state management
    pub(crate) is_logged_in: Arc<AtomicBool>,
    pub(crate) is_connecting: Arc<AtomicBool>,
    pub(crate) is_running: Arc<AtomicBool>,
    pub(crate) shutdown_notifier: Arc<Notify>,

    // Socket and connection fields
    pub(crate) frame_socket: Arc<Mutex<Option<FrameSocket>>>,
    pub(crate) noise_socket: Arc<Mutex<Option<NoiseSocket>>>,
    pub(crate) frames_rx: Arc<Mutex<Option<tokio::sync::mpsc::Receiver<bytes::Bytes>>>>,

    // Request and event handling
    pub(crate) response_waiters: Arc<Mutex<HashMap<String, oneshot::Sender<crate::binary::Node>>>>,
    pub(crate) unique_id: String,
    pub(crate) id_counter: Arc<AtomicU64>,
    pub(crate) event_handlers: Arc<RwLock<Vec<WrappedHandler>>>,

    // Reconnection logic
    pub(crate) expected_disconnect: Arc<AtomicBool>,
    pub enable_auto_reconnect: Arc<AtomicBool>,
    pub auto_reconnect_errors: Arc<AtomicU32>,
    pub last_successful_connect: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,
}

impl Client {
    pub fn new(store: store::Device) -> Self {
        let mut unique_id_bytes = [0u8; 2];
        rand::thread_rng().fill_bytes(&mut unique_id_bytes);

        Self {
            store,
            is_logged_in: Arc::new(AtomicBool::new(false)),
            is_connecting: Arc::new(AtomicBool::new(false)),
            is_running: Arc::new(AtomicBool::new(false)),
            shutdown_notifier: Arc::new(Notify::new()),

            frame_socket: Arc::new(Mutex::new(None)),
            noise_socket: Arc::new(Mutex::new(None)),
            frames_rx: Arc::new(Mutex::new(None)),

            response_waiters: Arc::new(Mutex::new(HashMap::new())),
            unique_id: format!("{}.{}", unique_id_bytes[0], unique_id_bytes[1]),
            id_counter: Arc::new(AtomicU64::new(0)),
            event_handlers: Arc::new(RwLock::new(Vec::new())),

            expected_disconnect: Arc::new(AtomicBool::new(false)),
            enable_auto_reconnect: Arc::new(AtomicBool::new(true)),
            auto_reconnect_errors: Arc::new(AtomicU32::new(0)),
            last_successful_connect: Arc::new(Mutex::new(None)),
        }
    }

    /// The main entry point to start the client.
    /// This will connect and then enter a loop to maintain the connection.
    pub async fn run(&mut self) {
        if self.is_running.swap(true, Ordering::SeqCst) {
            warn!("Client `run` method called while already running.");
            return;
        }
        while self.is_running.load(Ordering::Relaxed) {
            self.expected_disconnect.store(false, Ordering::Relaxed);

            if self.connect().await.is_err() {
                error!("Failed to connect, will retry...");
            } else {
                if self.read_messages_loop().await.is_err() {
                    warn!("Message loop exited with an error. Will attempt to reconnect if enabled.");
                } else {
                    warn!("Message loop exited gracefully.");
                }
                // Always cleanup after message loop exits
                self.cleanup_connection_state().await;
            }

            if !self.enable_auto_reconnect.load(Ordering::Relaxed) {
                self.is_running.store(false, Ordering::Relaxed);
                break;
            }

            let error_count = self.auto_reconnect_errors.fetch_add(1, Ordering::SeqCst);
            let delay_secs = u64::from(error_count * 2).min(30);
            let delay = Duration::from_secs(delay_secs);
            info!(
                "Will attempt to reconnect in {:?} (attempt {})",
                delay,
                error_count + 1
            );
            tokio::select! {
                _ = sleep(delay) => {},
                _ = self.shutdown_notifier.notified() => {
                    self.is_running.store(false, Ordering::Relaxed);
                    break;
                }
            }
        }
        info!("Client run loop has shut down.");
    }

    /// Internal connect logic.
    async fn connect(&self) -> Result<(), anyhow::Error> {
        if self.is_connecting.swap(true, Ordering::SeqCst) {
            return Err(ClientError::AlreadyConnected.into());
        }
        // Ensure is_connecting is false on function exit
        let _guard = scopeguard::guard((), |_| {
            self.is_connecting.store(false, Ordering::Relaxed);
        });

        if self.is_connected() {
            return Err(ClientError::AlreadyConnected.into());
        }

        let (mut frame_socket, mut frames_rx) = FrameSocket::new();
        frame_socket.connect().await?;

        let noise_socket =
            handshake::do_handshake(&self.store, &mut frame_socket, &mut frames_rx).await?;

        *self.frame_socket.lock().await = Some(frame_socket);
        *self.frames_rx.lock().await = Some(frames_rx);
        *self.noise_socket.lock().await = Some(noise_socket);

        Ok(())
    }

    /// Disconnects the client and signals the run loop to stop.
    pub async fn disconnect(&self) {
        info!("Disconnecting client intentionally.");
        self.expected_disconnect.store(true, Ordering::Relaxed);
        self.is_running.store(false, Ordering::Relaxed);
        self.shutdown_notifier.notify_waiters();
        if let Some(fs) = self.frame_socket.lock().await.as_mut() {
            fs.close().await;
        }
        self.cleanup_connection_state().await;
    }

    async fn cleanup_connection_state(&self) {
        self.is_logged_in.store(false, Ordering::Relaxed);
        *self.frame_socket.lock().await = None;
        *self.noise_socket.lock().await = None;
        *self.frames_rx.lock().await = None;
    }

    async fn read_messages_loop(&mut self) -> Result<(), anyhow::Error> {
        info!(target: "Client", "Starting message processing loop...");

        let mut rx_guard = self.frames_rx.lock().await;
        let mut frames_rx = rx_guard
            .take()
            .ok_or_else(|| anyhow::anyhow!("Cannot start message loop: not connected"))?;
        drop(rx_guard);

        loop {
            tokio::select! {
                biased;
                _ = self.shutdown_notifier.notified() => {
                    info!(target: "Client", "Shutdown signaled. Exiting message loop.");
                    return Ok(());
                },
                frame_opt = frames_rx.recv() => {
                    match frame_opt {
                        Some(encrypted_frame) => {
                            self.process_encrypted_frame(&encrypted_frame).await;
                        },
                        None => {
                            // The channel is closed, meaning the socket is dead.
                            self.cleanup_connection_state().await;
                             if !self.expected_disconnect.load(Ordering::Relaxed) {
                                self.dispatch_event(Event::Disconnected(crate::types::events::Disconnected)).await;
                                info!("Socket disconnected unexpectedly.");
                                return Err(anyhow::anyhow!("Socket disconnected unexpectedly"));
                            } else {
                                info!("Socket disconnected as expected.");
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }

    async fn process_encrypted_frame(&mut self, encrypted_frame: &bytes::Bytes) {
        let noise_socket_guard = self.noise_socket.lock().await;
        let noise_socket = match noise_socket_guard.as_ref() {
            Some(s) => s,
            None => {
                error!("Cannot process frame: not connected (no noise socket)");
                return;
            }
        };

        let decrypted_payload = match noise_socket.decrypt_frame(encrypted_frame) {
            Ok(p) => p,
            Err(e) => {
                error!(target: "Client", "Failed to decrypt frame: {}", e);
                return;
            }
        };
        drop(noise_socket_guard);

        let unpacked_data_cow = match binary::util::unpack(&decrypted_payload) {
            Ok(data) => data,
            Err(e) => {
                warn!(target: "Client/Recv", "Failed to decompress frame: {}", e);
                return;
            }
        };

        match binary::unmarshal(unpacked_data_cow.as_ref()) {
            Ok(node) => self.process_node(node).await,
            Err(e) => warn!(target: "Client/Recv", "Failed to unmarshal node: {}", e),
        };
    }

    async fn process_node(&mut self, node: Node) {
        debug!(target: "Client/Recv", "{}", node);

        if node.tag == "iq" && self.handle_iq_response(node.clone()).await {
            return;
        }

        match node.tag.as_str() {
            "success" => self.handle_success(&node).await,
            "failure" => self.handle_connect_failure(&node).await,
            "stream:error" => self.handle_stream_error(&node).await,
            "iq" => {
                if !self.handle_iq(&node).await {
                    warn!(target: "Client", "Received unhandled IQ: {}", node);
                }
            }
            "receipt" | "message" | "notification" | "call" | "presence" | "chatstate" => {
                warn!(target: "Client", "TODO: Implement handler for <{}>", node.tag);
            }
            "ack" => {} // Ignore acks for now
            _ => {
                warn!(target: "Client", "Received unknown top-level node: {}", node);
            }
        }
    }

    async fn handle_success(&self, _node: &Node) {
        info!("Successfully authenticated with WhatsApp servers!");
        self.is_logged_in.store(true, Ordering::Relaxed);
        *self.last_successful_connect.lock().await = Some(chrono::Utc::now());
        self.auto_reconnect_errors.store(0, Ordering::Relaxed);
        self.dispatch_event(Event::Connected(crate::types::events::Connected))
            .await;
    }

    async fn handle_stream_error(&self, node: &Node) {
        self.is_logged_in.store(false, Ordering::Relaxed);
        self.expected_disconnect.store(true, Ordering::Relaxed);
        self.shutdown_notifier.notify_one(); // Stop current read loop

        let mut attrs = node.attrs();
        let code = attrs.optional_string("code").unwrap_or("");
        let conflict_type = node
            .get_optional_child("conflict")
            .map(|n| n.attrs().optional_string("type").unwrap_or("").to_string())
            .unwrap_or_default();

        match (code, conflict_type.as_str()) {
            ("515", _) => {
                info!(target: "Client", "Got 515 stream error, forcing reconnect.");
                self.expected_disconnect.store(false, Ordering::Relaxed); // This is an unexpected disconnect
            }
            ("401", "device_removed") => {
                info!(target: "Client", "Got device removed stream error, logging out.");
                self.enable_auto_reconnect.store(false, Ordering::Relaxed);
                self.dispatch_event(Event::LoggedOut(crate::types::events::LoggedOut {
                    on_connect: false,
                    reason: ConnectFailureReason::LoggedOut,
                }))
                .await;
                // TODO: Add store.delete()
            }
            (_, "replaced") => {
                info!(target: "Client", "Got 'replaced' stream error (another client connected).");
                self.enable_auto_reconnect.store(false, Ordering::Relaxed);
                self.dispatch_event(Event::StreamReplaced(crate::types::events::StreamReplaced))
                    .await;
            }
            ("503", _) => {
                info!(target: "Client", "Got 503 service unavailable, will auto-reconnect.");
                self.expected_disconnect.store(false, Ordering::Relaxed);
            }
            _ => {
                error!(target: "Client", "Unknown stream error: {}", node);
                self.dispatch_event(Event::StreamError(crate::types::events::StreamError {
                    code: code.to_string(),
                    raw: Some(node.clone()),
                }))
                .await;
            }
        }
    }

    async fn handle_connect_failure(&self, node: &Node) {
        self.expected_disconnect.store(true, Ordering::Relaxed);
        self.shutdown_notifier.notify_one();

        let mut attrs = node.attrs();
        let reason_code = attrs.optional_u64("reason").unwrap_or(0) as i32;
        let reason = ConnectFailureReason::from(reason_code);

        // Allow auto-reconnect for recoverable errors
        if reason.should_reconnect() {
            self.expected_disconnect.store(false, Ordering::Relaxed);
        } else {
            // All other errors are fatal and should stop the reconnect loop
            self.enable_auto_reconnect.store(false, Ordering::Relaxed);
        }

        if reason.is_logged_out() {
            info!(target: "Client", "Got {:?} connect failure, logging out.", reason);
            self.dispatch_event(Event::LoggedOut(crate::types::events::LoggedOut {
                on_connect: true,
                reason,
            }))
            .await;
            // TODO: Add store.delete()
        } else if let ConnectFailureReason::TempBanned = reason {
            let ban_code = attrs.optional_u64("code").unwrap_or(0) as i32;
            let expire_secs = attrs.optional_u64("expire").unwrap_or(0);
            let expire_duration =
                chrono::Duration::try_seconds(expire_secs as i64).unwrap_or_default();
            warn!(target: "Client", "Temporary ban connect failure: {}", node);
            self.dispatch_event(Event::TemporaryBan(crate::types::events::TemporaryBan {
                code: crate::types::events::TempBanReason::from(ban_code),
                expire: expire_duration,
            }))
            .await;
        } else if let ConnectFailureReason::ClientOutdated = reason {
            error!(target: "Client", "Client is outdated and was rejected by server.");
            self.dispatch_event(Event::ClientOutdated(crate::types::events::ClientOutdated))
                .await;
        } else {
            warn!(target: "Client", "Unknown connect failure: {}", node);
            self.dispatch_event(Event::ConnectFailure(
                crate::types::events::ConnectFailure {
                    reason,
                    message: attrs.optional_string("message").unwrap_or("").to_string(),
                    raw: Some(node.clone()),
                },
            ))
            .await;
        }
    }

    async fn handle_iq(&mut self, node: &Node) -> bool {
        if let Some("get") = node.attrs().optional_string("type") {
            if let Some(_ping_node) = node.get_optional_child("ping") {
                info!(target: "Client", "Received ping, sending pong.");
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
                if let Err(e) = self.send_node(pong).await {
                    warn!("Failed to send pong: {:?}", e);
                }
                return true;
            }
        }

        if pair::handle_iq(self, node).await {
            return true;
        }

        false
    }

    pub(crate) async fn add_event_handler_internal(&self, handler: EventHandler) -> usize {
        let id = NEXT_HANDLER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let wrapped = WrappedHandler { id, handler };
        self.event_handlers.write().await.push(wrapped);
        id
    }

    pub async fn add_event_handler(&self, handler: EventHandler) {
        self.add_event_handler_internal(handler).await;
    }

    pub async fn remove_event_handler(&self, id: usize) -> bool {
        let mut handlers = self.event_handlers.write().await;
        let initial_len = handlers.len();
        handlers.retain(|h| h.id != id);
        handlers.len() < initial_len
    }

    pub async fn get_qr_channel(
        &self,
    ) -> Result<mpsc::Receiver<qrcode::QrCodeEvent>, qrcode::QrError> {
        qrcode::get_qr_channel_logic(self).await
    }

    pub fn is_connected(&self) -> bool {
        self.noise_socket
            .try_lock()
            .map_or(false, |guard| guard.is_some())
    }

    pub fn is_logged_in(&self) -> bool {
        self.is_logged_in.load(Ordering::Relaxed)
    }

    pub async fn dispatch_event(&self, event: Event) {
        let handlers = self.event_handlers.read().await;
        for wrapped in handlers.iter() {
            (wrapped.handler)(&event);
        }
    }

    pub async fn send_node(&self, node: Node) -> Result<(), ClientError> {
        let noise_socket_guard = self.noise_socket.lock().await;
        let frame_socket_guard = self.frame_socket.lock().await;
        let noise_socket = noise_socket_guard
            .as_ref()
            .ok_or(ClientError::NotConnected)?;
        let frame_socket = frame_socket_guard
            .as_ref()
            .ok_or(ClientError::NotConnected)?;

        debug!(target: "Client/Send", "{}", node);

        let payload = crate::binary::marshal(&node).map_err(|e| {
            error!("Failed to marshal node: {:?}", e);
            SocketError::Crypto("Marshal error".to_string())
        })?;

        let encrypted_payload = noise_socket.encrypt_frame(&payload).map_err(|e| {
            error!("Failed to encrypt frame: {:?}", e);
            SocketError::Crypto("Encrypt error".to_string())
        })?;

        frame_socket
            .send_frame(&encrypted_payload)
            .await
            .map_err(Into::into)
    }
}

// Needed to use guard with Client methods
