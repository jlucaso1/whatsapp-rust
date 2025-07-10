use crate::binary::node::Node;
use crate::handshake; // For do_handshake
use crate::keepalive;
use crate::socket::{FrameSocket, NoiseSocket, SocketError};
use crate::store::persistence_manager::PersistenceManager;
use log::{debug, error, info, warn}; // Logging
use scopeguard; // For RAII guards
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, Notify}; // For keepalive_loop

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("socket error: {0}")]
    Socket(#[from] SocketError),
    #[error("handshake error: {0}")]
    Handshake(String),
    #[error("already connected or connecting")]
    AlreadyConnectedOrConnecting,
    #[error("not connected")]
    NotConnected,
    #[error("connection attempt failed: {0}")]
    ConnectionFailed(String),
    #[error("marshal error: {0}")]
    Marshal(String),
    #[error("other: {0}")]
    Other(#[from] anyhow::Error),
}

pub struct ConnectionManager {
    pub(crate) state: Arc<Mutex<ConnectionState>>,
    pub(crate) frame_socket_internal: Arc<Mutex<Option<FrameSocket>>>, // Renamed to avoid conflict if FrameSocket itself is exposed
    pub(crate) noise_socket_internal: Arc<Mutex<Option<Arc<NoiseSocket>>>>, // Renamed
    // frames_rx is created within connect and passed to do_handshake and then potentially run_read_loop
    pub(crate) stanza_sender: mpsc::Sender<Node>,
    pub(crate) persistence_manager: Arc<PersistenceManager>,
    pub(crate) shutdown_notifier: Arc<Notify>,
    pub(crate) expected_disconnect: Arc<AtomicBool>,
    // This is to receive raw frames from the socket after handshake
    // It's an Option because it only exists while connected.
    pub(crate) raw_frames_rx: Arc<Mutex<Option<mpsc::Receiver<bytes::Bytes>>>>,
    // To signal the keepalive loop to stop
    pub(crate) keepalive_shutdown_notifier: Arc<Notify>,
}

impl ConnectionManager {
    pub fn new(
        persistence_manager: Arc<PersistenceManager>,
        stanza_sender: mpsc::Sender<Node>,
        shutdown_notifier: Arc<Notify>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            frame_socket_internal: Arc::new(Mutex::new(None)),
            noise_socket_internal: Arc::new(Mutex::new(None)),
            stanza_sender,
            persistence_manager,
            shutdown_notifier,
            expected_disconnect: Arc::new(AtomicBool::new(false)),
            raw_frames_rx: Arc::new(Mutex::new(None)),
            keepalive_shutdown_notifier: Arc::new(Notify::new()),
        }
    }

    pub async fn current_state(&self) -> ConnectionState {
        self.state.lock().await.clone()
    }

    pub async fn connect(self: &Arc<Self>) -> Result<(), ConnectionError> {
        let mut state_guard = self.state.lock().await;
        if *state_guard == ConnectionState::Connected || *state_guard == ConnectionState::Connecting
        {
            return Err(ConnectionError::AlreadyConnectedOrConnecting);
        }
        *state_guard = ConnectionState::Connecting;
        drop(state_guard);

        let _guard = scopeguard::guard((self.clone()), |conn_manager_clone| {
            tokio::spawn(async move {
                let mut state_guard = conn_manager_clone.state.lock().await;
                // If not connected after attempt, revert to Disconnected
                if *state_guard == ConnectionState::Connecting {
                    *state_guard = ConnectionState::Disconnected;
                }
            });
        });

        let (mut fs, mut frames_rx_for_handshake) = FrameSocket::new();
        fs.connect()
            .await
            .map_err(|e| ConnectionError::ConnectionFailed(e.to_string()))?;

        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let noise_socket_result = handshake::do_handshake(
            &device_snapshot, // This needs to be &store::Device
            &mut fs,
            &mut frames_rx_for_handshake, // Pass the receiver part for handshake
        )
        .await;

        let noise_socket = match noise_socket_result {
            Ok(ns) => Arc::new(ns),
            Err(e) => {
                // Ensure FrameSocket is closed on handshake failure
                fs.close().await;
                // Log specific handshake error if possible
                error!("Handshake failed: {:?}", e);
                // Assuming e is anyhow::Error, convert to ConnectionError::Handshake
                return Err(ConnectionError::Handshake(e.to_string()));
            }
        };

        // After successful handshake, fs provides a new receiver for actual data frames
        let data_frames_rx = fs.get_frames_receiver();

        *self.frame_socket_internal.lock().await = Some(fs);
        *self.noise_socket_internal.lock().await = Some(noise_socket.clone());
        *self.raw_frames_rx.lock().await = Some(data_frames_rx);
        *self.state.lock().await = ConnectionState::Connected;
        self.expected_disconnect.store(false, Ordering::Relaxed);

        info!("ConnectionManager: Successfully connected and handshake complete.");

        // Start keepalive loop
        let self_clone_for_keepalive = self.clone();
        tokio::spawn(async move {
            keepalive::keepalive_loop(
                noise_socket, // Pass the Arc<NoiseSocket>
                self_clone_for_keepalive.keepalive_shutdown_notifier.clone(),
            )
            .await;
        });

        Ok(())
    }

    pub async fn disconnect(&self, intentional: bool) {
        let mut state_guard = self.state.lock().await;
        if *state_guard == ConnectionState::Disconnected
            || *state_guard == ConnectionState::Disconnecting
        {
            info!("ConnectionManager: Already disconnected or disconnecting.");
            return;
        }
        *state_guard = ConnectionState::Disconnecting;
        drop(state_guard);

        info!(
            "ConnectionManager: Disconnecting (intentional: {})...",
            intentional
        );
        self.expected_disconnect
            .store(intentional, Ordering::Relaxed);

        // Signal keepalive loop to stop
        self.keepalive_shutdown_notifier.notify_waiters();

        if let Some(fs) = self.frame_socket_internal.lock().await.as_mut() {
            fs.close().await;
        }
        self.cleanup_connection_state_internal().await;
        info!("ConnectionManager: Disconnected.");
    }

    async fn cleanup_connection_state_internal(&self) {
        // Note: is_logged_in is typically managed by Client/StanzaProcessor based on <success>
        // self.client_is_logged_in.store(false, Ordering::Relaxed);
        *self.frame_socket_internal.lock().await = None;
        *self.noise_socket_internal.lock().await = None;
        *self.raw_frames_rx.lock().await = None;
        *self.state.lock().await = ConnectionState::Disconnected;
    }

    pub async fn send_node(&self, node: Node) -> Result<(), ConnectionError> {
        let noise_socket_arc = match self.noise_socket_internal.lock().await.clone() {
            Some(socket) => socket,
            None => return Err(ConnectionError::NotConnected),
        };

        if self.current_state().await != ConnectionState::Connected {
            return Err(ConnectionError::NotConnected);
        }

        debug!(target: "ConnectionManager/Send", "{node}");

        let payload =
            crate::binary::marshal(&node).map_err(|e| ConnectionError::Marshal(e.to_string()))?;

        noise_socket_arc.send_frame(&payload).await?; // SocketError converted by From

        Ok(())
    }

    // run_read_loop will be called by Client::run
    // It needs mutable access to raw_frames_rx, or to take ownership of the receiver.
    // If ConnectionManager is Arc<Self>, then raw_frames_rx must be Mutex-protected.
    pub async fn run_read_loop(self: &Arc<Self>) -> Result<(), ConnectionError> {
        info!("ConnectionManager: Starting read loop...");

        let mut raw_frames_rx_guard = self.raw_frames_rx.lock().await;
        let mut frames_rx = match raw_frames_rx_guard.take() {
            Some(rx) => rx,
            None => {
                // This can happen if connect was not called or failed before run_read_loop
                error!("ConnectionManager: Read loop started without a valid frame receiver. Was connect called?");
                return Err(ConnectionError::NotConnected);
            }
        };
        drop(raw_frames_rx_guard); // Release Mutex guard

        loop {
            tokio::select! {
                biased; // Prioritize shutdown
                _ = self.shutdown_notifier.notified() => {
                    info!("ConnectionManager: Read loop shutdown signaled.");
                    // self.disconnect(true).await; // Ensure cleanup if not already done
                    return Ok(());
                },
                frame_opt = frames_rx.recv() => {
                    match frame_opt {
                        Some(encrypted_frame) => {
                            let noise_socket_arc = match self.noise_socket_internal.lock().await.clone() {
                                Some(s) => s,
                                None => {
                                    warn!("ConnectionManager: Received frame but no noise socket. Disconnecting.");
                                    self.disconnect(false).await; // Not intentional
                                    return Err(ConnectionError::NotConnected);
                                }
                            };

                            let decrypted_payload = match noise_socket_arc.decrypt_frame(&encrypted_frame) {
                                Ok(p) => p,
                                Err(e) => {
                                    error!("ConnectionManager: Failed to decrypt frame: {:?}. Disconnecting.", e);
                                    // This error is critical, likely means session is broken.
                                    self.disconnect(false).await;
                                    return Err(ConnectionError::Socket(e));
                                }
                            };

                            // Decompress (unpack)
                            let unpacked_data_cow = match crate::binary::util::unpack(&decrypted_payload) {
                                Ok(data) => data,
                                Err(e) => {
                                    warn!("ConnectionManager: Failed to decompress frame: {:?}. Skipping frame.", e);
                                    continue; // Skip this frame
                                }
                            };

                            // Unmarshal
                            match crate::binary::unmarshal_ref(unpacked_data_cow.as_ref()) {
                                Ok(node_ref) => {
                                    let node = node_ref.to_owned();
                                    if let Err(e) = self.stanza_sender.send(node).await {
                                        error!("ConnectionManager: Failed to send node to StanzaProcessor: {:?}. StanzaProcessor might have shut down.", e);
                                        // This is a critical error for the system's data flow.
                                        // Consider if self.disconnect(false) is appropriate.
                                        // If stanza_sender channel is broken, StanzaProcessor is likely gone.
                                        self.disconnect(false).await;
                                        return Err(ConnectionError::Other(anyhow::anyhow!("StanzaProcessor channel broken")));
                                    }
                                }
                                Err(e) => {
                                    warn!("ConnectionManager: Failed to unmarshal node: {:?}. Skipping frame.", e);
                                    // Potentially log raw unpacked_data_cow for debugging
                                }
                            };
                        },
                        None => {
                            // Frame channel closed, meaning WebSocket disconnected.
                            if !self.expected_disconnect.load(Ordering::Relaxed) {
                                warn!("ConnectionManager: Socket disconnected unexpectedly.");
                                self.disconnect(false).await; // Ensure cleanup and state update
                                return Err(ConnectionError::Socket(SocketError::Disconnected(
                                    "Socket disconnected unexpectedly".to_string(),
                                )));
                            } else {
                                info!("ConnectionManager: Socket disconnected as expected.");
                                // self.disconnect(true).await; // Already called or will be by Client::disconnect
                                return Ok(()); // Graceful exit
                            }
                        }
                    }
                }
            }
        }
    }
}
