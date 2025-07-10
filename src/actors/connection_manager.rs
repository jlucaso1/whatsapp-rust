use super::messages::{ConnectionManagerCommand, ConnectionManagerEvent};
use crate::{
    handshake,
    socket::{FrameSocket, NoiseSocket, SocketError},
    store::persistence_manager::PersistenceManager, // Added PersistenceManager
};
use bytes::Bytes;
use log::{debug, error, info, warn};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

pub struct ConnectionManager {
    // Command channel to receive instructions
    command_rx: mpsc::Receiver<ConnectionManagerCommand>,
    // Event channel to send results/events back
    event_tx: mpsc::Sender<ConnectionManagerEvent>,

    frame_socket: Option<FrameSocket>,
    noise_socket: Option<Arc<NoiseSocket>>,
    frames_rx_from_socket: Option<mpsc::Receiver<Bytes>>, // Renamed for clarity

    // State
    is_connected: bool,
    expected_disconnect: bool,

    // Keep a reference to persistence_manager for handshake
    // This is passed in during the Connect command
    // persistence_manager: Option<Arc<PersistenceManager>>,
}

impl ConnectionManager {
    pub fn new(
        command_rx: mpsc::Receiver<ConnectionManagerCommand>,
        event_tx: mpsc::Sender<ConnectionManagerEvent>,
    ) -> Self {
        Self {
            command_rx,
            event_tx,
            frame_socket: None,
            noise_socket: None,
            frames_rx_from_socket: None,
            is_connected: false,
            expected_disconnect: false,
            // persistence_manager: None,
        }
    }

    pub async fn run(&mut self) {
        info!("ConnectionManager started");
        while let Some(command) = self.command_rx.recv().await {
            match command {
                ConnectionManagerCommand::Connect {
                    persistence_manager,
                } => {
                    // self.persistence_manager = Some(persistence_manager.clone()); // Store it if needed for other operations
                    if self.is_connected {
                        warn!("Connect command received but already connected.");
                        // Optionally send a ConnectionFailed or AlreadyConnected event
                        continue;
                    }
                    self.expected_disconnect = false;
                    match self.connect_internal(persistence_manager).await {
                        Ok(_) => {
                            self.is_connected = true;
                            if self.event_tx.send(ConnectionManagerEvent::Connected).await.is_err() {
                                error!("Failed to send Connected event: receiver dropped");
                            }
                            // Spawn the task to read frames from the socket
                            if let Some(frames_rx) = self.frames_rx_from_socket.take() {
                                tokio::spawn(Self::read_from_socket_loop(
                                    frames_rx,
                                    self.event_tx.clone(),
                                    self.noise_socket.clone().unwrap(), // Safe to unwrap after successful connect
                                    // self.expected_disconnect is tricky here, maybe pass a shared flag or handle in main loop
                                ));
                            } else {
                                error!("frames_rx_from_socket is None after successful connection, this should not happen.");
                                // Handle this error case, perhaps by disconnecting
                                self.disconnect_internal().await;
                                if self.event_tx.send(ConnectionManagerEvent::Disconnected(true)).await.is_err() {
                                    error!("Failed to send Disconnected event: receiver dropped");
                                }
                            }
                        }
                        Err(e) => {
                            error!("Connection failed: {:?}", e);
                            // Map error to ConnectFailureReason if possible, otherwise use a generic one
                            let reason = if let Some(socket_err) = e.downcast_ref::<SocketError>() {
                                // Example: map specific socket errors to reasons
                                // For now, using a generic placeholder
                                crate::types::events::ConnectFailureReason::Unknown
                            } else {
                                crate::types::events::ConnectFailureReason::Unknown
                            };
                            if self.event_tx.send(ConnectionManagerEvent::ConnectionFailed(reason)).await.is_err() {
                                error!("Failed to send ConnectionFailed event: receiver dropped");
                            }
                        }
                    }
                }
                ConnectionManagerCommand::Disconnect => {
                    self.expected_disconnect = true;
                    self.disconnect_internal().await;
                     if self.event_tx.send(ConnectionManagerEvent::Disconnected(true)).await.is_err() {
                        error!("Failed to send Disconnected event: receiver dropped");
                    }
                }
                ConnectionManagerCommand::SendFrame(encrypted_frame) => {
                    if !self.is_connected {
                        warn!("SendFrame command received but not connected.");
                        // Optionally notify sender of failure
                        continue;
                    }
                    if let Some(noise_socket) = &self.noise_socket {
                        match noise_socket.send_frame(&encrypted_frame).await {
                            Ok(_) => debug!("Frame sent successfully"),
                            Err(e) => {
                                error!("Failed to send frame: {:?}", e);
                                // Decide if this error warrants a disconnect or just an error event
                                // For now, we log and continue. A more robust implementation might
                                // count errors and disconnect if too many occur.
                            }
                        }
                    } else {
                        error!("Attempted to send frame but noise_socket is None");
                    }
                }
            }
        }
        info!("ConnectionManager stopped");
    }

    async fn connect_internal(
        &mut self,
        persistence_manager: Arc<PersistenceManager>,
    ) -> Result<(), anyhow::Error> {
        info!("ConnectionManager: Attempting to connect...");
        let (mut frame_socket, mut frames_rx) = FrameSocket::new();
        frame_socket.connect().await.map_err(|e| {
            error!("FrameSocket connect failed: {:?}", e);
            anyhow::Error::new(e) // Ensure it's converted to anyhow::Error
        })?;

        let device_snapshot = persistence_manager.get_device_snapshot().await;
        let noise_socket_result =
            handshake::do_handshake(&device_snapshot, &mut frame_socket, &mut frames_rx).await;

        match noise_socket_result {
            Ok(noise_socket) => {
                self.frame_socket = Some(frame_socket);
                self.frames_rx_from_socket = Some(frames_rx);
                self.noise_socket = Some(noise_socket);
                info!("ConnectionManager: Handshake successful, connection established.");
                Ok(())
            }
            Err(e) => {
                error!("Handshake failed: {:?}", e);
                // Ensure frame_socket is closed if handshake fails partially
                frame_socket.close().await;
                Err(e)
            }
        }
    }

    async fn disconnect_internal(&mut self) {
        info!("ConnectionManager: Disconnecting...");
        if let Some(fs) = self.frame_socket.as_mut() {
            fs.close().await;
        }
        self.frame_socket = None;
        self.noise_socket = None;
        self.frames_rx_from_socket = None; // Ensure this is cleared
        self.is_connected = false;
        // self.persistence_manager = None; // Clear persistence manager reference
        info!("ConnectionManager: Disconnected.");
    }

    // This loop runs in a separate task and reads frames from the WebSocket.
    // It owns its copy of the event_tx channel and the noise_socket Arc.
    async fn read_from_socket_loop(
        mut frames_rx: mpsc::Receiver<Bytes>,
        event_tx: mpsc::Sender<ConnectionManagerEvent>,
        noise_socket: Arc<NoiseSocket>,
        // expected_disconnect_flag: Arc<AtomicBool>, // Consider how to signal this
    ) {
        debug!("ConnectionManager: Starting read_from_socket_loop");
        loop {
            tokio::select! {
                // Add a way to shut down this loop if ConnectionManager itself is dropped or signaled.
                // For example, by dropping event_tx or using a dedicated shutdown signal.
                // _ = shutdown_signal.notified() => { info!("read_from_socket_loop shutting down."); break; }

                frame_opt = frames_rx.recv() => {
                    match frame_opt {
                        Some(encrypted_frame) => {
                            match noise_socket.decrypt_frame(&encrypted_frame) {
                                Ok(decrypted_payload) => {
                                    if event_tx.send(ConnectionManagerEvent::FrameReceived(decrypted_payload)).await.is_err() {
                                        error!("Failed to send FrameReceived event: receiver dropped. Stopping read loop.");
                                        break;
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to decrypt frame: {:?}. This might indicate a critical error.", e);
                                    // Depending on the error, might need to signal a disconnect.
                                    // For now, just log and continue. If decryption fails consistently,
                                    // the connection is likely unusable.
                                }
                            }
                        }
                        None => {
                            info!("FrameSocket disconnected (frames_rx ended).");
                            // Determine if this was expected. This is tricky as this loop is independent.
                            // One way: ConnectionManager sets a flag when it initiates disconnect.
                            // Another: Client facade tells ConnectionManager it's an expected disconnect.
                            // For now, assume unexpected if the loop terminates this way without prior explicit disconnect.
                            // This needs to be coordinated with `expected_disconnect` in the main ConnectionManager struct.
                            // A simple approach is to always send `Disconnected(false)` and let the receiver
                            // (e.g., Client facade) decide based on its own state if it was expected.
                            // However, the original design had `expected_disconnect` in the Client.
                            // Let's assume for now that if this channel closes, it's an "unmanaged" disconnect.
                            if event_tx.send(ConnectionManagerEvent::Disconnected(false)).await.is_err() {
                                error!("Failed to send Disconnected event: receiver dropped.");
                            }
                            break; // Exit loop
                        }
                    }
                }
            }
        }
        debug!("ConnectionManager: Exiting read_from_socket_loop");
    }
}

// Helper to spawn the ConnectionManager in its own task
pub fn spawn_connection_manager(
    buffer_size: usize,
) -> (
    mpsc::Sender<ConnectionManagerCommand>,
    mpsc::Receiver<ConnectionManagerEvent>,
) {
    let (cmd_tx, cmd_rx) = mpsc::channel(buffer_size);
    let (evt_tx, evt_rx) = mpsc::channel(buffer_size);

    let mut manager = ConnectionManager::new(cmd_rx, evt_tx);

    tokio::spawn(async move {
        manager.run().await;
    });

    (cmd_tx, evt_rx)
}
