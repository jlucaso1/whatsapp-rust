use crate::binary::node::Node;
use crate::binary::node::NodeContent;
use crate::handshake;
use crate::pair;
use crate::proto_helpers::MessageExt;
use crate::signal::session::SessionBuilder;
use crate::signal::state::prekey_bundle::PreKeyBundle;
use crate::signal::store::SessionStore;
use crate::socket::{FrameSocket, NoiseSocket, SocketError};
use crate::store;

use crate::appstate::keys::ALL_PATCH_NAMES;
use crate::binary;
use crate::proto::whatsapp as wa;
use crate::qrcode;
use crate::signal::{address::SignalAddress, session::SessionCipher};
use crate::types::events::{ConnectFailureReason, ContactUpdate, Event};
use crate::types::jid::{Jid, SERVER_JID};
use crate::types::message::MessageInfo;
use log::{debug, error, info, warn};
use prost::Message as ProtoMessage;
use rand::Rng;
use rand::RngCore;
use scopeguard;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot, Mutex, Notify, RwLock};
use tokio::time::{sleep, Duration};

pub type EventHandler = Box<dyn Fn(Arc<Event>) + Send + Sync>;
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

fn pad_message_v2(mut plaintext: Vec<u8>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    // Generate a random padding length from 1-15 bytes.
    let mut pad_val = rng.gen::<u8>() & 0x0F;
    if pad_val == 0 {
        pad_val = 0x0F;
    }
    // Append `pad_val` bytes with the value of `pad_val`.
    let padding = vec![pad_val; pad_val as usize];
    plaintext.extend_from_slice(&padding);
    plaintext
}

pub struct Client {
    pub store: tokio::sync::RwLock<store::Device>,

    // Concurrency and state management
    pub(crate) is_logged_in: Arc<AtomicBool>,
    pub(crate) is_connecting: Arc<AtomicBool>,
    pub(crate) is_running: Arc<AtomicBool>,
    pub(crate) shutdown_notifier: Arc<Notify>,

    // Socket and connection fields
    pub(crate) frame_socket: Arc<Mutex<Option<FrameSocket>>>,
    pub(crate) noise_socket: Arc<Mutex<Option<Arc<NoiseSocket>>>>,
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
    /// Fetch pre-keys for a list of JIDs from the server.
    pub async fn fetch_pre_keys(
        &self,
        jids: &[Jid],
    ) -> Result<HashMap<Jid, PreKeyBundle>, anyhow::Error> {
        let mut user_nodes = Vec::with_capacity(jids.len());
        for jid in jids {
            user_nodes.push(Node {
                tag: "user".into(),
                attrs: [("jid".to_string(), jid.to_string())].into(),
                content: None,
            });
        }

        let resp_node = self
            .send_iq(crate::request::InfoQuery {
                namespace: "encrypt",
                query_type: crate::request::InfoQueryType::Get,
                to: SERVER_JID.parse().unwrap(),
                content: Some(NodeContent::Nodes(vec![Node {
                    tag: "key".into(),
                    attrs: Default::default(),
                    content: Some(NodeContent::Nodes(user_nodes)),
                }])),
                id: None,
                target: None,
                timeout: None,
            })
            .await?;

        let list_node = resp_node
            .get_optional_child("list")
            .ok_or_else(|| anyhow::anyhow!("<list> not found in pre-key response"))?;

        let mut bundles = HashMap::new();
        for user_node in list_node.children().unwrap_or_default() {
            if user_node.tag != "user" {
                continue;
            }
            let mut attrs = user_node.attrs();
            let jid = attrs.jid("jid");
            let bundle = match self.node_to_pre_key_bundle(&jid, user_node) {
                Ok(b) => b,
                Err(e) => {
                    log::warn!("Failed to parse pre-key bundle for {}: {}", jid, e);
                    continue;
                }
            };
            bundles.insert(jid, bundle);
        }

        Ok(bundles)
    }

    fn node_to_pre_key_bundle(
        &self,
        jid: &Jid,
        node: &Node,
    ) -> Result<PreKeyBundle, anyhow::Error> {
        fn extract_bytes(node: Option<&Node>) -> Result<Vec<u8>, anyhow::Error> {
            match node.and_then(|n| n.content.as_ref()) {
                Some(NodeContent::Bytes(b)) => Ok(b.clone()),
                _ => Err(anyhow::anyhow!("Expected bytes in node content")),
            }
        }

        if let Some(error_node) = node.get_optional_child("error") {
            return Err(anyhow::anyhow!(
                "Error getting prekeys: {}",
                error_node.to_string()
            ));
        }

        let reg_id_bytes = extract_bytes(node.get_optional_child("registration"))?;
        if reg_id_bytes.len() != 4 {
            return Err(anyhow::anyhow!("Invalid registration ID length"));
        }
        let registration_id = u32::from_be_bytes(reg_id_bytes.try_into().unwrap());

        let keys_node = node.get_optional_child("keys").unwrap_or(node);

        let identity_key_bytes = extract_bytes(keys_node.get_optional_child("identity"))?;
        if identity_key_bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "Invalid identity key length: got {}, expected 32",
                identity_key_bytes.len()
            ));
        }
        let identity_key = crate::signal::identity::IdentityKey::new(
            crate::signal::ecc::keys::DjbEcPublicKey::new(identity_key_bytes.try_into().unwrap()),
        );

        let mut pre_key_id = None;
        let mut pre_key_public = None;
        if let Some(pre_key_node) = keys_node.get_optional_child("key") {
            let (id, key) = self.node_to_pre_key(pre_key_node)?;
            pre_key_id = Some(id);
            pre_key_public = Some(key);
        }

        let signed_pre_key_node = keys_node
            .get_optional_child("skey")
            .ok_or(anyhow::anyhow!("Missing signed prekey"))?;
        let (signed_pre_key_id, signed_pre_key_public, signed_pre_key_signature) =
            self.node_to_signed_pre_key(signed_pre_key_node)?;

        Ok(PreKeyBundle {
            registration_id,
            device_id: jid.device as u32,
            pre_key_id,
            pre_key_public,
            signed_pre_key_id,
            signed_pre_key_public,
            signed_pre_key_signature,
            identity_key,
        })
    }

    fn node_to_pre_key(
        &self,
        node: &Node,
    ) -> Result<(u32, crate::signal::ecc::keys::DjbEcPublicKey), anyhow::Error> {
        let id_bytes = node
            .get_optional_child("id")
            .and_then(|n| n.content.as_ref())
            .and_then(|c| {
                if let NodeContent::Bytes(b) = c {
                    Some(b.clone())
                } else {
                    None
                }
            })
            .ok_or(anyhow::anyhow!("Missing pre-key ID"))?;
        if id_bytes.len() != 3 {
            return Err(anyhow::anyhow!("Invalid pre-key ID length"));
        }
        let id = u32::from_be_bytes([0, id_bytes[0], id_bytes[1], id_bytes[2]]);

        let value_bytes = node
            .get_optional_child("value")
            .and_then(|n| n.content.as_ref())
            .and_then(|c| {
                if let NodeContent::Bytes(b) = c {
                    Some(b.clone())
                } else {
                    None
                }
            })
            .ok_or(anyhow::anyhow!("Missing pre-key value"))?;
        if value_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Invalid pre-key value length"));
        }

        Ok((
            id,
            crate::signal::ecc::keys::DjbEcPublicKey::new(value_bytes.try_into().unwrap()),
        ))
    }

    fn node_to_signed_pre_key(
        &self,
        node: &Node,
    ) -> Result<(u32, crate::signal::ecc::keys::DjbEcPublicKey, [u8; 64]), anyhow::Error> {
        let (id, public_key) = self.node_to_pre_key(node)?;
        let signature_bytes = node
            .get_optional_child("signature")
            .and_then(|n| n.content.as_ref())
            .and_then(|c| {
                if let NodeContent::Bytes(b) = c {
                    Some(b.clone())
                } else {
                    None
                }
            })
            .ok_or(anyhow::anyhow!("Missing signed pre-key signature"))?;
        if signature_bytes.len() != 64 {
            return Err(anyhow::anyhow!("Invalid signature length"));
        }

        Ok((id, public_key, signature_bytes.try_into().unwrap()))
    }
    pub fn new(store: store::Device) -> Self {
        let mut unique_id_bytes = [0u8; 2];
        rand::thread_rng().fill_bytes(&mut unique_id_bytes);

        Self {
            store: tokio::sync::RwLock::new(store),
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
    pub async fn run(self: &Arc<Self>) {
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
                    warn!(
                        "Message loop exited with an error. Will attempt to reconnect if enabled."
                    );
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
    pub async fn connect(self: &Arc<Self>) -> Result<(), anyhow::Error> {
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

        // Spawn keepalive loop after successful connect
        let client_clone = self.clone();
        tokio::spawn(client_clone.keepalive_loop());

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

    async fn request_app_state_keys(&self, keys: Vec<Vec<u8>>) {
        use crate::proto::whatsapp::message::protocol_message;

        let key_ids = keys
            .into_iter()
            .map(|id| wa::message::AppStateSyncKeyId { key_id: Some(id) })
            .collect();

        let msg = wa::Message {
            protocol_message: Some(Box::new(wa::message::ProtocolMessage {
                r#type: Some(protocol_message::Type::AppStateSyncKeyRequest as i32),
                app_state_sync_key_request: Some(wa::message::AppStateSyncKeyRequest { key_ids }),
                ..Default::default()
            })),
            ..Default::default()
        };

        if let Some(own_jid) = self.store.read().await.id.clone() {
            let own_non_ad = own_jid.to_non_ad();
            if let Err(e) = self.send_message(own_non_ad, msg).await {
                warn!("Failed to send app state key request: {:?}", e);
            }
        } else {
            warn!("Can't request app state keys, not logged in.");
        }
    }

    async fn read_messages_loop(self: &Arc<Self>) -> Result<(), anyhow::Error> {
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

    /// Removes padding from a decrypted message based on the wire protocol version.
    /// v2 messages use PKCS#7-like padding, where the last byte indicates the padding length.
    /// v3 and later messages do not have padding.
    fn unpad_message(plaintext: &[u8], version: u8) -> Result<Vec<u8>, anyhow::Error> {
        if version < 3 {
            if plaintext.is_empty() {
                return Err(anyhow::anyhow!("plaintext is empty, cannot unpad"));
            }
            let pad_len = plaintext[plaintext.len() - 1] as usize;
            if pad_len == 0 || pad_len > plaintext.len() {
                return Err(anyhow::anyhow!("invalid padding length: {}", pad_len));
            }
            Ok(plaintext[..plaintext.len() - pad_len].to_vec())
        } else {
            Ok(plaintext.to_vec())
        }
    }

    async fn process_encrypted_frame(self: &Arc<Self>, encrypted_frame: &bytes::Bytes) {
        let noise_socket_arc = { self.noise_socket.lock().await.clone() };
        let noise_socket = match noise_socket_arc {
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

    async fn process_node(self: &Arc<Self>, node: Node) {
        // Special handling for noisy app state sync responses
        if node.tag == "iq" {
            if let Some(sync_node) = node.get_optional_child("sync") {
                if let Some(collection_node) = sync_node.get_optional_child("collection") {
                    let name = collection_node.attrs().string("name");
                    debug!(target: "Client/Recv", "Received app state sync response for '{}' (hiding content).", name);
                } else {
                    debug!(target: "Client/Recv", "{}", node);
                }
            } else {
                debug!(target: "Client/Recv", "{}", node);
            }
        } else {
            debug!(target: "Client/Recv", "{}", node);
        }

        // Add this check at the top
        if node.tag == "xmlstreamend" {
            warn!(target: "Client", "Received <xmlstreamend/>, treating as disconnect.");
            self.shutdown_notifier.notify_one();
            return;
        }

        if node.tag == "iq" && self.handle_iq_response(node.clone()).await {
            return;
        }

        match node.tag.as_str() {
            "success" => self.handle_success(&node).await,
            "failure" => self.handle_connect_failure(&node).await,
            "stream:error" => self.handle_stream_error(&node).await,
            "ib" => self.clone().handle_ib(&node).await,
            "iq" => {
                if !self.handle_iq(&node).await {
                    warn!(target: "Client", "Received unhandled IQ: {}", node);
                }
            }
            "receipt" => self.handle_receipt(&node).await,
            "notification" => self.handle_notification(node).await,
            "call" | "presence" | "chatstate" => self.handle_unimplemented(&node.tag).await,
            "message" => {
                let client_clone = self.clone();
                tokio::spawn(async move {
                    client_clone.handle_encrypted_message(node).await;
                });
            }
            "ack" => {} // Ignore acks for now
            _ => {
                warn!(target: "Client", "Received unknown top-level node: {}", node);
            }
        }
    }

    async fn handle_unimplemented(&self, tag: &str) {
        warn!(target: "Client", "TODO: Implement handler for <{}>", tag);
    }

    async fn handle_receipt(&self, node: &Node) {
        let mut attrs = node.attrs();
        let from = attrs.jid("from");
        let id = attrs.string("id");
        let receipt_type_str = attrs.optional_string("type").unwrap_or("delivery");

        use crate::types::presence::ReceiptType;
        let receipt_type = match receipt_type_str {
            "read" => ReceiptType::Read,
            "played" => ReceiptType::Played,
            _ => ReceiptType::Delivered,
        };

        info!(
            "Received receipt type '{:?}' for message {} from {}",
            receipt_type, id, from
        );

        self.dispatch_event(Event::Receipt(crate::types::events::Receipt {
            message_ids: vec![id],
            source: crate::types::message::MessageSource {
                chat: from.clone(),
                sender: from.clone(),
                ..Default::default()
            },
            timestamp: chrono::Utc::now(),
            r#type: receipt_type,
            message_sender: from,
        }))
        .await;
    }

    async fn handle_notification(&self, node: Node) {
        // This will be a dispatcher for different notification types.
        // For now, we'll just log it as a TODO.
        self.handle_unimplemented(&node.tag).await;
        self.dispatch_event(Event::Notification(node)).await;
    }

    // --- App State Sync Logic ---
    async fn fetch_app_state_patches(
        &self,
        name: &str,
        version: u64,
        is_full_sync: bool,
    ) -> Result<Node, crate::request::IqError> {
        use crate::binary::node::{Attrs, Node, NodeContent};
        use crate::request::{InfoQuery, InfoQueryType};
        use crate::types::jid;

        let mut attrs = Attrs::new();
        attrs.insert("name".to_string(), name.to_string());
        attrs.insert("return_snapshot".to_string(), is_full_sync.to_string());
        if !is_full_sync {
            attrs.insert("version".to_string(), version.to_string());
        }

        let collection_node = Node {
            tag: "collection".to_string(),
            attrs,
            content: None,
        };

        let sync_node = Node {
            tag: "sync".to_string(),
            attrs: Attrs::new(),
            content: Some(NodeContent::Nodes(vec![collection_node])),
        };

        let iq = InfoQuery {
            namespace: "w:sync:app:state",
            query_type: InfoQueryType::Set,
            to: jid::SERVER_JID.parse().unwrap(),
            target: None,
            id: None,
            content: Some(NodeContent::Nodes(vec![sync_node])),
            timeout: None,
        };

        self.send_iq(iq).await
    }

    async fn app_state_sync(&self, name: &str, full_sync: bool) {
        use crate::appstate::processor::{PatchList, Processor};

        info!(target: "Client/AppState", "Starting AppState sync for '{}' (full_sync: {})", name, full_sync);

        // Use the client's store
        let store_guard = self.store.read().await;
        let app_state_store = store_guard.app_state_store.clone();
        let app_state_keys = store_guard.app_state_keys.clone();
        let contacts_store = store_guard.identities.clone();
        let processor = Processor::new(app_state_store.clone(), app_state_keys.clone());

        let mut current_state = match app_state_store.get_app_state_version(name).await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to get app state version for {}: {:?}", name, e);
                return;
            }
        };
        if full_sync {
            current_state.version = 0;
            current_state.hash = [0; 128];
        }

        let mut has_more = true;
        let mut is_first_sync = full_sync;

        while has_more {
            let resp_node = match self
                .fetch_app_state_patches(name, current_state.version, is_first_sync)
                .await
            {
                Ok(resp) => resp,
                Err(e) => {
                    error!(target: "Client/AppState", "Failed to fetch patches for {}: {:?}", name, e);
                    return;
                }
            };
            is_first_sync = false;

            if let Some(sync_node) = resp_node.get_optional_child("sync") {
                if let Some(collection_node) = sync_node.get_optional_child("collection") {
                    let mut attrs = collection_node.attrs();
                    has_more = attrs.optional_bool("has_more_patches");

                    let mut patches = Vec::new();
                    if let Some(patches_node) = collection_node.get_optional_child("patches") {
                        for patch_child in patches_node.children().unwrap_or_default() {
                            if let Some(crate::binary::node::NodeContent::Bytes(b)) =
                                &patch_child.content
                            {
                                if let Ok(patch) = wa::SyncdPatch::decode(b.as_slice()) {
                                    patches.push(patch);
                                }
                            }
                        }
                    }

                    let snapshot = None;
                    // TODO: Implement snapshot downloading from external blob reference
                    // For now, this part is skipped.

                    let patch_list = PatchList {
                        name: name.to_string(),
                        has_more_patches: has_more,
                        patches,
                        snapshot,
                    };

                    match processor
                        .decode_patches(&patch_list, current_state.clone())
                        .await
                    {
                        Ok((mutations, new_state)) => {
                            current_state = new_state;
                            info!(
                                target: "Client/AppState",
                                "Decoded {} mutations for '{}'. New version: {}",
                                mutations.len(), name, current_state.version
                            );
                            // Process and dispatch contact updates from mutations
                            for mutation in &mutations {
                                if mutation.operation == wa::syncd_mutation::SyncdOperation::Set {
                                    if let Some(contact_action) =
                                        mutation.action.contact_action.as_ref()
                                    {
                                        if mutation.index.len() > 1 {
                                            let jid_str = &mutation.index[1];
                                            if let Ok(jid) = Jid::from_str(jid_str) {
                                                // Use a dummy key for now, real identity keys are separate
                                                let _ = contacts_store
                                                    .put_identity(jid_str, [0u8; 32])
                                                    .await;
                                                let event = Event::ContactUpdate(ContactUpdate {
                                                    jid,
                                                    timestamp: chrono::Utc::now(),
                                                    action: Box::new(contact_action.clone()),
                                                    from_full_sync: full_sync,
                                                });
                                                let _ = self.dispatch_event(event).await;
                                            }
                                        }
                                        // TODO: Handle other action types (e.g., PinAction, ArchiveChatAction)
                                    }
                                }
                            }
                            // TODO: Dispatch these mutations as events
                        }
                        Err(e) => {
                            if let crate::appstate::errors::AppStateError::KeysNotFound(missing) = e
                            {
                                info!(
                                    "Requesting {} missing app state keys for sync of '{}'",
                                    missing.len(),
                                    name
                                );
                                self.request_app_state_keys(missing).await;
                            } else {
                                error!("Failed to decode patches for {}: {:?}", name, e);
                                has_more = false; // Stop on error
                            }
                        }
                    };
                } else {
                    warn!(target: "Client/AppState", "Sync response for '{}' missing <collection> node", name);
                    has_more = false;
                }
            } else {
                warn!(target: "Client/AppState", "Sync response for '{}' missing <sync> node", name);
                has_more = false;
            }
        }
        info!(target: "Client/AppState", "Finished AppState sync for '{}'", name);
    }

    pub async fn set_passive(&self, passive: bool) -> Result<(), crate::request::IqError> {
        use crate::binary::node::Node;
        use crate::request::{InfoQuery, InfoQueryType};
        use crate::types::jid::SERVER_JID;

        let tag = if passive { "passive" } else { "active" };

        let query = InfoQuery {
            namespace: "passive",
            query_type: InfoQueryType::Set,
            to: SERVER_JID.parse().unwrap(),
            target: None,
            id: None,
            content: Some(crate::binary::node::NodeContent::Nodes(vec![Node {
                tag: tag.to_string(),
                ..Default::default()
            }])),
            timeout: None,
        };

        self.send_iq(query).await.map(|_| ())
    }

    async fn handle_success(self: &Arc<Self>, _node: &Node) {
        info!("Successfully authenticated with WhatsApp servers!");
        self.is_logged_in.store(true, Ordering::Relaxed);
        *self.last_successful_connect.lock().await = Some(chrono::Utc::now());
        self.auto_reconnect_errors.store(0, Ordering::Relaxed);

        let client_clone = self.clone();
        tokio::spawn(async move {
            if let Err(e) = client_clone.set_passive(false).await {
                warn!("Failed to send post-connect passive IQ: {:?}", e);
            }
            client_clone
                .dispatch_event(Event::Connected(crate::types::events::Connected))
                .await;
        });
    }

    async fn expect_disconnect(&self) {
        self.expected_disconnect.store(true, Ordering::Relaxed);
    }

    async fn handle_stream_error(&self, node: &Node) {
        self.is_logged_in.store(false, Ordering::Relaxed);
        // Don't clear waiters here, let the disconnect handler do it.

        let mut attrs = node.attrs();
        let code = attrs.optional_string("code").unwrap_or("");
        let conflict_type = node
            .get_optional_child("conflict")
            .map(|n| n.attrs().optional_string("type").unwrap_or("").to_string())
            .unwrap_or_default();

        // The key is to decide if this is a recoverable error.
        // A `515` after pairing is normal and should trigger a reconnect.
        // A `515` at any other time is also a server-side disconnect that we should recover from.
        // Therefore, we do NOT call `expect_disconnect()` for it. The `run` loop will see it
        // as an unexpected disconnect and try to reconnect.
        match (code, conflict_type.as_str()) {
            ("515", _) => {
                info!(target: "Client", "Got 515 stream error, server is closing stream. Will auto-reconnect.");
                // We do *not* set expected_disconnect to true. This allows the run loop to handle it.
            }
            ("401", "device_removed") | (_, "replaced") => {
                info!(target: "Client", "Got stream error indicating client was removed or replaced. Logging out.");
                self.expect_disconnect().await; // This is a terminal error, so we expect the disconnect.
                self.enable_auto_reconnect.store(false, Ordering::Relaxed);

                let event = if conflict_type == "replaced" {
                    Event::StreamReplaced(crate::types::events::StreamReplaced)
                } else {
                    Event::LoggedOut(crate::types::events::LoggedOut {
                        on_connect: false,
                        reason: ConnectFailureReason::LoggedOut,
                    })
                };
                self.dispatch_event(event).await;
            }
            ("503", _) => {
                info!(target: "Client", "Got 503 service unavailable, will auto-reconnect.");
                // We do *not* set expected_disconnect to true. This allows the run loop to handle it.
            }
            _ => {
                error!(target: "Client", "Unknown stream error: {}", node);
                self.expect_disconnect().await; // Assume unknown stream errors are terminal.
                self.dispatch_event(Event::StreamError(crate::types::events::StreamError {
                    code: code.to_string(),
                    raw: Some(node.clone()),
                }))
                .await;
            }
        }

        // We must signal the read_messages_loop to stop after a stream error.
        self.shutdown_notifier.notify_one();
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

    async fn handle_iq(self: &Arc<Self>, node: &Node) -> bool {
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
        let event_arc = Arc::new(event);
        let handlers = self.event_handlers.read().await;
        for wrapped in handlers.iter() {
            (wrapped.handler)(event_arc.clone());
        }
    }

    pub async fn send_node(&self, node: Node) -> Result<(), ClientError> {
        let noise_socket_arc = { self.noise_socket.lock().await.clone() };
        let noise_socket = match noise_socket_arc {
            Some(socket) => socket,
            None => return Err(ClientError::NotConnected),
        };

        debug!(target: "Client/Send", "{}", node);

        let payload = crate::binary::marshal(&node).map_err(|e| {
            error!("Failed to marshal node: {:?}", e);
            SocketError::Crypto("Marshal error".to_string())
        })?;

        noise_socket.send_frame(&payload).await.map_err(Into::into)
    }

    // --- Signal E2EE: Handle incoming encrypted message ---
    pub async fn handle_encrypted_message(self: Arc<Self>, node: Node) {
        let info = match self.parse_message_info(&node).await {
            Ok(info) => info,
            Err(e) => {
                log::warn!("Failed to parse message info: {:?}", e);
                return;
            }
        };

        let enc_node = match node.get_optional_child("enc") {
            Some(node) => node,
            None => {
                warn!("Received message without <enc> child: {}", node.tag);
                return;
            }
        };

        let ciphertext = match &enc_node.content {
            Some(crate::binary::node::NodeContent::Bytes(b)) => b.clone(),
            _ => {
                warn!("Enc node has no byte content");
                return;
            }
        };

        let enc_version = enc_node
            .attrs()
            .optional_string("v")
            .unwrap_or("2")
            .parse::<u8>()
            .unwrap_or(2);

        let signal_address = SignalAddress::new(
            info.source.sender.user.clone(),
            info.source.sender.device as u32,
        );
        let store_guard = self.store.read().await;
        let device_arc = Arc::new((*store_guard).clone());
        let cipher = SessionCipher::new(device_arc.clone(), signal_address);

        // Determine enc type and use the new decrypt logic
        let enc_type = enc_node.attrs().string("type"); // pkmsg or msg
        use crate::signal::protocol::{Ciphertext, PreKeySignalMessage, SignalMessage};
        let ciphertext_enum = match enc_type.as_str() {
            "pkmsg" => match PreKeySignalMessage::deserialize(&ciphertext) {
                Ok(msg) => Ciphertext::PreKey(msg),
                Err(e) => {
                    log::warn!("Failed to deserialize PreKeySignalMessage: {:?}", e);
                    return;
                }
            },
            "msg" => match SignalMessage::deserialize(&ciphertext) {
                // Note: This doesn't verify MAC yet
                Ok(msg) => Ciphertext::Whisper(msg),
                Err(e) => {
                    log::warn!("Failed to deserialize SignalMessage: {:?}", e);
                    return;
                }
            },
            _ => {
                log::warn!("Unsupported enc type: {}", enc_type);
                return;
            }
        };

        match cipher.decrypt(ciphertext_enum).await {
            Ok(padded_plaintext) => {
                let plaintext = match Self::unpad_message(&padded_plaintext, enc_version) {
                    Ok(pt) => pt,
                    Err(e) => {
                        log::error!("Failed to unpad message from {}: {}", info.source.sender, e);
                        return;
                    }
                };

                log::info!(
                    "Successfully decrypted and unpadded message from {}: {} bytes",
                    info.source.sender,
                    plaintext.len()
                );

                // The decrypted plaintext is ALWAYS a wa::Message

                if let Ok(mut msg) = wa::Message::decode(plaintext.as_slice()) {
                    // Now, check for specific message types within the wa::Message container
                    if let Some(protocol_msg) = msg.protocol_message.take() {
                        if protocol_msg.r#type()
                            == wa::message::protocol_message::Type::AppStateSyncKeyShare
                        {
                            if let Some(key_share) = protocol_msg.app_state_sync_key_share.as_ref()
                            {
                                log::info!(
                                    "Found AppStateSyncKeyShare with {} keys. Storing them now.",
                                    key_share.keys.len()
                                );
                                self.handle_app_state_sync_key_share(key_share).await;

                                let self_clone = self.clone();
                                tokio::spawn(async move {
                                    for name in ALL_PATCH_NAMES {
                                        self_clone.app_state_sync(name, false).await;
                                    }
                                });
                            }
                        } else {
                            log::warn!(
                                "Received unhandled protocol message of type: {:?}",
                                protocol_msg.r#type()
                            );
                        }
                    } else if msg.sender_key_distribution_message.is_some() {
                        // TODO: handle SKDM
                        log::warn!("Received unhandled SenderKeyDistributionMessage");
                    } else {
                        let base_msg = (&msg).get_base_message();

                        log::debug!(
                            target: "Client/Recv",
                            "Decrypted message content: {:?}",
                            base_msg
                        );

                        if let Some(text) = base_msg.conversation.as_ref() {
                            log::info!(r#"Received message from {}: "{}""#, info.push_name, text);
                        } else if let Some(ext_text) = base_msg.extended_text_message.as_ref() {
                            if let Some(text) = ext_text.text.as_ref() {
                                log::info!(
                                    r#"Received extended text message from {}: "{}""#,
                                    info.push_name,
                                    text
                                );

                                // compare text if is equal to "send"
                                if text == "send" {
                                    log::info!("Received 'send' command, sending a response.");
                                    let response_text = "Hello from Signal E2EE!";
                                    if let Err(e) = self
                                        .send_text_message(info.source.chat.clone(), response_text)
                                        .await
                                    {
                                        log::error!("Failed to send response message: {:?}", e);
                                    }
                                }
                            }
                        }
                        let _ = self
                            .dispatch_event(Event::Message(Box::new(msg), info.clone()))
                            .await;
                    }
                } else {
                    log::warn!("Failed to unmarshal decrypted plaintext into wa::Message");
                }
            }
            Err(e) => {
                log::error!(
                    "Failed to decrypt message from {}: {:?}",
                    info.source.sender,
                    e
                );
            }
        }
    }

    // --- Signal E2EE: Dummy parse_message_info ---
    pub async fn parse_message_info(&self, node: &Node) -> Result<MessageInfo, anyhow::Error> {
        let mut attrs = node.attrs();
        Ok(MessageInfo {
            source: crate::types::message::MessageSource {
                chat: attrs.jid("from"),
                sender: {
                    let from = attrs.jid("from");
                    if from.is_group() {
                        attrs.jid("participant")
                    } else {
                        from
                    }
                },
                is_from_me: false,
                is_group: attrs.jid("from").is_group(),
                ..Default::default()
            },
            id: attrs.string("id"),
            ..Default::default()
        })
    }

    // --- Signal E2EE: Send a text message ---
    pub async fn send_text_message(&self, to: Jid, text: &str) -> Result<(), anyhow::Error> {
        let content = wa::Message {
            conversation: Some(text.to_string()),
            ..Default::default()
        };
        self.send_message(to, content).await
    }

    // --- Signal E2EE: Send a message (encrypted) ---
    pub async fn send_message(&self, to: Jid, message: wa::Message) -> Result<(), anyhow::Error> {
        let store = self.store.read().await;
        if store.id.is_none() {
            return Err(anyhow::anyhow!("Not logged in"));
        }

        // 1. Create a Signal Address for the recipient
        let signal_address = SignalAddress::new(to.user.clone(), to.device as u32);

        // 2. Load the session record, build if needed, and persist after encryption.
        let store_arc = Arc::new(store.clone());
        let mut session_record = store
            .load_session(&signal_address)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let session_exists = !session_record.is_fresh();

        if !session_exists {
            info!("No session found for {}, building a new one.", to);
            let bundles = self.fetch_pre_keys(&[to.clone()]).await?;
            let bundle = bundles
                .get(&to)
                .ok_or_else(|| anyhow::anyhow!("No prekey bundle for {}", to))?;
            let builder = SessionBuilder::new(store_arc.clone(), signal_address.clone());
            if let Err(e) = builder.process_bundle(&mut session_record, bundle).await {
                return Err(anyhow::anyhow!(e.to_string()));
            }
        }

        // 3. Encrypt the message using the session record
        let cipher = SessionCipher::new(store_arc.clone(), signal_address.clone());
        let serialized_msg_proto = <wa::Message as ProtoMessage>::encode_to_vec(&message);

        let padded_plaintext = pad_message_v2(serialized_msg_proto);

        let encrypted_message = match cipher.encrypt(&mut session_record, &padded_plaintext).await {
            Ok(msg) => msg,
            Err(e) => return Err(anyhow::anyhow!(format!("{:?}", e))),
        };

        // Save the updated session record
        store_arc
            .store_session(&signal_address, &session_record)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        // Determine encryption type for stanza
        let enc_type = match encrypted_message.q_type() {
            crate::signal::protocol::PREKEY_TYPE => "pkmsg",
            _ => "msg",
        };

        // 4. Construct the <message> stanza
        let stanza = crate::binary::node::Node {
            tag: "message".to_string(),
            attrs: [
                ("to".to_string(), to.to_string()),
                ("id".to_string(), self.generate_request_id()),
                ("type".to_string(), "text".to_string()),
            ]
            .into(),
            content: Some(crate::binary::node::NodeContent::Nodes(vec![
                crate::binary::node::Node {
                    tag: "enc".to_string(),
                    attrs: [
                        ("v".to_string(), "2".to_string()),
                        ("type".to_string(), enc_type.to_string()),
                    ]
                    .into(),
                    content: Some(crate::binary::node::NodeContent::Bytes(
                        encrypted_message.serialize(),
                    )),
                },
            ])),
        };

        // 5. Send it
        self.send_node(stanza).await?;

        Ok(())
    }

    async fn handle_ib(self: Arc<Self>, node: &Node) {
        for child in node.children().unwrap_or_default() {
            match child.tag.as_str() {
                "dirty" => {
                    let mut attrs = child.attrs();
                    let dirty_type = attrs.string("type");
                    if dirty_type == "account_sync" {
                        info!(
                            target: "Client",
                            "Received 'account_sync' dirty state notification. Triggering sync for all app state categories."
                        );
                        let client_clone = self.clone();
                        tokio::spawn(async move {
                            for name in ALL_PATCH_NAMES {
                                client_clone.app_state_sync(name, false).await;
                            }
                        });
                    } else {
                        info!(
                            target: "Client",
                            "Received dirty state notification for type: '{}'. Triggering App State Sync.",
                            dirty_type
                        );
                        let client_clone = self.clone();
                        tokio::spawn(async move {
                            client_clone.app_state_sync(&dirty_type, false).await;
                        });
                    }
                }
                "edge_routing" => {
                    info!(target: "Client", "Received edge routing info, ignoring for now.");
                }
                _ => {
                    warn!(target: "Client", "Unhandled ib child: <{}>", child.tag);
                }
            }
        }
    }
    /// Store AppStateSyncKey(s) received from a protocol message.
    pub async fn handle_app_state_sync_key_share(&self, keys: &wa::message::AppStateSyncKeyShare) {
        let key_store = self.store.read().await.app_state_keys.clone();
        for key in &keys.keys {
            if let Some(key_id_proto) = &key.key_id {
                if let Some(key_id) = &key_id_proto.key_id {
                    if let Some(key_data) = &key.key_data {
                        if let Some(fingerprint) = &key_data.fingerprint {
                            if let Some(data) = &key_data.key_data {
                                let fingerprint_bytes = fingerprint.encode_to_vec();
                                let new_key = store::traits::AppStateSyncKey {
                                    key_data: data.clone(),
                                    fingerprint: fingerprint_bytes,
                                    timestamp: key_data.timestamp(),
                                };

                                if let Err(e) =
                                    key_store.set_app_state_sync_key(key_id, new_key).await
                                {
                                    error!(
                                        "Failed to store app state sync key {:?}: {:?}",
                                        hex::encode(key_id),
                                        e
                                    );
                                } else {
                                    info!(
                                        "Stored new app state sync key with ID {:?}",
                                        hex::encode(key_id)
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// Needed to use guard with Client methods
