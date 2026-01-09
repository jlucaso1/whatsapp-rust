//! WhatsApp client wrapper for UI integration

use std::sync::Arc;

use log::{debug, error, info, warn};
use tokio::sync::{Mutex, mpsc};
use wacore::proto_helpers::MessageExt;
use wacore::types::call::{CallId, CallMediaType, EndCallReason};
use wacore::types::events::Event;
use wacore::types::presence::ReceiptType;
use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;
use whatsapp_rust::bot::Bot;
use whatsapp_rust::calls::CallOptions;
use whatsapp_rust::client::Client;
use whatsapp_rust::store::SqliteStore;
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use whatsapp_rust_ureq_http_client::UreqHttpClient;

use super::media_callback::CallMediaManager;
use crate::state::{
    ChatMessage, DownloadableMedia, IncomingCall, MediaContent, MediaType, UiEvent,
};
use wacore::download::MediaType as DownloadMediaType;

/// Helper struct for building DownloadableMedia from common message fields
struct DownloadableBuilder<'a> {
    direct_path: Option<&'a str>,
    media_key: Option<&'a [u8]>,
    file_enc_sha256: Option<&'a [u8]>,
    file_length: Option<u64>,
    mime_type: &'a str,
    duration_secs: Option<u32>,
    download_type: DownloadMediaType,
}

impl<'a> DownloadableBuilder<'a> {
    /// Try to build a DownloadableMedia from the provided fields.
    /// Returns None if any required field (direct_path, media_key, file_enc_sha256) is missing.
    fn build(self) -> Option<DownloadableMedia> {
        let direct_path = self.direct_path?;
        let media_key = self.media_key?;
        let file_enc_sha256 = self.file_enc_sha256?;

        Some(DownloadableMedia {
            direct_path: direct_path.to_string(),
            media_key: media_key.to_vec(),
            file_enc_sha256: file_enc_sha256.to_vec(),
            file_length: self.file_length.unwrap_or(0),
            mime_type: self.mime_type.to_string(),
            duration_secs: self.duration_secs,
            download_type: self.download_type,
        })
    }
}

/// Extract relay credentials (auth_token, relay_key) from WebRTC transport or fallback data.
async fn extract_relay_credentials(
    call_manager: &whatsapp_rust::calls::CallManager,
    call_id: &CallId,
    relay: &whatsapp_rust::calls::RelayData,
) -> (Vec<u8>, Vec<u8>) {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    if let Some(transport) = call_manager.get_webrtc_transport(call_id).await
        && let Some(relay_info) = transport.connected_relay().await
    {
        let auth = engine
            .decode(&relay_info.auth_token)
            .unwrap_or_else(|_| relay_info.auth_token.as_bytes().to_vec());
        let key = engine
            .decode(&relay_info.relay_key)
            .unwrap_or_else(|_| relay_info.relay_key.as_bytes().to_vec());
        return (auth, key);
    }

    // Fallback to relay data
    let auth = relay.auth_tokens.first().cloned().unwrap_or_default();
    let key = relay.relay_key.clone().unwrap_or_default();
    (auth, key)
}

/// Shared client handle for accessing the WhatsApp client from UI
pub type ClientHandle = Arc<Mutex<Option<Arc<Client>>>>;

/// Shared UI event sender for sending events from async operations
pub type UiEventSender = Arc<Mutex<Option<mpsc::UnboundedSender<UiEvent>>>>;

/// Shared media manager handle for accessing from UI operations
pub type MediaManagerHandle = Arc<Mutex<Option<Arc<CallMediaManager>>>>;

/// WhatsApp client wrapper that manages the connection and provides
/// a clean interface for UI operations.
pub struct WhatsAppClient {
    /// Tokio runtime for async operations
    runtime: Arc<tokio::runtime::Runtime>,
    /// Shared client reference
    client_handle: ClientHandle,
    /// Shared UI event sender for sending events from operations like start_call
    ui_sender: UiEventSender,
    /// Shared media manager for call media operations
    media_manager_handle: MediaManagerHandle,
    /// Whether the client has been started
    started: bool,
}

impl WhatsAppClient {
    /// Create a new WhatsApp client wrapper
    pub fn new() -> Self {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to create tokio runtime"),
        );

        Self {
            runtime,
            client_handle: Arc::new(Mutex::new(None)),
            ui_sender: Arc::new(Mutex::new(None)),
            media_manager_handle: Arc::new(Mutex::new(None)),
            started: false,
        }
    }

    /// Get the runtime handle for UI async operations
    #[allow(dead_code)]
    pub fn runtime(&self) -> Arc<tokio::runtime::Runtime> {
        self.runtime.clone()
    }

    /// Get the client handle for sending messages
    #[allow(dead_code)]
    pub fn client_handle(&self) -> ClientHandle {
        self.client_handle.clone()
    }

    /// Start the WhatsApp client in a background thread
    ///
    /// Returns a receiver for UI events, or an error if already started
    pub fn start(&mut self) -> Result<mpsc::UnboundedReceiver<UiEvent>, &'static str> {
        if self.started {
            return Err("WhatsApp client already started");
        }
        self.started = true;

        let (ui_tx, ui_rx) = mpsc::unbounded_channel::<UiEvent>();
        let client_handle = self.client_handle.clone();
        let ui_sender = self.ui_sender.clone();
        let media_manager_handle = self.media_manager_handle.clone();
        let runtime = self.runtime.clone();

        // Store the sender for use by other methods like start_call
        {
            let ui_sender_clone = self.ui_sender.clone();
            let ui_tx_clone = ui_tx.clone();
            self.runtime.spawn(async move {
                let mut guard = ui_sender_clone.lock().await;
                *guard = Some(ui_tx_clone);
            });
        }

        std::thread::spawn(move || {
            runtime.block_on(async move {
                // Also store sender in the async context
                {
                    let mut guard = ui_sender.lock().await;
                    *guard = Some(ui_tx.clone());
                }
                Self::run_client(ui_tx, client_handle, media_manager_handle).await;
            });
        });

        Ok(ui_rx)
    }

    /// Internal async function to run the client
    async fn run_client(
        ui_tx: mpsc::UnboundedSender<UiEvent>,
        client_handle: ClientHandle,
        media_manager_handle: MediaManagerHandle,
    ) {
        // Initialize SQLite backend
        let backend = match SqliteStore::new("whatsapp.db").await {
            Ok(store) => Arc::new(store),
            Err(e) => {
                error!("Failed to create SQLite backend: {}", e);
                let _ = ui_tx.send(UiEvent::Error(format!("Database error: {}", e)));
                return;
            }
        };
        info!("SQLite backend initialized successfully.");

        let transport_factory = TokioWebSocketTransportFactory::new();
        let http_client = UreqHttpClient::new();

        // Create the media manager for handling call media sessions
        let media_manager = Arc::new(CallMediaManager::new());

        // Store media manager reference for UI to use (for accept_call)
        {
            let mut guard = media_manager_handle.lock().await;
            *guard = Some(media_manager.clone());
        }

        let ui_tx_clone = ui_tx.clone();
        let media_manager_clone = media_manager.clone();

        let mut bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport_factory)
            .with_http_client(http_client)
            .on_event(move |event, client| {
                let ui_tx = ui_tx_clone.clone();
                let media_manager = media_manager_clone.clone();
                async move {
                    Self::handle_event(event, client, ui_tx, media_manager).await;
                }
            })
            .build()
            .await
            .expect("Failed to build bot");

        // Store client reference for UI to use
        {
            let mut guard = client_handle.lock().await;
            *guard = Some(bot.client());
        }

        // Notify UI that init is complete
        let _ = ui_tx.send(UiEvent::InitComplete);

        // Run the bot
        match bot.run().await {
            Ok(handle) => {
                let _ = handle.await;
            }
            Err(e) => {
                error!("Bot failed to start: {}", e);
                let _ = ui_tx.send(UiEvent::Error(format!("Connection failed: {}", e)));
            }
        }
    }

    /// Handle events from the WhatsApp client
    async fn handle_event(
        event: Event,
        client: Arc<Client>,
        ui_tx: mpsc::UnboundedSender<UiEvent>,
        media_manager: Arc<CallMediaManager>,
    ) {
        match event {
            Event::PairingQrCode { code, timeout } => {
                info!("QR code received");
                let _ = ui_tx.send(UiEvent::QrCode {
                    code,
                    timeout_secs: timeout.as_secs(),
                });
            }
            Event::PairingCode { code, timeout } => {
                info!("Pair code received: {}", code);
                let _ = ui_tx.send(UiEvent::PairCode {
                    code,
                    timeout_secs: timeout.as_secs(),
                });
            }
            Event::PairSuccess(_) => {
                info!("Pairing successful, syncing...");
                let _ = ui_tx.send(UiEvent::PairSuccess);
            }
            Event::Connected(_) => {
                info!("Connected to WhatsApp!");
                let _ = ui_tx.send(UiEvent::Connected);
            }
            Event::LoggedOut(_) => {
                info!("Logged out from WhatsApp");
                let _ = ui_tx.send(UiEvent::Disconnected("Logged out".to_string()));
            }
            Event::CallOffer(offer) => {
                // Skip offline calls - they are stale calls from offline sync
                if offer.is_offline {
                    info!(
                        "Ignoring offline call {} from {} (stale)",
                        offer.meta.call_id, offer.meta.from
                    );
                    return;
                }

                info!("Incoming call from {}", offer.meta.from);
                let call = IncomingCall::with_name(
                    offer.meta.call_id.clone(),
                    offer.meta.from.to_string(),
                    offer.meta.from.to_string(),
                    offer.media_type == CallMediaType::Video,
                    offer.is_offline,
                );
                let _ = ui_tx.send(UiEvent::IncomingCall(call));
            }
            Event::CallEnded(ended) => {
                // Stop the media session if active
                media_manager.stop_session(&ended.meta.call_id).await;
                let _ = ui_tx.send(UiEvent::CallEnded(ended.meta.call_id.into()));
            }
            Event::CallAccepted(accepted) => {
                info!("Call {} accepted by peer", accepted.meta.call_id);

                // Get relay data and keys for media connection
                let call_id_str = accepted.meta.call_id.clone();
                let call_id = CallId::new(&call_id_str);
                let call_manager = client.get_call_manager().await;

                // Check if we have relay data and encryption keys
                let relay_data = call_manager.get_relay_data(&call_id).await;
                let _is_initiator = call_manager.is_initiator(&call_id).await.unwrap_or(true);

                match relay_data {
                    Some(relay) => {
                        info!(
                            "Starting media connection for call {} ({} endpoints, hbh_key={} bytes)",
                            call_id_str,
                            relay.endpoints.len(),
                            relay.hbh_key.as_ref().map(|k| k.len()).unwrap_or(0),
                        );

                        // 1. Connect via WebRTC DataChannel first
                        match call_manager.connect_relay(&call_id, &relay).await {
                            Ok(relay_name) => {
                                info!(
                                    "Call {} connected to relay {} via WebRTC",
                                    call_id_str, relay_name
                                );

                                if let Some(hbh_key) = &relay.hbh_key {
                                    let (auth_token_bytes, relay_key_bytes) =
                                        extract_relay_credentials(&call_manager, &call_id, &relay)
                                            .await;

                                    if let Err(e) = media_manager
                                        .start_webrtc_session(
                                            call_manager.clone(),
                                            &call_id_str,
                                            hbh_key,
                                            &auth_token_bytes,
                                            &relay_key_bytes,
                                        )
                                        .await
                                    {
                                        error!(
                                            "Failed to start WebRTC audio for call {}: {}",
                                            call_id_str, e
                                        );
                                    } else {
                                        info!("Call {} WebRTC audio pipeline started", call_id_str);
                                    }
                                } else {
                                    warn!(
                                        "No hbh_key available for call {} - cannot start audio",
                                        call_id_str
                                    );
                                }
                            }
                            Err(e) => {
                                error!("Failed to connect WebRTC for call {}: {}", call_id_str, e);
                            }
                        }
                    }
                    None => {
                        warn!("No relay data available for call {}", call_id_str);
                    }
                }

                let _ = ui_tx.send(UiEvent::CallAccepted(accepted.meta.call_id.into()));
            }
            Event::Message(msg, info) => {
                // Use MessageExt to unwrap ephemeral/device_sent/view_once wrappers
                let base_msg = msg.get_base_message();

                // Check if this is a reaction message
                if let Some(reaction) = &base_msg.reaction_message {
                    if let Some(key) = &reaction.key
                        && let Some(target_id) = &key.id
                    {
                        let emoji = reaction.text.clone().unwrap_or_default();
                        debug!(
                            "Reaction '{}' from {} on message {}",
                            emoji, info.source.sender, target_id
                        );

                        // Use remote_jid from key if available, otherwise use chat from info
                        let chat_jid = key
                            .remote_jid
                            .as_ref()
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| info.source.chat.to_string());

                        let normalized_chat_jid = client.normalize_jid_to_lid(&chat_jid).await;

                        let _ = ui_tx.send(UiEvent::ReactionReceived {
                            chat_jid: normalized_chat_jid,
                            message_id: target_id.clone(),
                            sender: info.source.sender.to_string(),
                            emoji,
                        });
                    }
                    return;
                }

                // Try to extract media content
                let media_result = Self::try_extract_media(base_msg, &client).await;

                // Extract text content
                let content = msg
                    .text_content()
                    .map(|s| s.to_string())
                    .or_else(|| {
                        // Use caption from media if available
                        msg.get_caption().map(|s| s.to_string())
                    })
                    .unwrap_or_else(|| {
                        // Use placeholder based on media type
                        if media_result.is_some() {
                            String::new() // Empty for media-only messages
                        } else {
                            "[Media]".to_string()
                        }
                    });

                let mut chat_message = ChatMessage {
                    id: info.id.clone(),
                    sender: info.source.sender.to_string(),
                    sender_name: None, // Will be set in handle_message_received for groups
                    content,
                    timestamp: info.timestamp,
                    is_from_me: info.source.is_from_me,
                    is_read: false,
                    media: None,
                    reactions: std::collections::HashMap::new(),
                };

                // Attach media if downloaded successfully
                if let Some(media) = media_result {
                    chat_message.media = Some(media);
                }

                // Normalize chat JID to LID if mapping exists
                // This ensures the same user doesn't appear as different chats
                // when messages come from PN vs LID
                let normalized_chat_jid = client
                    .normalize_jid_to_lid(&info.source.chat.to_string())
                    .await;

                let sender_name = (!info.push_name.is_empty()).then(|| info.push_name.clone());

                let _ = ui_tx.send(UiEvent::MessageReceived {
                    chat_jid: normalized_chat_jid,
                    message: Box::new(chat_message),
                    sender_name,
                });
            }
            Event::Receipt(receipt) => {
                let Some(dominated_type) = (match &receipt.r#type {
                    ReceiptType::Read | ReceiptType::ReadSelf => Some(ReceiptType::Read),
                    ReceiptType::Played | ReceiptType::PlayedSelf => Some(ReceiptType::Played),
                    _ => None,
                }) else {
                    return;
                };

                info!(
                    "Receipt {:?} for {} message(s) in {}",
                    dominated_type,
                    receipt.message_ids.len(),
                    receipt.source.chat
                );

                // Normalize the chat JID
                let normalized_chat_jid = client
                    .normalize_jid_to_lid(&receipt.source.chat.to_string())
                    .await;

                let _ = ui_tx.send(UiEvent::ReceiptReceived {
                    chat_jid: normalized_chat_jid,
                    message_ids: receipt.message_ids,
                    receipt_type: dominated_type,
                });
            }
            _ => {}
        }
    }

    /// Helper to download media with logging
    async fn download_media<T: wacore::download::Downloadable>(
        client: &Arc<Client>,
        media: &T,
        media_name: &str,
    ) -> Option<Vec<u8>> {
        info!("Downloading {}...", media_name);
        match client.download(media).await {
            Ok(data) => {
                info!(
                    "{} downloaded successfully: {} bytes",
                    media_name,
                    data.len()
                );
                Some(data)
            }
            Err(e) => {
                warn!("Failed to download {}: {}", media_name, e);
                None
            }
        }
    }

    /// Try to extract and download media from a message
    async fn try_extract_media(msg: &wa::Message, _client: &Arc<Client>) -> Option<MediaContent> {
        // Check for sticker message
        if let Some(sticker) = &msg.sticker_message
            && let Some(data) = Self::download_media(_client, sticker.as_ref(), "sticker").await
        {
            let is_animated = sticker.is_animated.unwrap_or(false);
            let is_lottie = sticker.is_lottie.unwrap_or(false);
            let mime = sticker
                .mimetype
                .clone()
                .unwrap_or_else(|| "image/webp".to_string());
            info!(
                "Sticker: mime={}, is_animated={}, is_lottie={}, size={} bytes",
                mime,
                is_animated,
                is_lottie,
                data.len()
            );
            return Some(MediaContent {
                media_type: MediaType::Sticker,
                data: Arc::new(data),
                mime_type: mime,
                width: sticker.width,
                height: sticker.height,
                caption: None,
                downloadable: None,
                is_animated,
                duration_secs: None,
            });
        }

        // Check for image message
        if let Some(image) = &msg.image_message
            && let Some(data) = Self::download_media(_client, image.as_ref(), "image").await
        {
            return Some(MediaContent {
                media_type: MediaType::Image,
                data: Arc::new(data),
                mime_type: image
                    .mimetype
                    .clone()
                    .unwrap_or_else(|| "image/jpeg".to_string()),
                width: image.width,
                height: image.height,
                caption: image.caption.clone(),
                downloadable: None,
                is_animated: false,
                duration_secs: None,
            });
        }

        // Check for video message - store thumbnail for preview, metadata for download
        if let Some(video) = &msg.video_message {
            // Use thumbnail for display, or empty vec if none
            let thumbnail_data = video
                .jpeg_thumbnail
                .as_ref()
                .filter(|t| !t.is_empty())
                .cloned()
                .unwrap_or_default();

            // Build downloadable info using helper
            let downloadable = DownloadableBuilder {
                direct_path: video.direct_path.as_deref(),
                media_key: video.media_key.as_deref(),
                file_enc_sha256: video.file_enc_sha256.as_deref(),
                file_length: video.file_length,
                mime_type: video.mimetype.as_deref().unwrap_or("video/mp4"),
                duration_secs: video.seconds,
                download_type: DownloadMediaType::Video,
            }
            .build();

            // Only return if we have either thumbnail or downloadable info
            if !thumbnail_data.is_empty() || downloadable.is_some() {
                return Some(MediaContent {
                    media_type: MediaType::Video,
                    data: Arc::new(thumbnail_data),
                    mime_type: "image/jpeg".to_string(), // Thumbnail is JPEG
                    width: video.width,
                    height: video.height,
                    caption: video.caption.clone(),
                    downloadable,
                    is_animated: false,
                    duration_secs: video.seconds,
                });
            }
        }

        // Check for audio message - lazy load, only download when user clicks play
        if let Some(audio) = &msg.audio_message {
            let default_mime = "audio/ogg; codecs=opus";
            let mime_type = audio.mimetype.as_deref().unwrap_or(default_mime);

            // Build downloadable info using helper
            let downloadable = DownloadableBuilder {
                direct_path: audio.direct_path.as_deref(),
                media_key: audio.media_key.as_deref(),
                file_enc_sha256: audio.file_enc_sha256.as_deref(),
                file_length: audio.file_length,
                mime_type,
                duration_secs: audio.seconds,
                download_type: DownloadMediaType::Audio,
            }
            .build();

            // Only return if we have downloadable info
            if downloadable.is_some() {
                return Some(MediaContent {
                    media_type: MediaType::Audio,
                    data: Arc::new(vec![]), // Empty until downloaded
                    mime_type: mime_type.to_string(),
                    width: None,
                    height: None,
                    caption: None,
                    downloadable,
                    is_animated: false,
                    duration_secs: audio.seconds,
                });
            }
        }

        // Check for document message (no download, just metadata)
        if let Some(doc) = &msg.document_message {
            return Some(MediaContent {
                media_type: MediaType::Document,
                data: Arc::new(vec![]),
                mime_type: doc.mimetype.clone().unwrap_or_default(),
                width: None,
                height: None,
                caption: doc.caption.clone(),
                downloadable: None,
                is_animated: false,
                duration_secs: None,
            });
        }

        None
    }

    /// Send a text message to a chat
    pub fn send_message(&self, jid_str: &str, content: &str) {
        let client_handle = self.client_handle.clone();
        let jid_str = jid_str.to_string();
        let content = content.to_string();
        let runtime = self.runtime.clone();

        std::thread::spawn(move || {
            runtime.block_on(async move {
                // Parse JID string
                let jid: Jid = match jid_str.parse() {
                    Ok(j) => j,
                    Err(e) => {
                        error!("Invalid JID '{}': {}", jid_str, e);
                        return;
                    }
                };

                let guard = client_handle.lock().await;
                if let Some(client) = guard.as_ref() {
                    let message = wa::Message {
                        conversation: Some(content.clone()),
                        ..Default::default()
                    };

                    match client.send_message(jid, message).await {
                        Ok(msg_id) => {
                            info!("Message sent successfully: {}", msg_id);
                        }
                        Err(e) => {
                            error!("Failed to send message: {}", e);
                        }
                    }
                } else {
                    error!("Client not available for sending message");
                }
            });
        });
    }

    /// Download media using DownloadableMedia info
    /// Returns a oneshot receiver that will contain the result
    pub fn download_downloadable_media(
        &self,
        downloadable: DownloadableMedia,
    ) -> tokio::sync::oneshot::Receiver<Result<Vec<u8>, String>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let client_handle = self.client_handle.clone();
        let runtime = self.runtime.clone();

        std::thread::spawn(move || {
            runtime.block_on(async move {
                let guard = client_handle.lock().await;
                if let Some(client) = guard.as_ref() {
                    info!(
                        "Downloading media: {} bytes expected",
                        downloadable.file_length
                    );
                    match client.download(&downloadable).await {
                        Ok(data) => {
                            info!("Media downloaded successfully: {} bytes", data.len());
                            let _ = tx.send(Ok(data));
                        }
                        Err(e) => {
                            error!("Failed to download media: {}", e);
                            let _ = tx.send(Err(e.to_string()));
                        }
                    }
                } else {
                    let _ = tx.send(Err("Client not available".to_string()));
                }
            });
        });

        rx
    }

    /// Send a PTT audio message to a chat
    pub fn send_audio_message(
        &self,
        jid_str: &str,
        audio_data: Vec<u8>,
        duration_secs: u32,
        waveform: Vec<u8>,
    ) {
        use wacore::download::MediaType as WaMediaType;

        let client_handle = self.client_handle.clone();
        let jid_str = jid_str.to_string();
        let runtime = self.runtime.clone();

        std::thread::spawn(move || {
            runtime.block_on(async move {
                // Parse JID string
                let jid: Jid = match jid_str.parse() {
                    Ok(j) => j,
                    Err(e) => {
                        error!("Invalid JID '{}': {}", jid_str, e);
                        return;
                    }
                };

                let guard = client_handle.lock().await;
                if let Some(client) = guard.as_ref() {
                    // Upload the audio file
                    let upload_result = match client.upload(audio_data, WaMediaType::Audio).await {
                        Ok(resp) => resp,
                        Err(e) => {
                            error!("Failed to upload audio: {}", e);
                            return;
                        }
                    };

                    info!("Audio uploaded successfully: {}", upload_result.url);

                    // Build the AudioMessage
                    let audio_message = wa::message::AudioMessage {
                        url: Some(upload_result.url),
                        direct_path: Some(upload_result.direct_path),
                        media_key: Some(upload_result.media_key),
                        file_sha256: Some(upload_result.file_sha256),
                        file_enc_sha256: Some(upload_result.file_enc_sha256),
                        file_length: Some(upload_result.file_length),
                        mimetype: Some("audio/ogg; codecs=opus".to_string()),
                        seconds: Some(duration_secs),
                        ptt: Some(true), // This marks it as a voice message
                        waveform: Some(waveform),
                        ..Default::default()
                    };

                    let message = wa::Message {
                        audio_message: Some(Box::new(audio_message)),
                        ..Default::default()
                    };

                    match client.send_message(jid, message).await {
                        Ok(msg_id) => {
                            info!("Audio message sent successfully: {}", msg_id);
                        }
                        Err(e) => {
                            error!("Failed to send audio message: {}", e);
                        }
                    }
                } else {
                    error!("Client not available for sending audio message");
                }
            });
        });
    }

    /// Send "composing" chat state (typing indicator)
    pub fn send_composing(&self, jid_str: &str) {
        let client_handle = self.client_handle.clone();
        let jid_str = jid_str.to_string();
        let runtime = self.runtime.clone();

        std::thread::spawn(move || {
            runtime.block_on(async move {
                let jid: Jid = match jid_str.parse() {
                    Ok(j) => j,
                    Err(e) => {
                        error!("Invalid JID '{}': {}", jid_str, e);
                        return;
                    }
                };

                let guard = client_handle.lock().await;
                if let Some(client) = guard.as_ref()
                    && let Err(e) = client.chatstate().send_composing(&jid).await
                {
                    warn!("Failed to send composing state: {}", e);
                }
            });
        });
    }

    /// Send "paused" chat state (stopped typing)
    pub fn send_paused(&self, jid_str: &str) {
        let client_handle = self.client_handle.clone();
        let jid_str = jid_str.to_string();
        let runtime = self.runtime.clone();

        std::thread::spawn(move || {
            runtime.block_on(async move {
                let jid: Jid = match jid_str.parse() {
                    Ok(j) => j,
                    Err(e) => {
                        error!("Invalid JID '{}': {}", jid_str, e);
                        return;
                    }
                };

                let guard = client_handle.lock().await;
                if let Some(client) = guard.as_ref()
                    && let Err(e) = client.chatstate().send_paused(&jid).await
                {
                    warn!("Failed to send paused state: {}", e);
                }
            });
        });
    }

    /// Send read receipts to mark messages as read
    ///
    /// # Arguments
    /// * `chat_jid_str` - The JID of the chat (e.g., "123456@s.whatsapp.net")
    /// * `messages` - List of (message_id, sender_jid_string) tuples
    pub fn send_read_receipts(&self, chat_jid_str: &str, messages: Vec<(String, String)>) {
        if messages.is_empty() {
            return;
        }

        let client_handle = self.client_handle.clone();
        let chat_jid_str = chat_jid_str.to_string();
        let runtime = self.runtime.clone();

        std::thread::spawn(move || {
            runtime.block_on(async move {
                // Parse chat JID
                let chat_jid: Jid = match chat_jid_str.parse() {
                    Ok(j) => j,
                    Err(e) => {
                        error!("Invalid chat JID '{}': {}", chat_jid_str, e);
                        return;
                    }
                };

                // Parse message sender JIDs, skipping invalid ones
                let parsed_messages: Vec<(String, Jid)> = messages
                    .into_iter()
                    .filter_map(|(msg_id, sender_str)| {
                        sender_str
                            .parse::<Jid>()
                            .inspect_err(|e| warn!("Invalid sender JID '{}': {}", sender_str, e))
                            .ok()
                            .map(|jid| (msg_id, jid))
                    })
                    .collect();

                if parsed_messages.is_empty() {
                    return;
                }

                let guard = client_handle.lock().await;
                if let Some(client) = guard.as_ref() {
                    client.send_read_receipts(&chat_jid, &parsed_messages).await;
                } else {
                    error!("Client not available for sending read receipts");
                }
            });
        });
    }

    /// Accept an incoming call
    ///
    /// This sends the accept signaling to the caller and starts the media session.
    pub fn accept_call(&self, call_id: &str) {
        let client_handle = self.client_handle.clone();
        let media_manager_handle = self.media_manager_handle.clone();
        let call_id = call_id.to_string();
        let runtime = self.runtime.clone();

        std::thread::spawn(move || {
            runtime.block_on(async move {
                let guard = client_handle.lock().await;
                if let Some(client) = guard.as_ref() {
                    let call_manager = client.get_call_manager().await;
                    let call_id_obj = CallId::new(&call_id);

                    // First, decrypt the call key if we haven't already
                    // For incoming calls, we need to decrypt the offer's encrypted key
                    if let Some(call_info) = call_manager.get_call_info(&call_id_obj).await
                        && call_info.encryption.is_none() {
                            // Need to decrypt the call key from the offer
                            if let Some(ref enc_data) = call_info.offer_enc_data {
                                // Use caller_pn (phone number) for Signal encryption if available,
                                // otherwise fall back to call_creator
                                let sender = call_info.caller_pn.as_ref().unwrap_or(&call_info.call_creator);

                                info!(
                                    "Decrypting call key for incoming call {} from {} (type: {:?})",
                                    call_id, sender, enc_data.enc_type
                                );

                                match client.decrypt_call_key_from(
                                    sender,
                                    &enc_data.ciphertext,
                                    enc_data.enc_type,
                                ).await {
                                    Ok(call_key) => {
                                        info!("Successfully decrypted call key for incoming call {}", call_id);
                                        if let Err(e) = call_manager.store_encryption_key(&call_id_obj, call_key).await {
                                            error!("Failed to store decrypted call key for {}: {}", call_id, e);
                                        }
                                    }
                                    Err(e) => {
                                        error!("Failed to decrypt call key for {}: {}", call_id, e);
                                    }
                                }
                            } else {
                                warn!("No encrypted key data in incoming call {}", call_id);
                            }
                        }

                    // Send preaccept to show "ringing" to caller
                    match call_manager.send_preaccept(&call_id_obj).await {
                        Ok(node) => {
                            if let Err(e) = client.send_node(node).await {
                                warn!("Failed to send preaccept: {}", e);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to build preaccept: {}", e);
                        }
                    }

                    // Then send accept
                    match call_manager.accept_call(&call_id_obj).await {
                        Ok(node) => {
                            if let Err(e) = client.send_node(node).await {
                                error!("Failed to send accept: {}", e);
                            } else {
                                info!("Call accepted: {}", call_id);

                                // Start the media session (same as CallAccepted handler for outgoing calls)
                                let relay_data = call_manager.get_relay_data(&call_id_obj).await;
                                let derived_keys = call_manager.get_derived_keys(&call_id_obj).await;

                                match relay_data {
                                    Some(relay) => {
                                        info!(
                                            "Starting WebRTC connection for incoming call {} ({} endpoints, hbh_key={} bytes)",
                                            call_id,
                                            relay.endpoints.len(),
                                            relay.hbh_key.as_ref().map(|k| k.len()).unwrap_or(0)
                                        );

                                        // 1. Connect via WebRTC DataChannel first
                                        match call_manager.connect_relay(&call_id_obj, &relay).await {
                                            Ok(relay_name) => {
                                                info!(
                                                    "Incoming call {} WebRTC connected to relay {}",
                                                    call_id, relay_name
                                                );

                                                if let Some(hbh_key) = &relay.hbh_key {
                                                    let (auth_token_bytes, relay_key_bytes) =
                                                        extract_relay_credentials(
                                                            &call_manager,
                                                            &call_id_obj,
                                                            &relay,
                                                        )
                                                        .await;

                                                    let media_guard = media_manager_handle.lock().await;
                                                    if let Some(ref media_manager) = *media_guard {
                                                        if let Err(e) = media_manager
                                                            .start_webrtc_session(
                                                                call_manager.clone(),
                                                                &call_id,
                                                                hbh_key,
                                                                &auth_token_bytes,
                                                                &relay_key_bytes,
                                                            )
                                                            .await
                                                        {
                                                            error!(
                                                                "Failed to start WebRTC audio for incoming call {}: {}",
                                                                call_id, e
                                                            );
                                                        } else {
                                                            info!(
                                                                "Incoming call {} WebRTC audio pipeline started",
                                                                call_id
                                                            );
                                                        }
                                                    } else {
                                                        error!("Media manager not available for incoming call {}", call_id);
                                                    }
                                                } else {
                                                    warn!(
                                                        "No hbh_key available for incoming call {} - cannot start audio",
                                                        call_id
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                error!(
                                                    "Failed to establish WebRTC for incoming call {}: {}",
                                                    call_id, e
                                                );
                                            }
                                        }
                                    }
                                    None => {
                                        warn!("No relay data available for incoming call {}", call_id);
                                    }
                                }
                                // Note: derived_keys are used for e2e SRTP encryption
                                // but for relay transport we use hbh_key instead
                                let _ = derived_keys; // Mark as intentionally unused
                            }
                        }
                        Err(e) => {
                            error!("Failed to accept call: {}", e);
                        }
                    }
                } else {
                    error!("Client not available for accepting call");
                }
            });
        });
    }

    /// Decline an incoming call
    ///
    /// This sends a reject signaling message to the caller with a "declined" reason.
    pub fn decline_call(&self, call_id: &str) {
        let client_handle = self.client_handle.clone();
        let call_id = call_id.to_string();
        let runtime = self.runtime.clone();

        std::thread::spawn(move || {
            runtime.block_on(async move {
                let guard = client_handle.lock().await;
                if let Some(client) = guard.as_ref() {
                    let call_manager = client.get_call_manager().await;
                    let call_id = CallId::new(&call_id);

                    match call_manager
                        .reject_call(&call_id, EndCallReason::Declined)
                        .await
                    {
                        Ok(node) => {
                            if let Err(e) = client.send_node(node).await {
                                error!("Failed to send reject: {}", e);
                            } else {
                                info!("Call declined: {}", call_id);
                            }
                        }
                        Err(e) => {
                            error!("Failed to decline call: {}", e);
                        }
                    }
                } else {
                    error!("Client not available for declining call");
                }
            });
        });
    }

    /// Start an outgoing call to the specified JID
    ///
    /// This initiates a call by:
    /// 1. Creating the call in CallManager
    /// 2. Ensuring a Signal session exists with the recipient
    /// 3. Encrypting the call key using Signal protocol
    /// 4. Building the offer stanza with encrypted key
    /// 5. Sending the stanza
    /// 6. Marking the offer as sent
    /// 7. Sending OutgoingCallStarted event to UI
    pub fn start_call(&self, recipient_jid_str: &str, is_video: bool) {
        let client_handle = self.client_handle.clone();
        let ui_sender = self.ui_sender.clone();
        let recipient_jid_str = recipient_jid_str.to_string();
        let runtime = self.runtime.clone();

        std::thread::spawn(move || {
            runtime.block_on(async move {
                // Helper to send failure event
                let send_failure = |ui_sender: &UiEventSender, jid: &str, error: String| {
                    let ui_sender = ui_sender.clone();
                    let jid = jid.to_string();
                    tokio::spawn(async move {
                        if let Some(sender) = ui_sender.lock().await.as_ref() {
                            let _ = sender.send(UiEvent::OutgoingCallFailed {
                                recipient_jid: jid,
                                error,
                            });
                        }
                    });
                };

                // Parse recipient JID
                let recipient_jid: Jid = match recipient_jid_str.parse() {
                    Ok(j) => j,
                    Err(e) => {
                        error!("Invalid recipient JID '{}': {}", recipient_jid_str, e);
                        send_failure(&ui_sender, &recipient_jid_str, format!("Invalid JID: {}", e));
                        return;
                    }
                };

                let guard = client_handle.lock().await;
                if let Some(client) = guard.as_ref() {
                    let call_manager = client.get_call_manager().await;
                    let options = if is_video {
                        CallOptions::video()
                    } else {
                        CallOptions::audio()
                    };

                    // Step 1: Create the call and get call ID
                    let call_id = match call_manager.start_call(recipient_jid.clone(), options).await
                    {
                        Ok(id) => id,
                        Err(e) => {
                            error!("Failed to create call: {}", e);
                            send_failure(&ui_sender, &recipient_jid_str, format!("Failed to create call: {}", e));
                            return;
                        }
                    };

                    // Step 2: Ensure we have a Signal session with the recipient
                    let session_target = match client.ensure_call_session(&recipient_jid).await {
                        Ok(target) => target,
                        Err(e) => {
                            error!("Failed to establish call session: {}", e);
                            // Clean up the call we created
                            let _ = call_manager.end_call(&call_id).await;
                            send_failure(&ui_sender, &recipient_jid_str, format!("Failed to establish session: {}", e));
                            return;
                        }
                    };

                    // Step 3: Encrypt the call key for the recipient and store it
                    let encrypted_key = match client.encrypt_call_key_for(&session_target).await {
                        Ok((call_key, encrypted)) => {
                            info!(
                                "Encrypted call key for {}: type={:?}, {} bytes",
                                session_target,
                                encrypted.enc_type,
                                encrypted.ciphertext.len()
                            );

                            // Store the encryption key in the call manager for later use
                            if let Err(e) = call_manager.store_encryption_key(&call_id, call_key).await {
                                warn!("Failed to store encryption key: {}", e);
                            } else {
                                info!("Stored encryption key for call {}", call_id);
                            }

                            Some(encrypted)
                        }
                        Err(e) => {
                            warn!(
                                "Failed to encrypt call key for {}: {} - proceeding without encrypted key",
                                session_target, e
                            );
                            None
                        }
                    };

                    // Step 4: Build the offer stanza with encrypted key
                    let node = match call_manager
                        .build_offer_stanza_with_key(&call_id, encrypted_key)
                        .await
                    {
                        Ok(n) => n,
                        Err(e) => {
                            error!("Failed to build offer stanza: {}", e);
                            send_failure(&ui_sender, &recipient_jid_str, format!("Failed to build offer: {}", e));
                            return;
                        }
                    };

                    // Step 5: Send the stanza
                    if let Err(e) = client.send_node(node).await {
                        error!("Failed to send call offer: {}", e);
                        send_failure(&ui_sender, &recipient_jid_str, format!("Failed to send offer: {}", e));
                        return;
                    }

                    // Step 6: Mark offer as sent (transitions to Ringing state)
                    if let Err(e) = call_manager.mark_offer_sent(&call_id).await {
                        warn!("Failed to mark offer as sent: {}", e);
                    }

                    info!(
                        "Call {} started to {}: {}",
                        call_id,
                        recipient_jid,
                        if is_video { "video" } else { "audio" }
                    );

                    // Step 7: Notify UI with the actual call ID
                    if let Some(sender) = ui_sender.lock().await.as_ref() {
                        let _ = sender.send(UiEvent::OutgoingCallStarted {
                            call_id,
                            recipient_jid: recipient_jid_str.clone(),
                        });
                    }
                } else {
                    error!("Client not available for starting call");
                    send_failure(&ui_sender, &recipient_jid_str, "Client not available".to_string());
                }
            });
        });
    }

    /// Cancel an outgoing call
    ///
    /// This sends a terminate signaling message to end the call.
    pub fn cancel_call(&self, call_id: &str) {
        let client_handle = self.client_handle.clone();
        let call_id = call_id.to_string();
        let runtime = self.runtime.clone();

        std::thread::spawn(move || {
            runtime.block_on(async move {
                let guard = client_handle.lock().await;
                if let Some(client) = guard.as_ref() {
                    let call_manager = client.get_call_manager().await;
                    let call_id = CallId::new(&call_id);

                    match call_manager.end_call(&call_id).await {
                        Ok(node) => {
                            if let Err(e) = client.send_node(node).await {
                                error!("Failed to send cancel: {}", e);
                            } else {
                                info!("Call cancelled: {}", call_id);
                            }
                        }
                        Err(e) => {
                            error!("Failed to cancel call: {}", e);
                        }
                    }
                } else {
                    error!("Client not available for cancelling call");
                }
            });
        });
    }
}

impl Default for WhatsAppClient {
    fn default() -> Self {
        Self::new()
    }
}
