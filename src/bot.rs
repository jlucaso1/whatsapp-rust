use crate::cache_config::CacheConfig;
use crate::client::Client;
use crate::pair_code::PairCodeOptions;
use crate::store::commands::DeviceCommand;
use crate::store::persistence_manager::PersistenceManager;
use crate::store::traits::Backend;
use crate::types::enc_handler::EncHandler;
use crate::types::events::{Event, EventHandler};
use crate::types::message::MessageInfo;
use anyhow::Result;
use log::{info, warn};
use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use thiserror::Error;
use wacore::runtime::Runtime;
use waproto::whatsapp as wa;

/// Typestate marker: a required builder field has not been provided yet.
pub struct Missing;
/// Typestate marker: a required builder field has been provided.
pub struct Provided;

#[derive(Debug, Error)]
pub enum BotBuilderError {
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub struct MessageContext {
    pub message: Box<wa::Message>,
    pub info: MessageInfo,
    pub client: Arc<Client>,
}

impl MessageContext {
    pub async fn send_message(
        &self,
        message: wa::Message,
    ) -> Result<crate::send::SendResult, anyhow::Error> {
        self.client
            .send_message(self.info.source.chat.clone(), message)
            .await
    }

    /// Build a quote context for this message.
    ///
    /// Handles:
    /// - Correct stanza_id/participant (newsletters + group status)
    /// - Stripping nested mentions to avoid accidental tags
    /// - Preserving bot quote chains (matches WhatsApp Web)
    ///
    /// Use this when you need manual control but want correct quoting behavior.
    pub fn build_quote_context(&self) -> wa::ContextInfo {
        // Use the standalone function from wacore with full message info
        // This handles newsletter/group status participant resolution
        wacore::proto_helpers::build_quote_context_with_info(
            &self.info.id,
            &self.info.source.sender,
            &self.info.source.chat,
            &self.message,
        )
    }

    pub async fn edit_message(
        &self,
        original_message_id: impl Into<String>,
        new_message: wa::Message,
    ) -> Result<String, anyhow::Error> {
        self.client
            .edit_message(
                self.info.source.chat.clone(),
                original_message_id,
                new_message,
            )
            .await
    }

    /// Delete a message for everyone in the chat.
    pub async fn revoke_message(
        &self,
        message_id: String,
        revoke_type: crate::send::RevokeType,
    ) -> Result<(), anyhow::Error> {
        self.client
            .revoke_message(self.info.source.chat.clone(), message_id, revoke_type)
            .await
    }
}

type EventHandlerCallback =
    Arc<dyn Fn(Event, Arc<Client>) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

struct BotEventHandler {
    client: Arc<Client>,
    event_handler: Option<EventHandlerCallback>,
}

impl EventHandler for BotEventHandler {
    fn handle_event(&self, event: &Event) {
        if let Some(handler) = &self.event_handler {
            let handler_clone = handler.clone();
            let event_clone = event.clone();
            let client_clone = self.client.clone();

            self.client
                .runtime
                .spawn(Box::pin(async move {
                    handler_clone(event_clone, client_clone).await;
                }))
                .detach();
        }
    }
}

/// Handle returned by [`Bot::run`] that can be awaited to wait for the
/// client's run loop to finish.
pub struct BotHandle {
    done_rx: futures::channel::oneshot::Receiver<()>,
    _abort_handle: wacore::runtime::AbortHandle,
}

impl BotHandle {
    /// Abort the bot's run task.
    pub fn abort(&self) {
        self._abort_handle.abort();
    }
}

impl std::future::Future for BotHandle {
    type Output = Result<(), futures::channel::oneshot::Canceled>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        Pin::new(&mut self.done_rx).poll(cx)
    }
}

pub struct Bot {
    client: Arc<Client>,
    sync_task_receiver: Option<async_channel::Receiver<crate::sync_task::MajorSyncTask>>,
    event_handler: Option<EventHandlerCallback>,
    pair_code_options: Option<PairCodeOptions>,
}

impl std::fmt::Debug for Bot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bot")
            .field("client", &"<Client>")
            .field("sync_task_receiver", &self.sync_task_receiver.is_some())
            .field("event_handler", &self.event_handler.is_some())
            .field("pair_code_options", &self.pair_code_options.is_some())
            .finish()
    }
}

impl Bot {
    pub fn builder() -> BotBuilder<Missing, Missing, Missing, Missing> {
        BotBuilder::new()
    }

    pub fn client(&self) -> Arc<Client> {
        self.client.clone()
    }

    pub async fn run(&mut self) -> Result<BotHandle> {
        if let Some(receiver) = self.sync_task_receiver.take() {
            let worker_client = Arc::downgrade(&self.client);
            self.client
                .runtime
                .spawn(Box::pin(async move {
                    while let Ok(task) = receiver.recv().await {
                        let Some(worker_client) = worker_client.upgrade() else {
                            break;
                        };

                        worker_client.process_sync_task(task).await;
                    }
                    info!("Sync worker shutting down.");
                }))
                .detach();
        }

        let handler = Arc::new(BotEventHandler {
            client: self.client.clone(),
            event_handler: self.event_handler.take(),
        });
        self.client.core.event_bus.add_handler(handler);

        // If pair code options are set, spawn a task to request pair code after socket is ready
        if let Some(options) = self.pair_code_options.take() {
            let client_for_pair = self.client.clone();
            self.client.runtime.spawn(Box::pin(async move {
                // Wait for socket to be ready (before login) with 30 second timeout
                if let Err(e) = client_for_pair
                    .wait_for_socket(std::time::Duration::from_secs(30))
                    .await
                {
                    warn!(target: "Bot/PairCode", "Timeout waiting for socket: {}", e);
                    return;
                }

                // Check if already logged in (paired via QR or existing session)
                if client_for_pair.is_logged_in() {
                    info!(target: "Bot/PairCode", "Already logged in, skipping pair code request");
                    return;
                }

                // Request pair code
                match client_for_pair.pair_with_code(options).await {
                    Ok(code) => {
                        info!(target: "Bot/PairCode", "Pair code generated: {}", code);
                    }
                    Err(e) => {
                        warn!(target: "Bot/PairCode", "Failed to request pair code: {}", e);
                    }
                }
            })).detach();
        }

        let client_for_run = self.client.clone();
        let (done_tx, done_rx) = futures::channel::oneshot::channel::<()>();
        let abort_handle = self.client.runtime.spawn(Box::pin(async move {
            client_for_run.run().await;
            let _ = done_tx.send(());
        }));

        Ok(BotHandle {
            done_rx,
            _abort_handle: abort_handle,
        })
    }
}

/// Builder for [`Bot`] using the typestate pattern.
///
/// The four type parameters (`B`, `T`, `H`, `R`) track whether the required
/// fields (backend, transport_factory, http_client, runtime) have been
/// provided. The `build()` method is only available when all four are
/// [`Provided`], turning missing-field errors into compile-time errors.
pub struct BotBuilder<B = Missing, T = Missing, H = Missing, R = Missing> {
    // Required fields (guaranteed present when B/T/H/R = Provided)
    backend: Option<Arc<dyn Backend>>,
    transport_factory: Option<Arc<dyn crate::transport::TransportFactory>>,
    http_client: Option<Arc<dyn crate::http::HttpClient>>,
    runtime: Option<Arc<dyn Runtime>>,
    // Optional fields
    event_handler: Option<EventHandlerCallback>,
    custom_enc_handlers: HashMap<String, Arc<dyn EncHandler>>,
    override_version: Option<(u32, u32, u32)>,
    os_info: Option<(
        Option<String>,
        Option<wa::device_props::AppVersion>,
        Option<wa::device_props::PlatformType>,
    )>,
    pair_code_options: Option<PairCodeOptions>,
    skip_history_sync: bool,
    initial_push_name: Option<String>,
    cache_config: CacheConfig,
    _marker: PhantomData<(B, T, H, R)>,
}

impl BotBuilder<Missing, Missing, Missing, Missing> {
    fn new() -> Self {
        Self {
            backend: None,
            transport_factory: None,
            http_client: None,
            runtime: None,
            event_handler: None,
            custom_enc_handlers: HashMap::new(),
            override_version: None,
            os_info: None,
            pair_code_options: None,
            skip_history_sync: false,
            initial_push_name: None,
            cache_config: CacheConfig::default(),
            _marker: PhantomData,
        }
    }
}

// ── Required-field setters (each transitions one type parameter) ──────────

impl<T, H, R> BotBuilder<Missing, T, H, R> {
    /// Use a backend implementation for storage.
    /// This is the only way to configure storage - there are no defaults.
    ///
    /// # Arguments
    /// * `backend` - The backend implementation that provides all storage operations
    ///
    /// # Example
    /// ```rust,ignore
    /// let backend = Arc::new(SqliteStore::new("whatsapp.db").await?);
    /// let bot = Bot::builder()
    ///     .with_backend(backend)
    ///     .build()
    ///     .await?;
    /// ```
    pub fn with_backend(self, backend: Arc<dyn Backend>) -> BotBuilder<Provided, T, H, R> {
        BotBuilder {
            backend: Some(backend),
            transport_factory: self.transport_factory,
            http_client: self.http_client,
            runtime: self.runtime,
            event_handler: self.event_handler,
            custom_enc_handlers: self.custom_enc_handlers,
            override_version: self.override_version,
            os_info: self.os_info,
            pair_code_options: self.pair_code_options,
            skip_history_sync: self.skip_history_sync,
            initial_push_name: self.initial_push_name,
            cache_config: self.cache_config,
            _marker: PhantomData,
        }
    }
}

impl<B, H, R> BotBuilder<B, Missing, H, R> {
    /// Set the transport factory for creating network connections.
    /// This is required to build a bot.
    ///
    /// # Arguments
    /// * `factory` - The transport factory implementation
    ///
    /// # Example
    /// ```rust,ignore
    /// use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
    ///
    /// let bot = Bot::builder()
    ///     .with_backend(backend)
    ///     .with_transport_factory(TokioWebSocketTransportFactory::new())
    ///     .build()
    ///     .await?;
    /// ```
    pub fn with_transport_factory<F>(self, factory: F) -> BotBuilder<B, Provided, H, R>
    where
        F: crate::transport::TransportFactory + 'static,
    {
        BotBuilder {
            backend: self.backend,
            transport_factory: Some(Arc::new(factory)),
            http_client: self.http_client,
            runtime: self.runtime,
            event_handler: self.event_handler,
            custom_enc_handlers: self.custom_enc_handlers,
            override_version: self.override_version,
            os_info: self.os_info,
            pair_code_options: self.pair_code_options,
            skip_history_sync: self.skip_history_sync,
            initial_push_name: self.initial_push_name,
            cache_config: self.cache_config,
            _marker: PhantomData,
        }
    }
}

impl<B, T, R> BotBuilder<B, T, Missing, R> {
    /// Configure the HTTP client used for media operations and version fetching.
    ///
    /// # Arguments
    /// * `client` - The HTTP client implementation
    ///
    /// # Example
    /// ```rust,ignore
    /// use whatsapp_rust_ureq_http_client::UreqHttpClient;
    ///
    /// let bot = Bot::builder()
    ///     .with_backend(backend)
    ///     .with_http_client(UreqHttpClient::new())
    ///     .build()
    ///     .await?;
    /// ```
    pub fn with_http_client<C>(self, client: C) -> BotBuilder<B, T, Provided, R>
    where
        C: crate::http::HttpClient + 'static,
    {
        BotBuilder {
            backend: self.backend,
            transport_factory: self.transport_factory,
            http_client: Some(Arc::new(client)),
            runtime: self.runtime,
            event_handler: self.event_handler,
            custom_enc_handlers: self.custom_enc_handlers,
            override_version: self.override_version,
            os_info: self.os_info,
            pair_code_options: self.pair_code_options,
            skip_history_sync: self.skip_history_sync,
            initial_push_name: self.initial_push_name,
            cache_config: self.cache_config,
            _marker: PhantomData,
        }
    }
}

impl<B, T, H> BotBuilder<B, T, H, Missing> {
    /// Set the async runtime implementation to use.
    ///
    /// This is required to build a bot.
    pub fn with_runtime<Rt: Runtime>(self, runtime: Rt) -> BotBuilder<B, T, H, Provided> {
        BotBuilder {
            backend: self.backend,
            transport_factory: self.transport_factory,
            http_client: self.http_client,
            runtime: Some(Arc::new(runtime)),
            event_handler: self.event_handler,
            custom_enc_handlers: self.custom_enc_handlers,
            override_version: self.override_version,
            os_info: self.os_info,
            pair_code_options: self.pair_code_options,
            skip_history_sync: self.skip_history_sync,
            initial_push_name: self.initial_push_name,
            cache_config: self.cache_config,
            _marker: PhantomData,
        }
    }
}

// ── Optional-field setters (available in any state) ──────────────────────

impl<B, T, H, R> BotBuilder<B, T, H, R> {
    pub fn on_event<F, Fut>(mut self, handler: F) -> Self
    where
        F: Fn(Event, Arc<Client>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.event_handler = Some(Arc::new(move |event, client| {
            Box::pin(handler(event, client))
        }));
        self
    }

    /// Register a custom handler for a specific encrypted message type
    ///
    /// # Arguments
    /// * `enc_type` - The encrypted message type (e.g., "frskmsg")
    /// * `handler` - The handler implementation for this type
    ///
    /// # Returns
    /// The updated BotBuilder
    pub fn with_enc_handler<Eh>(mut self, enc_type: impl Into<String>, handler: Eh) -> Self
    where
        Eh: EncHandler + 'static,
    {
        self.custom_enc_handlers
            .insert(enc_type.into(), Arc::new(handler));
        self
    }

    /// Override the WhatsApp version used by the client.
    ///
    /// By default, the client will automatically fetch the latest version from WhatsApp's servers.
    /// Use this method to force a specific version instead.
    ///
    /// # Arguments
    /// * `version` - A tuple of (primary, secondary, tertiary) version numbers
    ///
    /// # Example
    /// ```rust,ignore
    /// let bot = Bot::builder()
    ///     .with_backend(backend)
    ///     .with_version((2, 3000, 1027868167))
    ///     .build()
    ///     .await?;
    /// ```
    pub fn with_version(mut self, version: (u32, u32, u32)) -> Self {
        self.override_version = Some(version);
        self
    }

    /// Override the device properties sent to WhatsApp servers.
    /// This allows customizing how your device appears on the linked devices list.
    ///
    /// # Arguments
    /// * `os_name` - Optional OS name (e.g., "macOS", "Windows", "Linux")
    /// * `version` - Optional app version as AppVersion struct
    /// * `platform_type` - Optional platform type that determines the device name shown
    ///   on the phone's linked devices list (e.g., Chrome, Firefox, Safari, Desktop)
    ///
    /// **Important**: The `platform_type` determines what device name is shown on the phone.
    /// Common values: `Chrome`, `Firefox`, `Safari`, `Edge`, `Desktop`, `Ipad`, etc.
    /// If not set, defaults to `Unknown` which shows as "Unknown device".
    ///
    /// You can pass `None` for any parameter to keep the default value.
    ///
    /// # Example
    /// ```rust,ignore
    /// use waproto::whatsapp::device_props::{self, PlatformType};
    ///
    /// // Show as "Chrome" on linked devices
    /// let bot = Bot::builder()
    ///     .with_backend(backend)
    ///     .with_device_props(
    ///         Some("macOS".to_string()),
    ///         Some(device_props::AppVersion {
    ///             primary: Some(2),
    ///             secondary: Some(0),
    ///             tertiary: Some(0),
    ///             ..Default::default()
    ///         }),
    ///         Some(PlatformType::Chrome),
    ///     )
    ///     .build()
    ///     .await?;
    ///
    /// // Show as "Desktop" on linked devices
    /// let bot = Bot::builder()
    ///     .with_backend(backend)
    ///     .with_device_props(None, None, Some(PlatformType::Desktop))
    ///     .build()
    ///     .await?;
    /// ```
    pub fn with_device_props(
        mut self,
        os_name: Option<String>,
        version: Option<wa::device_props::AppVersion>,
        platform_type: Option<wa::device_props::PlatformType>,
    ) -> Self {
        self.os_info = Some((os_name, version, platform_type));
        self
    }

    /// Configure pair code authentication to run automatically after connecting.
    ///
    /// When set, the pair code request will be sent automatically after establishing
    /// a connection, and the pairing code will be dispatched via `Event::PairingCode`.
    /// This runs concurrently with QR code pairing - whichever completes first wins.
    ///
    /// # Arguments
    /// * `options` - Configuration for pair code authentication
    ///
    /// # Example
    /// ```rust,ignore
    /// use whatsapp_rust::pair_code::{PairCodeOptions, PlatformId};
    ///
    /// let bot = Bot::builder()
    ///     .with_backend(backend)
    ///     .with_transport_factory(transport)
    ///     .with_http_client(http_client)
    ///     .with_pair_code(PairCodeOptions {
    ///         phone_number: "15551234567".to_string(),
    ///         show_push_notification: true,
    ///         custom_code: Some("ABCD1234".to_string()),
    ///         platform_id: PlatformId::Chrome,
    ///         platform_display: "Chrome (Linux)".to_string(),
    ///     })
    ///     .on_event(|event, client| async move {
    ///         match event {
    ///             Event::PairingCode { code, timeout } => {
    ///                 println!("Enter this code on your phone: {}", code);
    ///             }
    ///             _ => {}
    ///         }
    ///     })
    ///     .build()
    ///     .await?;
    /// ```
    pub fn with_pair_code(mut self, options: PairCodeOptions) -> Self {
        self.pair_code_options = Some(options);
        self
    }

    /// Skip processing of history sync notifications from the phone.
    ///
    /// When enabled, the client will acknowledge all incoming history sync
    /// notifications (so the phone considers them delivered) but will not
    /// download or process any historical data (INITIAL_BOOTSTRAP, RECENT,
    /// FULL, PUSH_NAME, etc.). A debug log entry is emitted for each skipped
    /// notification. This is useful for bot use cases where message history
    /// is not needed.
    ///
    /// Default: `false` (history sync is processed normally).
    ///
    /// # Example
    /// ```rust,ignore
    /// let bot = Bot::builder()
    ///     .with_backend(backend)
    ///     .with_transport_factory(transport)
    ///     .with_http_client(http_client)
    ///     .skip_history_sync()
    ///     .build()
    ///     .await?;
    /// ```
    pub fn skip_history_sync(mut self) -> Self {
        self.skip_history_sync = true;
        self
    }

    /// Set an initial push name on the device before connecting.
    ///
    /// This is included in the `ClientPayload` during registration, allowing the
    /// mock server to deterministically assign phone numbers based on push name
    /// (same push name = same phone, enabling multi-device testing).
    pub fn with_push_name(mut self, name: impl Into<String>) -> Self {
        self.initial_push_name = Some(name.into());
        self
    }

    /// Configure cache TTL and capacity settings.
    ///
    /// By default, all caches match WhatsApp Web behavior. Use this method
    /// to customize cache durations for your use case.
    ///
    /// # Example
    /// ```rust,ignore
    /// use whatsapp_rust::{CacheConfig, CacheEntryConfig};
    ///
    /// // Disable TTL for group and device caches (good for bots with few groups)
    /// let bot = Bot::builder()
    ///     .with_backend(backend)
    ///     .with_transport_factory(transport)
    ///     .with_http_client(http_client)
    ///     .with_cache_config(CacheConfig {
    ///         group_cache: CacheEntryConfig::new(None, 1_000),
    ///         device_registry_cache: CacheEntryConfig::new(None, 5_000),
    ///         ..Default::default()
    ///     })
    ///     .build()
    ///     .await?;
    /// ```
    pub fn with_cache_config(mut self, config: CacheConfig) -> Self {
        self.cache_config = config;
        self
    }
}

// ── build() — only available when all 4 required fields are Provided ─────

impl BotBuilder<Provided, Provided, Provided, Provided> {
    pub async fn build(self) -> std::result::Result<Bot, BotBuilderError> {
        // Destructure to extract required fields — typestate guarantees all are Some.
        let (Some(runtime), Some(backend), Some(transport_factory), Some(http_client)) = (
            self.runtime,
            self.backend,
            self.transport_factory,
            self.http_client,
        ) else {
            unreachable!("typestate guarantees all required fields are Provided")
        };

        // Note: For multi-account mode, create the backend with SqliteStore::new_for_device()
        // before passing it to with_backend()
        let persistence_manager = Arc::new(
            PersistenceManager::new(backend)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to create persistence manager: {}", e))?,
        );

        persistence_manager
            .clone()
            .run_background_saver(runtime.clone(), std::time::Duration::from_secs(30));

        // Apply initial push name if specified (for deterministic mock server phone assignment)
        if let Some(name) = self.initial_push_name {
            persistence_manager
                .process_command(DeviceCommand::SetPushName(name))
                .await;
        }

        // Apply device props override if specified
        if let Some((os_name, version, platform_type)) = self.os_info {
            info!(
                "Applying device props override: os={:?}, version={:?}, platform_type={:?}",
                os_name, version, platform_type
            );
            persistence_manager
                .process_command(DeviceCommand::SetDeviceProps(
                    os_name,
                    version,
                    platform_type,
                ))
                .await;
        }

        info!("Creating client...");
        let (client, sync_task_receiver) = Client::new_with_cache_config(
            runtime,
            persistence_manager.clone(),
            transport_factory,
            http_client,
            self.override_version,
            self.cache_config,
        )
        .await;

        // Register custom enc handlers
        for (enc_type, handler) in self.custom_enc_handlers {
            client
                .custom_enc_handlers
                .write()
                .await
                .insert(enc_type, handler);
        }

        if self.skip_history_sync {
            client.set_skip_history_sync(true);
        }

        Ok(Bot {
            client,
            sync_task_receiver: Some(sync_task_receiver),
            event_handler: self.event_handler,
            pair_code_options: self.pair_code_options,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TokioRuntime;
    use crate::http::{HttpClient, HttpRequest, HttpResponse};
    use crate::store::SqliteStore;
    use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;

    // Mock HTTP client for testing
    #[derive(Debug, Clone)]
    struct MockHttpClient;

    #[async_trait::async_trait]
    impl HttpClient for MockHttpClient {
        async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse> {
            // Return a mock response for version fetching
            Ok(HttpResponse {
                status_code: 200,
                body: br#"self.__swData=JSON.parse(/*BTDS*/"{\"dynamic_data\":{\"SiteData\":{\"server_revision\":1026131876,\"client_revision\":1026131876}}}");"#.to_vec(),
            })
        }
    }

    async fn create_test_sqlite_backend() -> Arc<dyn Backend> {
        let temp_db = format!(
            "file:memdb_bot_{}?mode=memory&cache=shared",
            uuid::Uuid::new_v4()
        );
        Arc::new(
            SqliteStore::new(&temp_db)
                .await
                .expect("Failed to create test SqliteStore"),
        ) as Arc<dyn Backend>
    }

    async fn create_test_sqlite_backend_for_device(device_id: i32) -> Arc<dyn Backend> {
        let temp_db = format!(
            "file:memdb_bot_{}?mode=memory&cache=shared",
            uuid::Uuid::new_v4()
        );
        Arc::new(
            SqliteStore::new_for_device(&temp_db, device_id)
                .await
                .expect("Failed to create test SqliteStore"),
        ) as Arc<dyn Backend>
    }

    #[tokio::test]
    async fn test_bot_builder_single_device() {
        let backend = create_test_sqlite_backend().await;
        let transport = TokioWebSocketTransportFactory::new();
        let http_client = MockHttpClient;

        let bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport)
            .with_http_client(http_client)
            .with_runtime(TokioRuntime)
            .build()
            .await
            .expect("Failed to build bot");

        // Verify bot was created successfully
        let _client = bot.client();
    }

    #[tokio::test]
    async fn test_bot_builder_multi_device() {
        // Create a backend configured for device ID 42
        let backend = create_test_sqlite_backend_for_device(42).await;
        let transport = TokioWebSocketTransportFactory::new();

        let bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport)
            .with_http_client(MockHttpClient)
            .with_runtime(TokioRuntime)
            .build()
            .await
            .expect("Failed to build bot");

        // Verify bot was created successfully
        let _client = bot.client();
    }

    #[tokio::test]
    async fn test_bot_builder_with_custom_backend() {
        // Create an in-memory backend for testing
        let backend = create_test_sqlite_backend().await;
        let transport = TokioWebSocketTransportFactory::new();
        let http_client = MockHttpClient;
        let bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport)
            .with_http_client(http_client)
            .with_runtime(TokioRuntime)
            .build()
            .await
            .expect("Failed to build bot with custom backend");

        // Verify the bot was created successfully
        let _client = bot.client();
    }

    #[tokio::test]
    async fn test_bot_builder_with_custom_backend_specific_device() {
        // Create a backend configured for device ID 100
        let backend = create_test_sqlite_backend_for_device(100).await;
        let transport = TokioWebSocketTransportFactory::new();
        let http_client = MockHttpClient;

        // Build a bot with the custom backend
        let bot = Bot::builder()
            .with_backend(backend)
            .with_http_client(http_client)
            .with_transport_factory(transport)
            .with_runtime(TokioRuntime)
            .build()
            .await
            .expect("Failed to build bot with custom backend for specific device");

        // Verify the bot was created successfully
        let _client = bot.client();
    }

    // NOTE: test_bot_builder_missing_backend, test_bot_builder_missing_transport,
    // and test_bot_builder_missing_http_client have been removed because the
    // typestate pattern now makes those cases compile-time errors instead of
    // runtime errors.

    #[tokio::test]
    async fn test_bot_builder_with_version_override() {
        let backend = create_test_sqlite_backend().await;
        let transport = TokioWebSocketTransportFactory::new();
        let http_client = MockHttpClient;

        let bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport)
            .with_http_client(http_client)
            .with_version((2, 3000, 123456789))
            .with_runtime(TokioRuntime)
            .build()
            .await
            .expect("Failed to build bot with version override");

        // Verify the bot was created successfully
        let client = bot.client();

        // Check that the override version is stored in the client
        assert_eq!(client.override_version, Some((2, 3000, 123456789)));
    }

    #[tokio::test]
    async fn test_bot_builder_with_device_props_override() {
        let backend = create_test_sqlite_backend().await;
        let transport = TokioWebSocketTransportFactory::new();
        let http_client = MockHttpClient;

        let custom_os = "CustomOS".to_string();
        let custom_version = wa::device_props::AppVersion {
            primary: Some(99),
            secondary: Some(88),
            tertiary: Some(77),
            ..Default::default()
        };

        let bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport)
            .with_http_client(http_client)
            .with_device_props(Some(custom_os.clone()), Some(custom_version), None)
            .with_runtime(TokioRuntime)
            .build()
            .await
            .expect("Failed to build bot with device props override");

        let client = bot.client();
        let persistence_manager = client.persistence_manager();
        let device = persistence_manager.get_device_snapshot().await;

        // Verify the device props were overridden
        assert_eq!(device.device_props.os, Some(custom_os));
        assert_eq!(device.device_props.version, Some(custom_version));
    }

    #[tokio::test]
    async fn test_bot_builder_with_os_only_override() {
        let backend = create_test_sqlite_backend().await;
        let transport = TokioWebSocketTransportFactory::new();
        let http_client = MockHttpClient;

        let custom_os = "CustomOS".to_string();

        let bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport)
            .with_http_client(http_client)
            .with_device_props(Some(custom_os.clone()), None, None)
            .with_runtime(TokioRuntime)
            .build()
            .await
            .expect("Failed to build bot with OS only override");

        let client = bot.client();
        let persistence_manager = client.persistence_manager();
        let device = persistence_manager.get_device_snapshot().await;

        // Verify only OS was overridden, version should be default
        assert_eq!(device.device_props.os, Some(custom_os));
        // Version should be the default since we didn't override it
        assert_eq!(
            device.device_props.version,
            Some(wacore::store::Device::default_device_props_version())
        );
    }

    #[tokio::test]
    async fn test_bot_builder_with_version_only_override() {
        let backend = create_test_sqlite_backend().await;
        let transport = TokioWebSocketTransportFactory::new();
        let http_client = MockHttpClient;

        let custom_version = wa::device_props::AppVersion {
            primary: Some(99),
            secondary: Some(88),
            tertiary: Some(77),
            ..Default::default()
        };

        let bot = Bot::builder()
            .with_backend(backend)
            .with_http_client(http_client)
            .with_transport_factory(transport)
            .with_device_props(None, Some(custom_version), None)
            .with_runtime(TokioRuntime)
            .build()
            .await
            .expect("Failed to build bot with version only override");

        let client = bot.client();
        let persistence_manager = client.persistence_manager();
        let device = persistence_manager.get_device_snapshot().await;

        // Verify only version was overridden, OS should be default ("rust")
        assert_eq!(device.device_props.version, Some(custom_version));
        // OS should be the default since we didn't override it
        assert_eq!(
            device.device_props.os,
            Some(wacore::store::Device::default_os().to_string())
        );
    }

    #[tokio::test]
    async fn test_bot_builder_with_platform_type_override() {
        let backend = create_test_sqlite_backend().await;
        let transport = TokioWebSocketTransportFactory::new();
        let http_client = MockHttpClient;

        let bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport)
            .with_http_client(http_client)
            .with_device_props(None, None, Some(wa::device_props::PlatformType::Chrome))
            .with_runtime(TokioRuntime)
            .build()
            .await
            .expect("Failed to build bot with platform type override");

        let client = bot.client();
        let persistence_manager = client.persistence_manager();
        let device = persistence_manager.get_device_snapshot().await;

        // Verify platform type was set to Chrome
        assert_eq!(
            device.device_props.platform_type,
            Some(wa::device_props::PlatformType::Chrome as i32)
        );
        // OS and version should remain default
        assert_eq!(
            device.device_props.os,
            Some(wacore::store::Device::default_os().to_string())
        );
        assert_eq!(
            device.device_props.version,
            Some(wacore::store::Device::default_device_props_version())
        );
    }

    #[tokio::test]
    async fn test_bot_builder_with_full_device_props_override() {
        let backend = create_test_sqlite_backend().await;
        let transport = TokioWebSocketTransportFactory::new();
        let http_client = MockHttpClient;

        let custom_os = "macOS".to_string();
        let custom_version = wa::device_props::AppVersion {
            primary: Some(2),
            secondary: Some(0),
            tertiary: Some(0),
            ..Default::default()
        };
        let custom_platform = wa::device_props::PlatformType::Safari;

        let bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport)
            .with_http_client(http_client)
            .with_device_props(
                Some(custom_os.clone()),
                Some(custom_version),
                Some(custom_platform),
            )
            .with_runtime(TokioRuntime)
            .build()
            .await
            .expect("Failed to build bot with full device props override");

        let client = bot.client();
        let persistence_manager = client.persistence_manager();
        let device = persistence_manager.get_device_snapshot().await;

        // Verify all device props were overridden
        assert_eq!(device.device_props.os, Some(custom_os));
        assert_eq!(device.device_props.version, Some(custom_version));
        assert_eq!(
            device.device_props.platform_type,
            Some(custom_platform as i32)
        );
    }

    #[tokio::test]
    async fn test_bot_builder_skip_history_sync() {
        let backend = create_test_sqlite_backend().await;
        let transport = TokioWebSocketTransportFactory::new();
        let http_client = MockHttpClient;

        let bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport)
            .with_http_client(http_client)
            .skip_history_sync()
            .with_runtime(TokioRuntime)
            .build()
            .await
            .expect("Failed to build bot with skip_history_sync");

        assert!(bot.client().skip_history_sync_enabled());
    }

    #[tokio::test]
    async fn test_bot_builder_default_history_sync_enabled() {
        let backend = create_test_sqlite_backend().await;
        let transport = TokioWebSocketTransportFactory::new();
        let http_client = MockHttpClient;

        let bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport)
            .with_http_client(http_client)
            .with_runtime(TokioRuntime)
            .build()
            .await
            .expect("Failed to build bot");

        assert!(!bot.client().skip_history_sync_enabled());
    }
}
