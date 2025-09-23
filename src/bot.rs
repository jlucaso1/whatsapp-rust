use crate::client::Client;
use crate::config::ClientConfig;
use crate::store::persistence_manager::{DevicePersistence, PersistenceManager};
use crate::store::store_manager::StoreManager;
use crate::store::traits::Backend;
use crate::types::enc_handler::EncHandler;
use crate::types::events::{Event, EventHandler};
use crate::types::message::MessageInfo;
use anyhow::Result;
use http::Uri;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task;
use waproto::whatsapp as wa;

pub struct MessageContext {
    pub message: Box<wa::Message>,
    pub info: MessageInfo,
    pub client: Arc<Client>,
}

impl MessageContext {
    pub async fn send_message(&self, message: wa::Message) -> Result<String, anyhow::Error> {
        self.client
            .send_message(self.info.source.chat.clone(), message)
            .await
    }

    pub async fn edit_message(
        &self,
        original_message_id: String,
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

            tokio::spawn(async move {
                handler_clone(event_clone, client_clone).await;
            });
        }
    }
}

pub struct Bot {
    client: Arc<Client>,
    sync_task_receiver: Option<mpsc::Receiver<crate::sync_task::MajorSyncTask>>,
    event_handler: Option<EventHandlerCallback>,
}

impl Bot {
    pub fn builder() -> BotBuilder {
        BotBuilder::new()
    }

    pub fn client(&self) -> Arc<Client> {
        self.client.clone()
    }

    pub async fn run(&mut self) -> Result<task::JoinHandle<()>> {
        if let Some(mut receiver) = self.sync_task_receiver.take() {
            let worker_client = self.client.clone();
            tokio::spawn(async move {
                while let Some(task) = receiver.recv().await {
                    match task {
                        crate::sync_task::MajorSyncTask::HistorySync {
                            message_id,
                            notification,
                        } => {
                            worker_client
                                .process_history_sync_task(message_id, *notification)
                                .await;
                        }
                        crate::sync_task::MajorSyncTask::AppStateSync { name, full_sync } => {
                            if let Err(e) = worker_client
                                .process_app_state_sync_task(name, full_sync)
                                .await
                            {
                                warn!("App state sync task for {:?} failed: {}", name, e);
                            }
                        }
                    }
                }
                info!("Sync worker shutting down.");
            });
        }

        let handler = Arc::new(BotEventHandler {
            client: self.client.clone(),
            event_handler: self.event_handler.take(),
        });
        self.client.core.event_bus.add_handler(handler);

        let client_for_run = self.client.clone();
        let client_handle = tokio::spawn(async move {
            client_for_run.run().await;
        });

        Ok(client_handle)
    }
}

#[derive(Default)]
pub struct BotBuilder {
    event_handler: Option<EventHandlerCallback>,
    db_path: Option<String>,
    override_app_version: Option<(u32, u32, u32)>,
    custom_enc_handlers: HashMap<String, Arc<dyn EncHandler>>,
    store_manager: Option<Arc<StoreManager>>,
    device_id: Option<i32>,
    // New field for direct backend support
    backend: Option<Arc<dyn Backend>>,
    device_persistence: Option<Arc<dyn DevicePersistence>>,
}

impl BotBuilder {
    fn new() -> Self {
        Self::default()
    }

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

    pub fn with_config(mut self, config: ClientConfig) -> Self {
        let db_path = if config.db_path.is_empty() {
            "whatsapp.db".to_string()
        } else {
            config.db_path
        };
        self.db_path = Some(db_path);
        self.override_app_version = config.app_version_override;
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
    pub fn with_enc_handler<H>(mut self, enc_type: impl Into<String>, handler: H) -> Self
    where
        H: EncHandler + 'static,
    {
        self.custom_enc_handlers
            .insert(enc_type.into(), Arc::new(handler));
        self
    }

    /// Use a specific StoreManager for multi-account support.
    /// This overrides any database path configuration.
    pub fn with_store_manager(mut self, store_manager: Arc<StoreManager>) -> Self {
        self.store_manager = Some(store_manager);
        self
    }

    /// Specify which device ID to use for multi-account scenarios.
    /// This requires a StoreManager to be set via `with_store_manager()` or a backend via `with_backend()`.
    /// If not specified, a new device will be created.
    pub fn for_device(mut self, device_id: i32) -> Self {
        self.device_id = Some(device_id);
        self
    }

    /// Use a custom backend implementation for storage.
    /// This allows using alternative storage backends (e.g., PostgreSQL, Redis) instead of SQLite.
    ///
    /// # Arguments
    /// * `backend` - The backend implementation that provides all storage operations
    /// * `device_persistence` - The device persistence implementation for loading/saving device data
    ///
    /// # Example
    /// ```rust,ignore
    /// let backend = Arc::new(MyCustomBackend::new());
    /// let device_persistence = Arc::new(MyCustomDevicePersistence::new());
    /// let bot = Bot::builder()
    ///     .with_backend(backend, device_persistence)
    ///     .build()
    ///     .await?;
    /// ```
    pub fn with_backend(
        mut self,
        backend: Arc<dyn Backend>,
        device_persistence: Arc<dyn DevicePersistence>,
    ) -> Self {
        self.backend = Some(backend);
        self.device_persistence = Some(device_persistence);
        self
    }

    pub async fn build(self) -> Result<Bot> {
        let persistence_manager = if let Some(backend) = self.backend {
            // Custom backend mode
            let device_persistence = self.device_persistence.ok_or_else(|| {
                anyhow::anyhow!("Device persistence is required when using custom backend")
            })?;

            if let Some(device_id) = self.device_id {
                info!(
                    "Creating PersistenceManager with custom backend for device ID: {}",
                    device_id
                );
                Arc::new(
                    PersistenceManager::new_for_device_with_backend(
                        device_id,
                        backend,
                        device_persistence,
                    )
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to create persistence manager for device {}: {}",
                            device_id,
                            e
                        )
                    })?,
                )
            } else {
                info!("Creating PersistenceManager with custom backend");
                Arc::new(
                    PersistenceManager::new_with_backend(backend, device_persistence)
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!("Failed to create persistence manager: {}", e)
                        })?,
                )
            }
        } else if let Some(store_manager) = self.store_manager {
            // Multi-account mode using StoreManager
            let manager = if let Some(device_id) = self.device_id {
                info!("Loading existing device with ID: {}", device_id);
                store_manager
                    .get_persistence_manager(device_id)
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to get persistence manager for device {}: {}",
                            device_id,
                            e
                        )
                    })?
            } else {
                info!("Creating new device");
                store_manager
                    .create_new_device()
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to create new device: {}", e))?
            };

            info!("Using device ID: {}", manager.device_id());
            manager
        } else {
            // Backward compatibility mode using direct database path
            let db_path = self.db_path.unwrap_or_else(|| "whatsapp.db".to_string());
            info!(
                "Initializing PersistenceManager with SQLite at '{}'...",
                &db_path
            );

            Arc::new(
                PersistenceManager::new(&db_path)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to init persistence manager: {}", e))?,
            )
        };

        persistence_manager
            .clone()
            .run_background_saver(std::time::Duration::from_secs(30));

        spawn_preconnect_task().await;

        crate::version::resolve_and_update_version(&persistence_manager, self.override_app_version)
            .await;

        info!("Creating client...");
        let (client, sync_task_receiver) = Client::new(persistence_manager.clone()).await;

        // Register custom enc handlers
        for (enc_type, handler) in self.custom_enc_handlers {
            client.custom_enc_handlers.insert(enc_type, handler);
        }

        Ok(Bot {
            client,
            sync_task_receiver: Some(sync_task_receiver),
            event_handler: self.event_handler,
        })
    }
}

async fn spawn_preconnect_task() {
    if let Ok(uri) = crate::socket::consts::URL.parse::<Uri>() {
        if let Some(host) = uri.host() {
            let port = uri.port_u16().unwrap_or(443);
            let address = format!("{}:{}", host, port);

            debug!(target: "Client/Preconnect", "Starting pre-connect to {}", address);
            if let Err(e) = TcpStream::connect(&address).await {
                warn!(target: "Client/Preconnect", "Pre-connection to {} failed: {}", address, e);
            } else {
                debug!(target: "Client/Preconnect", "Pre-connection to {} successful.", address);
            }
        }
    } else {
        warn!(target: "Client/Preconnect", "Could not parse WA_URL for pre-connect task.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::store_manager::StoreManager;

    async fn create_test_store_manager() -> Arc<StoreManager> {
        let temp_db = format!(
            "file:memdb_bot_{}?mode=memory&cache=shared",
            uuid::Uuid::new_v4()
        );
        Arc::new(
            StoreManager::new(&temp_db)
                .await
                .expect("Failed to create test StoreManager"),
        )
    }

    #[tokio::test]
    async fn test_bot_builder_backward_compatibility() {
        // Test that the original API still works
        let temp_db = format!("/tmp/test_bot_{}.db", uuid::Uuid::new_v4());

        let config = ClientConfig {
            db_path: temp_db,
            app_version_override: None,
        };

        // This should work without using StoreManager
        let _bot = Bot::builder()
            .with_config(config)
            .build()
            .await
            .expect("Failed to build bot with backward compatibility");
    }

    #[tokio::test]
    async fn test_bot_builder_with_store_manager_new_device() {
        let store_manager = create_test_store_manager().await;

        // Create a bot with a new device using StoreManager
        let bot = Bot::builder()
            .with_store_manager(store_manager.clone())
            .build()
            .await
            .expect("Failed to build bot with new device");

        // Verify we can get the device ID
        let client = bot.client();
        let persistence_manager = client.persistence_manager();
        let device_id = persistence_manager.device_id();

        // Should be a valid device ID (auto-assigned)
        assert!(device_id > 0);

        // Verify the device exists in the store manager
        assert!(
            store_manager
                .device_exists(device_id)
                .await
                .expect("Failed to check device existence")
        );
    }

    #[tokio::test]
    async fn test_bot_builder_with_store_manager_specific_device() {
        let store_manager = create_test_store_manager().await;

        // First create a device to get an ID
        let device_manager = store_manager
            .create_new_device()
            .await
            .expect("Failed to create device");
        let device_id = device_manager.device_id();

        // Now create a bot for that specific device
        let bot = Bot::builder()
            .with_store_manager(store_manager.clone())
            .for_device(device_id)
            .build()
            .await
            .expect("Failed to build bot for specific device");

        // Verify it's using the correct device
        let client = bot.client();
        let persistence_manager = client.persistence_manager();
        assert_eq!(persistence_manager.device_id(), device_id);
    }

    #[tokio::test]
    async fn test_bot_builder_device_not_found() {
        let store_manager = create_test_store_manager().await;

        // Try to create a bot for a non-existent device
        let result = Bot::builder()
            .with_store_manager(store_manager)
            .for_device(999) // Non-existent device ID
            .build()
            .await;

        // Should fail
        assert!(result.is_err());
        if let Err(error) = result {
            let error_msg = error.to_string();
            assert!(error_msg.contains("999"));
        }
    }

    #[tokio::test]
    async fn test_multiple_bots_same_store_manager() {
        let store_manager = create_test_store_manager().await;

        // Create two bots with the same store manager (different devices)
        let bot1 = Bot::builder()
            .with_store_manager(store_manager.clone())
            .build()
            .await
            .expect("Failed to build bot 1");

        let bot2 = Bot::builder()
            .with_store_manager(store_manager.clone())
            .build()
            .await
            .expect("Failed to build bot 2");

        // They should have different device IDs
        let device_id1 = bot1.client().persistence_manager().device_id();
        let device_id2 = bot2.client().persistence_manager().device_id();

        assert_ne!(device_id1, device_id2);

        // Both devices should exist in the store manager
        assert!(
            store_manager
                .device_exists(device_id1)
                .await
                .expect("Failed to check device 1")
        );
        assert!(
            store_manager
                .device_exists(device_id2)
                .await
                .expect("Failed to check device 2")
        );

        // Should have 2 devices total
        let devices = store_manager
            .list_devices()
            .await
            .expect("Failed to list devices");
        assert_eq!(devices.len(), 2);
    }

    #[tokio::test]
    async fn test_bot_builder_with_custom_backend() {
        // Create an in-memory backend for testing
        let backend = Arc::new(crate::store::in_memory_backend::InMemoryBackend::new());
        let device_persistence = backend.clone() as Arc<dyn DevicePersistence>;

        // Build a bot with the custom backend
        let bot = Bot::builder()
            .with_backend(backend.clone(), device_persistence)
            .build()
            .await
            .expect("Failed to build bot with custom backend");

        // Verify the bot was created successfully
        let client = bot.client();
        let persistence_manager = client.persistence_manager();

        // Should have device ID 1 for backward compatibility mode
        assert_eq!(persistence_manager.device_id(), 1);

        // Verify it's not using SQLite
        assert!(persistence_manager.sqlite_store().is_none());
    }

    #[tokio::test]
    async fn test_bot_builder_with_custom_backend_specific_device() {
        // Create an in-memory backend for testing
        let backend = Arc::new(crate::store::in_memory_backend::InMemoryBackend::new());
        let device_persistence = backend.clone() as Arc<dyn DevicePersistence>;

        // First, we need to create some device data for device ID 100
        let mut device = wacore::store::Device::new();
        device.push_name = "Test Device".to_string();
        device_persistence
            .save_device_data_for_device(100, &device)
            .await
            .expect("Failed to save device data");

        // Build a bot with the custom backend for a specific device
        let bot = Bot::builder()
            .with_backend(backend.clone(), device_persistence)
            .for_device(100)
            .build()
            .await
            .expect("Failed to build bot with custom backend for specific device");

        // Verify the bot was created successfully with the correct device ID
        let client = bot.client();
        let persistence_manager = client.persistence_manager();

        assert_eq!(persistence_manager.device_id(), 100);

        // Verify it's not using SQLite
        assert!(persistence_manager.sqlite_store().is_none());
    }
}
