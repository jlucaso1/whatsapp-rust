use crate::client::Client;
use crate::store::persistence_manager::PersistenceManager;
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
    custom_enc_handlers: HashMap<String, Arc<dyn EncHandler>>,
    device_id: Option<i32>,
    // The only way to configure storage
    backend: Option<Arc<dyn Backend>>,
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

    /// Specify which device ID to use for multi-account scenarios.
    /// If not specified, single device mode will be used.
    pub fn for_device(mut self, device_id: i32) -> Self {
        self.device_id = Some(device_id);
        self
    }

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
    pub fn with_backend(mut self, backend: Arc<dyn Backend>) -> Self {
        self.backend = Some(backend);
        self
    }

    pub async fn build(self) -> Result<Bot> {
        let backend = self.backend.ok_or_else(|| {
            anyhow::anyhow!("Backend is required. Use with_backend() to set a storage implementation.")
        })?;

        let persistence_manager = if let Some(device_id) = self.device_id {
            info!("Creating PersistenceManager for device ID: {}", device_id);
            Arc::new(
                PersistenceManager::new_for_device(device_id, backend)
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
            info!("Creating PersistenceManager for single device mode");
            Arc::new(
                PersistenceManager::new(backend)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to create persistence manager: {}", e))?,
            )
        };

        persistence_manager
            .clone()
            .run_background_saver(std::time::Duration::from_secs(30));

        spawn_preconnect_task().await;

        crate::version::resolve_and_update_version(&persistence_manager, None).await;

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
    use crate::store::sqlite_store::SqliteStore;

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

    #[tokio::test]
    async fn test_bot_builder_single_device() {
        let backend = create_test_sqlite_backend().await;

        let bot = Bot::builder()
            .with_backend(backend)
            .build()
            .await
            .expect("Failed to build bot");

        let client = bot.client();
        let persistence_manager = client.persistence_manager();
        
        // Should have device ID 1 for single device mode
        assert_eq!(persistence_manager.device_id(), 1);
        assert!(!persistence_manager.is_multi_account());
    }

    #[tokio::test]
    async fn test_bot_builder_multi_device() {
        let backend = create_test_sqlite_backend().await;

        // First, we need to create device data for device ID 42
        let mut device = wacore::store::Device::new();
        device.push_name = "Test Device".to_string();
        backend.save_device_data_for_device(42, &device).await
            .expect("Failed to save device data");

        let bot = Bot::builder()
            .with_backend(backend)
            .for_device(42)
            .build()
            .await
            .expect("Failed to build bot");

        let client = bot.client();
        let persistence_manager = client.persistence_manager();
        
        // Should have device ID 42
        assert_eq!(persistence_manager.device_id(), 42);
        assert!(persistence_manager.is_multi_account());
    }

    #[tokio::test]
    async fn test_bot_builder_with_custom_backend() {
        // Create an in-memory backend for testing
        let backend = Arc::new(crate::store::in_memory_backend::InMemoryBackend::new()) as Arc<dyn Backend>;

        // Build a bot with the custom backend
        let bot = Bot::builder()
            .with_backend(backend)
            .build()
            .await
            .expect("Failed to build bot with custom backend");

        // Verify the bot was created successfully
        let client = bot.client();
        let persistence_manager = client.persistence_manager();
        
        // Should have device ID 1 for single device mode
        assert_eq!(persistence_manager.device_id(), 1);
    }

    #[tokio::test]
    async fn test_bot_builder_with_custom_backend_specific_device() {
        // Create an in-memory backend for testing
        let backend = Arc::new(crate::store::in_memory_backend::InMemoryBackend::new()) as Arc<dyn Backend>;

        // First, we need to create some device data for device ID 100
        let mut device = wacore::store::Device::new();
        device.push_name = "Test Device".to_string();
        backend.save_device_data_for_device(100, &device).await
            .expect("Failed to save device data");

        // Build a bot with the custom backend for a specific device
        let bot = Bot::builder()
            .with_backend(backend)
            .for_device(100)
            .build()
            .await
            .expect("Failed to build bot with custom backend for specific device");

        // Verify the bot was created successfully with the correct device ID
        let client = bot.client();
        let persistence_manager = client.persistence_manager();
        
        assert_eq!(persistence_manager.device_id(), 100);
    }

    #[tokio::test]
    async fn test_bot_builder_missing_backend() {
        // Try to build without setting a backend
        let result = Bot::builder()
            .build()
            .await;

        // This should fail
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Backend is required"));
    }
}