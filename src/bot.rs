use crate::client::Client;
use crate::config::ClientConfig;
use crate::store::persistence_manager::PersistenceManager;
use crate::types::events::{Event, EventHandler};
use crate::types::message::MessageInfo;
use anyhow::Result;
use http::Uri;
use log::{debug, info, warn};
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
    pub async fn send_message(&self, message: wa::Message) -> Result<(), anyhow::Error> {
        let message_id = self.client.generate_message_id().await;
        self.client
            .send_message_impl(
                self.info.source.chat.clone(),
                Arc::new(message),
                message_id,
                false,
                false,
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

    pub async fn build(self) -> Result<Bot> {
        let db_path = self.db_path.unwrap_or_else(|| "whatsapp.db".to_string());
        info!(
            "Initializing PersistenceManager with SQLite at '{}'...",
            &db_path
        );
        let persistence_manager = Arc::new(
            PersistenceManager::new(&db_path)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to init persistence manager: {}", e))?,
        );

        persistence_manager
            .clone()
            .run_background_saver(std::time::Duration::from_secs(30));

        spawn_preconnect_task().await;

        crate::version::resolve_and_update_version(&persistence_manager, self.override_app_version)
            .await;

        info!("Creating client...");
        let (client, sync_task_receiver) = Client::new(persistence_manager.clone()).await;

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
