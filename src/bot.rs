use crate::client::Client;
use crate::qrcode::QrCodeEvent;
use crate::store::persistence_manager::PersistenceManager;
use crate::types::events::{Event, EventHandler};
use crate::types::message::MessageInfo;
use log::{error, info, warn};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use waproto::whatsapp as wa;

pub struct MessageContext {
    pub message: Box<wa::Message>,
    pub info: MessageInfo,
    client: Arc<Client>,
}

impl MessageContext {
    pub async fn reply(&self, text: &str) -> Result<(), anyhow::Error> {
        self.client
            .send_text_message(self.info.source.chat.clone(), text)
            .await
    }
}

type MessageHandler =
    Arc<dyn Fn(MessageContext) -> Pin<Box<dyn Future<Output = ()>>> + Send + Sync>;

pub struct Bot;

impl Bot {
    pub fn builder() -> BotBuilder {
        BotBuilder::new()
    }
}

pub struct BotBuilder {
    message_handler: Option<MessageHandler>,
    db_path: String,
}

impl BotBuilder {
    fn new() -> Self {
        Self {
            message_handler: None,
            db_path: "whatsapp.db".to_string(),
        }
    }

    pub fn on_message<F, Fut>(mut self, handler: F) -> Self
    where
        F: Fn(MessageContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        self.message_handler = Some(Arc::new(move |ctx| Box::pin(handler(ctx))));
        self
    }

    pub fn with_db_path(mut self, db_path: &str) -> Self {
        self.db_path = db_path.to_string();
        self
    }

    pub async fn run(self) {
        info!(
            "Initializing PersistenceManager with SQLite at '{}'...",
            self.db_path
        );
        let persistence_manager = Arc::new(
            PersistenceManager::new(&self.db_path)
                .await
                .expect("Failed to initialize PersistenceManager with SQLite"),
        );

        persistence_manager
            .clone()
            .run_background_saver(std::time::Duration::from_secs(30));

        info!("Creating client...");
        let (client, mut sync_task_receiver) = Client::new(persistence_manager.clone()).await;

        // SPAWN THE DEDICATED SYNC WORKER
        let worker_client = client.clone();
        tokio::task::spawn_local(async move {
            while let Some(task) = sync_task_receiver.recv().await {

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

        let handler = Arc::new(BotEventHandler {
            client: client.clone(),
            message_handler: self.message_handler,
        });
        client.core.event_bus.add_handler(handler);

        let device_snapshot = persistence_manager.get_device_snapshot().await;
        if device_snapshot.id.is_none() {
            info!("Client is not logged in. Starting QR code pairing process...");

            let client_clone = client.clone();
            let client_handle = tokio::task::spawn_local(async move {
                client_clone.run().await;
            });

            match client.get_qr_channel().await {
                Ok(mut qr_rx) => {
                    while let Some(event) = qr_rx.recv().await {
                        match event {
                            QrCodeEvent::Code { code, .. } => {
                                let qr_url = format!(
                                    "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data={}",
                                    urlencoding::encode(&code)
                                );
                                info!("----------------------------------------");
                                info!(
                                    "Scan this URL in a browser to see the QR code:\n  {}",
                                    qr_url
                                );
                                info!("----------------------------------------");
                            }
                            QrCodeEvent::Success => {
                                info!(
                                    "✅ Pairing successful! The client will now continue running."
                                );
                                break;
                            }
                            QrCodeEvent::Error(e) => {
                                error!("❌ Pairing failed: {:?}", e);
                                client.disconnect().await;
                                break;
                            }
                            QrCodeEvent::Timeout => {
                                warn!("⌛ Pairing timed out. Please restart the application.");
                                client.disconnect().await;
                                break;
                            }
                            _ => {}
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to get QR channel: {}", e);
                    client.disconnect().await;
                }
            }
            if let Err(e) = client_handle.await {
                error!("Client task panicked or was cancelled: {}", e);
            }
        } else {
            info!("Client is already logged in. Starting main event loop.");
            client.run().await;
        }

        info!("Bot has shut down.");
    }
}

struct BotEventHandler {
    client: Arc<Client>,
    message_handler: Option<MessageHandler>,
}

impl EventHandler for BotEventHandler {
    fn handle_event(&self, event: &Event) {
        if let Event::Message(msg, info) = event
            && let Some(handler) = &self.message_handler
        {
            let handler_clone = handler.clone();
            let client_clone = self.client.clone();
            let msg_clone = msg.clone();
            let info_clone = info.clone();

            let context = MessageContext {
                message: msg_clone,
                info: info_clone,
                client: client_clone,
            };

            tokio::task::spawn_local(async move {
                handler_clone(context).await;
            });
        }
    }
}
