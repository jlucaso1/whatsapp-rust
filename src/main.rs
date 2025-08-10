use chrono::Local;
use log::{error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::task;
use wacore::types::events::{Event, EventHandler};
use whatsapp_rust::client::Client;
use whatsapp_rust::proto_helpers::MessageExt;
use whatsapp_rust::store::commands::DeviceCommand;
use whatsapp_rust::store::persistence_manager::PersistenceManager;

struct MainEventHandler {
    persistence_manager: Arc<PersistenceManager>,
    client: Arc<Client>,
}

impl EventHandler for MainEventHandler {
    fn handle_event(&self, event: &Event) {
        match event {
            Event::Message(msg, info) => {
                if let Some(text) = msg.text_content() {
                    log::info!("Received message: {}", text);
                    if text == "send" {
                        log::info!("Received 'send' command, sending a response.");
                        let response_text = "Hello from whatsapp-rust!";
                        let client_clone = self.client.clone();
                        let chat_jid = info.source.chat.clone();
                        tokio::task::spawn_local(async move {
                            if let Err(e) = client_clone
                                .send_text_message(chat_jid, response_text)
                                .await
                            {
                                log::error!("Failed to send response message: {:?}", e);
                            }
                        });
                    }
                }
            }
            Event::LoggedOut(logout_event) => {
                info!("Received logout event: {:?}", logout_event.reason);
            }
            Event::SelfPushNameUpdated(update) => {
                info!(
                    "Received SelfPushNameUpdated event from '{}' to '{}'.",
                    update.old_name, update.new_name
                );
                let pm_clone = self.persistence_manager.clone();
                let name_clone = update.new_name.clone();
                tokio::task::spawn_local(async move {
                    pm_clone
                        .process_command(DeviceCommand::SetPushName(name_clone))
                        .await;
                });
            }
            _ => {
                // You can add more arms here or just ignore other events
            }
        }
    }
}

fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            use std::io::Write;
            writeln!(
                buf,
                "{} [{:<5}] [{}] - {}",
                Local::now().format("%H:%M:%S"),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .init();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let local = task::LocalSet::new();

    local.block_on(&rt, async {
        info!("Initializing PersistenceManager...");
        let persistence_manager = Arc::new(
            PersistenceManager::new("./whatsapp_store")
                .await
                .expect("Failed to initialize PersistenceManager"),
        );

        Arc::clone(&persistence_manager).run_background_saver(Duration::from_secs(60));

        info!("Creating client...");
        let client = Arc::new(Client::new(persistence_manager.clone()).await);

        let handler = Arc::new(MainEventHandler {
            persistence_manager: persistence_manager.clone(),
            client: client.clone(),
        });
        client.core.event_bus.add_handler(handler);

        let device_snapshot = persistence_manager.get_device_snapshot().await;
        if device_snapshot.id.is_none() {
            let client_clone = client.clone();
            task::spawn_local(async move {
                let mut qr_rx = client_clone.get_qr_channel().await.unwrap();
                info!("QR Channel listener started. Waiting for events...");
                while let Some(event) = qr_rx.recv().await {
                    use whatsapp_rust::qrcode::QrCodeEvent;
                    match event {
                        QrCodeEvent::Code { code, .. } => {
                            info!("----------------------------------------");
                            info!("Got new QR Code. Scan with your WhatsApp app.");
                            let qr_url = format!(
                                "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data={code}",
                                code = urlencoding::encode(&code)
                            );
                            info!("Scan this URL in a browser to see the QR code:\n  {qr_url}");
                            info!("----------------------------------------");
                        }
                        QrCodeEvent::Success => {
                            info!("✅ Pairing successful! The client will now connect.");
                            break;
                        }
                        QrCodeEvent::Error(e) => {
                            error!("❌ Pairing failed: {e:?}");
                            break;
                        }
                        QrCodeEvent::Timeout => {
                            warn!("⌛ Pairing timed out. Please restart the application.");
                            break;
                        }
                        _ => {
                            info!("[QR Event] Received other state: {event:?}");
                        }
                    }
                }
                info!("QR Channel listener finished.");
            });
        }

        client.run().await;
    });

    info!("Application has shut down.");
    Ok(())
}
