use chrono::Local;
use log::{error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::task;
use whatsapp_rust::client::Client;
use whatsapp_rust::proto_helpers::MessageExt;
use whatsapp_rust::store::commands::DeviceCommand;
use whatsapp_rust::store::persistence_manager::PersistenceManager;

fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            use std::io::Write;
            writeln!(
                buf,
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S"),
                record.level(),
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

        let client_for_handler = client.clone();
        let pm_for_handler = persistence_manager.clone();

        {
            let mut logged_out_rx = client.subscribe_to_logged_out();
            let _pm_clone = pm_for_handler.clone();
            task::spawn_local(async move {
                while let Ok(logout_event) = logged_out_rx.recv().await {
                    info!("Received logout event: {:?}", logout_event.reason);
                }
            });
        }

        {
            let mut self_push_name_rx = client.subscribe_to_self_push_name_updated();
            let pm_clone = pm_for_handler.clone();
            task::spawn_local(async move {
                while let Ok(update) = self_push_name_rx.recv().await {
                    info!(
                        "Received SelfPushNameUpdated event from '{}' to '{}'.",
                        update.old_name, update.new_name
                    );
                    pm_clone
                        .process_command(DeviceCommand::SetPushName(update.new_name.clone()))
                        .await;
                }
            });
        }

        {
            let mut message_rx = client.subscribe_to_messages();
            let client_clone = client_for_handler.clone();
            task::spawn_local(async move {
                while let Ok(message_data) = message_rx.recv().await {
                    let (msg, info_node) = &*message_data;
                    if let Some(text) = msg.text_content() {
                        log::info!("Received message: {}", text);
                        if text == "send" {
                            log::info!("Received 'send' command, sending a response.");
                            let response_text = "Hello from whatsapp-rust!";
                            if let Err(e) = client_clone
                                .send_text_message(info_node.source.chat.clone(), response_text)
                                .await
                            {
                                log::error!("Failed to send response message: {e:?}");
                            }
                        }
                    } else if let Some(ext_text) = msg.extended_text_message.as_ref()
                        && let Some(text) = ext_text.text.as_ref()
                        && text == "send"
                    {
                        log::info!("Received 'send' command, sending a response.");
                        let response_text = "Hello from whatsapp-rust!";
                        if let Err(e) = client_clone
                            .send_text_message(info_node.source.chat.clone(), response_text)
                            .await
                        {
                            log::error!("Failed to send response message: {e:?}");
                        }
                    }
                }
            });
        }

        client.run().await;
    });

    info!("Application has shut down.");
    Ok(())
}
