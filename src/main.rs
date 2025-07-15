use log::{error, info, warn};
use std::env;
use std::sync::Arc;
use std::time::Duration;
use whatsapp_rust::client::Client;
use whatsapp_rust::proto_helpers::MessageExt;
// use whatsapp_rust::store; // store::Device is now accessed via PersistenceManager
// use whatsapp_rust::store::filestore::FileStore; // FileStore is encapsulated in PersistenceManager
use whatsapp_rust::store::commands::DeviceCommand;
use whatsapp_rust::store::persistence_manager::PersistenceManager;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("Initializing PersistenceManager...");
    let persistence_manager = Arc::new(
        PersistenceManager::new("./whatsapp_store")
            .await
            .expect("Failed to initialize PersistenceManager"),
    );

    // Start the background saver
    Arc::clone(&persistence_manager).run_background_saver(Duration::from_secs(60)); // Save every 60 seconds

    info!("Creating client...");
    // Client::new now expects Arc<PersistenceManager>
    let client = Arc::new(Client::new(persistence_manager.clone()).await);

    // Check for capture mode environment variable
    if let Ok(capture_path) = env::var("WHATSAPP_CAPTURE_BUNDLES") {
        info!("📦 Enabling capture mode: {}", capture_path);
        client.enable_capture_mode(&capture_path).await;
    }

    // If not logged in, start the QR pairing process
    // Access device state via persistence_manager
    let device_snapshot = persistence_manager.get_device_snapshot().await;
    if device_snapshot.id.is_none() {
        let client_clone = client.clone();
        // No need to clone persistence_manager for saving here, it's handled by background saver
        // or specific commands. The QR success event will trigger a command.
        tokio::spawn(async move {
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
                        // After successful pairing, the client internally updates its state (like JID, account)
                        // These updates should now go through PersistenceManager commands.
                        // Assuming Client::handle_qr_event or similar internal logic
                        // will use persistence_manager.process_command(...)
                        // For now, we'll rely on the client's internal logic to eventually call
                        // persistence_manager methods to update and mark dirty.
                        // The background saver will pick it up.
                        // If an immediate save is desired here, a specific command could trigger it,
                        // or PersistenceManager could expose a manual save_if_dirty method.
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

    // The event handlers now use typed subscriptions instead of a generic handler
    let client_for_handler = client.clone();
    let pm_for_handler = persistence_manager.clone();

    // Subscribe to LoggedOut events
    {
        let mut logged_out_rx = client.subscribe_to_logged_out();
        let _pm_clone = pm_for_handler.clone();
        tokio::spawn(async move {
            while let Ok(logout_event) = logged_out_rx.recv().await {
                info!("Received logout event: {:?}", logout_event.reason);
                // Potentially clear device ID, etc. using a command
                // _pm_clone.process_command(DeviceCommand::SetId(None)).await;
                // _pm_clone.process_command(DeviceCommand::SetLid(None)).await;
                // _pm_clone.process_command(DeviceCommand::SetAccount(None)).await;
            }
        });
    }

    // Subscribe to SelfPushNameUpdated events
    {
        let mut self_push_name_rx = client.subscribe_to_self_push_name_updated();
        let pm_clone = pm_for_handler.clone();
        tokio::spawn(async move {
            while let Ok(update) = self_push_name_rx.recv().await {
                info!(
                    "Received SelfPushNameUpdated event from '{}' to '{}'.",
                    update.old_name, update.new_name
                );
                // Send command to update push name
                pm_clone
                    .process_command(DeviceCommand::SetPushName(update.new_name.clone()))
                    .await;
                // The background saver will handle saving.
            }
        });
    }

    // Subscribe to Message events
    {
        let mut message_rx = client.subscribe_to_messages();
        let client_clone = client_for_handler.clone();
        tokio::spawn(async move {
            while let Ok(message_data) = message_rx.recv().await {
                let (msg, info_node) = &*message_data;
                // Renamed 'info' to 'info_node' to avoid conflict
                if let Some(text) = msg.text_content() {
                    if text == "send" {
                        log::info!("Received 'send' command, sending a response.");
                        let response_text = "Hello from whatsapp-rust!"; // Updated text
                        if let Err(e) = client_clone
                            .send_text_message(info_node.source.chat.clone(), response_text)
                            .await
                        {
                            log::error!("Failed to send response message: {e:?}");
                        }
                    }
                } else if let Some(ext_text) = msg.extended_text_message.as_ref() {
                    if let Some(text) = ext_text.text.as_ref() {
                        if text == "send" {
                            log::info!("Received 'send' command, sending a response.");
                            let response_text = "Hello from whatsapp-rust!"; // Updated text
                            if let Err(e) = client_clone
                                .send_text_message(info_node.source.chat.clone(), response_text)
                                .await
                            {
                                log::error!("Failed to send response message: {e:?}");
                            }
                        }
                    }
                }
            }
        });
    }

    // The main run loop
    client.run().await;

    info!("Application has shut down.");
    Ok(())
}
