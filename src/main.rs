use log::{error, info, warn};
use std::sync::Arc;
use whatsapp_rust::client::Client;
use whatsapp_rust::store;
use whatsapp_rust::store::filestore::FileStore;
use whatsapp_rust::types::events::Event;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("Initializing the filesystem store...");
    let store_backend = Arc::new(FileStore::new("./whatsapp_store").await?);

    // Try to load an existing device session
    let device = if let Some(loaded_data) = store_backend.load_device_data().await? {
        info!("Loaded existing device from store.");
        let mut dev = store::Device::new(store_backend.clone());
        dev.load_from_serializable(loaded_data);
        dev
    } else {
        info!("No existing device found, creating a new one.");

        // The device will be saved after a successful pairing
        store::Device::new(store_backend.clone())
    };

    info!("Creating client...");
    let client = Arc::new(Client::new(device));

    // If not logged in, start the QR pairing process
    if client.store.read().await.id.is_none() {
        let client_clone = client.clone();
        let store_backend_clone = store_backend.clone();
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
                            "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data={}",
                            urlencoding::encode(&code)
                        );
                        info!("Scan this URL in a browser to see the QR code:\n  {qr_url}");
                        info!("----------------------------------------");
                    }
                    QrCodeEvent::Success => {
                        info!("✅ Pairing successful! The client will now connect.");
                        // Save the newly paired device to disk
                        let store_guard = client_clone.store.read().await;
                        if let Err(e) = store_backend_clone
                            .save_device_data(&store_guard.to_serializable())
                            .await
                        {
                            error!("Failed to save new device state after pairing: {e}");
                        }
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

    let store_backend_for_handler = store_backend.clone();
    let client_for_handler = client.clone();
    client
        .add_event_handler(Box::new(move |event: Arc<Event>| {
            let store_backend_clone = store_backend_for_handler.clone();
            let client_clone = client_for_handler.clone();
            tokio::spawn(async move {
                match &*event {
                    Event::LoggedOut(logout_event) => {
                        info!("Received logout event: {:?}", logout_event.reason);
                    }
                    Event::SelfPushNameUpdated(update) => {
                        info!(
                            "Received SelfPushNameUpdated event from '{}' to '{}', saving state.",
                            update.old_name, update.new_name
                        );
                        let store_guard = client_clone.store.read().await;
                        if let Err(e) = store_backend_clone
                            .save_device_data(&store_guard.to_serializable())
                            .await
                        {
                            error!("Failed to save device state after push name update: {e}");
                        }
                    }
                    _ => {}
                }
            });
        }))
        .await;

    // The main run loop
    client.run().await;

    info!("Application has shut down.");
    Ok(())
}
