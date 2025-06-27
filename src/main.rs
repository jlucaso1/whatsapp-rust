// src/main.rs

use log::{error, info, warn};
use std::sync::Arc;
use whatsapp_rust::client::Client;
use whatsapp_rust::qrcode;
use whatsapp_rust::store;
use whatsapp_rust::store::memory::MemoryStore;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("Initializing a new in-memory store...");
    let store_backend = Arc::new(MemoryStore::new());

    info!("Initializing a new device with the store...");
    let store = store::Device::new(store_backend.clone(), store_backend.clone());

    info!("Creating client...");
    let client = Arc::new(tokio::sync::Mutex::new(Client::new(store)));

    // If not logged in, start the QR pairing process
    {
        let client_guard = client.lock().await;
        if client_guard.store.id.is_none() {
            let mut qr_rx = client_guard.get_qr_channel().await?;
            drop(client_guard);

            tokio::spawn(async move {
                info!("QR Channel listener started. Waiting for events...");
                while let Some(event) = qr_rx.recv().await {
                    match event {
                        qrcode::QrCodeEvent::Code { code, .. } => {
                            info!("----------------------------------------");
                            info!("Got new QR Code. Scan with your WhatsApp app.");
                            let qr_url = format!(
                                "https://api.qrserver.com/v1/create-qr-code/?size=400x400&data={}",
                                urlencoding::encode(&code)
                            );
                            info!("Scan this URL in a browser to see the QR code:\n{}", qr_url);
                            info!("----------------------------------------");
                        }
                        qrcode::QrCodeEvent::Success => {
                            info!("✅ Pairing successful! The client will now connect.");
                            break;
                        }
                        qrcode::QrCodeEvent::Error(e) => {
                            error!("❌ Pairing failed: {:?}", e);
                            return; // Stop the process on error
                        }
                        qrcode::QrCodeEvent::Timeout => {
                            warn!("⌛ Pairing timed out. Please restart the application.");
                            return;
                        }
                        _ => {
                            info!("[QR Event] Received other state: {:?}", event);
                        }
                    }
                }
                info!("QR Channel listener finished.");
            });
        }
    }

    // The main run loop
    client.lock().await.run().await;

    info!("Application has shut down.");
    Ok(())
}
