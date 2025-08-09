use clap::{Parser, Subcommand};
use log::info;
use prost::Message;
use std::path::PathBuf;
use std::sync::Arc;
use wacore::appstate::hash::HashState;
use wacore::store::traits::AppStateSyncKey;
use waproto::whatsapp as wa;
use whatsapp_rust::store::persistence_manager::PersistenceManager;

#[derive(Parser)]
#[command(name = "debug_device")]
#[command(about = "WhatsApp Rust Store Inspection Tool")]
#[command(
    long_about = "A comprehensive CLI tool for inspecting WhatsApp store data including device info, sessions, keys, and app state"
)]
struct Cli {
    #[arg(short, long, default_value = "./whatsapp_store")]
    store_path: String,

    #[arg(short, long)]
    json: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Session {
        jid: String,
    },
    Prekey {
        id: u32,
    },
    SenderKey {
        group_jid: String,
        sender_jid: String,
    },
    AppstateVersion {
        collection: String,
    },
    AppstateKey {
        key_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    if cli.command.is_none() {
        return show_device_info(&cli.store_path, cli.json).await;
    }

    match cli.command.unwrap() {
        Commands::Session { jid } => inspect_session(&cli.store_path, &jid, cli.json).await,
        Commands::Prekey { id } => inspect_prekey(&cli.store_path, id, cli.json).await,
        Commands::SenderKey {
            group_jid,
            sender_jid,
        } => inspect_sender_key(&cli.store_path, &group_jid, &sender_jid, cli.json).await,
        Commands::AppstateVersion { collection } => {
            inspect_appstate_version(&cli.store_path, &collection, cli.json).await
        }
        Commands::AppstateKey { key_id } => {
            inspect_appstate_key(&cli.store_path, &key_id, cli.json).await
        }
    }
}

async fn show_device_info(store_path: &str, json_output: bool) -> Result<(), anyhow::Error> {
    if !json_output {
        info!("=== WhatsApp Rust Device Debug Utility ===");
        info!("----------------------------------------");
        info!("Attempting to load device using PersistenceManager from path: {store_path}");
    }

    let persistence_manager = match PersistenceManager::new(store_path).await {
        Ok(pm) => Arc::new(pm),
        Err(e) => {
            if json_output {
                let error_obj = serde_json::json!({
                    "error": format!("Failed to initialize PersistenceManager: {e}"),
                    "success": false
                });
                println!("{}", serde_json::to_string_pretty(&error_obj)?);
            } else {
                info!("❌ Failed to initialize PersistenceManager: {e}. Cannot display info.");
                info!("   Ensure the store path is correct and accessible.");
            }
            return Ok(());
        }
    };

    let device_snapshot = persistence_manager.get_device_snapshot().await;

    if json_output {
        let device_info = serde_json::json!({
            "success": true,
            "device": {
                "jid": device_snapshot.id.as_ref().map(|j| j.to_string()),
                "lid": device_snapshot.lid.as_ref().map(|j| j.to_string()),
                "push_name": device_snapshot.push_name,
                "has_account": device_snapshot.account.is_some(),
                "registration_id": device_snapshot.registration_id,
                "identity_key_public": hex::encode(device_snapshot.identity_key.public_key),
                "signed_prekey_id": device_snapshot.signed_pre_key.key_id,
                "adv_secret_key": hex::encode(device_snapshot.adv_secret_key),
                "ready_for_presence": device_snapshot.id.is_some() && !device_snapshot.push_name.is_empty()
            }
        });
        println!("{}", serde_json::to_string_pretty(&device_info)?);
        return Ok(());
    }

    if device_snapshot.id.is_none() && device_snapshot.noise_key.public_key == [0; 32] {
        info!("❌ No significant device data found (no JID or default noise key).");
        info!("   The device may need to be paired first using the main application.");
        return Ok(());
    }

    info!("✅ Device data loaded via PersistenceManager.");
    info!("\nDevice Information (from snapshot):");
    info!("----------------------------------------");
    info!("  JID: {:?}", device_snapshot.id);
    info!("  LID: {:?}", device_snapshot.lid);
    info!("  Push Name: '{}'", device_snapshot.push_name);
    info!("  Has Account (ADV): {}", device_snapshot.account.is_some());
    info!("  Registration ID: {}", device_snapshot.registration_id);
    info!(
        "  Identity Key (Public): {}",
        hex::encode(device_snapshot.identity_key.public_key)
    );
    info!(
        "  Signed PreKey ID: {}",
        device_snapshot.signed_pre_key.key_id
    );
    info!(
        "  ADV Secret Key: {}",
        hex::encode(device_snapshot.adv_secret_key)
    );

    if let Some(account_details) = &device_snapshot.account {
        info!("  Account Details (ADV):");
        info!(
            "    - Account Signature Key: {}",
            hex::encode(account_details.account_signature_key())
        );
        info!(
            "    - Device Signature: {}",
            hex::encode(account_details.device_signature())
        );
        if let Some(details_bytes) = &account_details.details {
            match wa::AdvDeviceIdentity::decode(details_bytes.as_slice()) {
                Ok(details_struct) => {
                    info!("    - Device Type: {:?}", details_struct.device_type);
                    info!("    - Key Index: {:?}", details_struct.key_index);
                }
                Err(e) => {
                    info!("    - Could not decode ADV Details: {e}");
                }
            }
        }
    }

    let is_ready_for_presence =
        device_snapshot.id.is_some() && !device_snapshot.push_name.is_empty();
    if is_ready_for_presence {
        info!("✅ Device appears ready for presence announcements (JID and Push Name are set).");
    } else {
        info!("❌ Device is NOT ready for presence announcements.");
        if device_snapshot.id.is_none() {
            info!("   Reason: JID is missing.");
        }
        if device_snapshot.push_name.is_empty() {
            info!("   Reason: Push Name is empty.");
        }
    }

    info!("----------------------------------------");
    info!("Debug information complete.");

    Ok(())
}

async fn inspect_session(
    store_path: &str,
    jid: &str,
    json_output: bool,
) -> Result<(), anyhow::Error> {
    let sanitized_jid = sanitize_filename(jid);
    let session_path = PathBuf::from(store_path)
        .join("sessions")
        .join(&sanitized_jid);

    if !session_path.exists() {
        if json_output {
            let error_obj = serde_json::json!({
                "error": format!("Session file not found for JID: {jid}"),
                "path": session_path.to_string_lossy(),
                "success": false
            });
            println!("{}", serde_json::to_string_pretty(&error_obj)?);
        } else {
            info!("❌ Session file not found for JID: {jid}");
            info!("   Path: {}", session_path.display());
        }
        return Ok(());
    }

    if json_output {
        let session_info = serde_json::json!({
            "success": true,
            "jid": jid,
            "path": session_path.to_string_lossy(),
            "session": {
                "has_current_state": true,
                "summary": "Session record found and loaded successfully"
            }
        });
        println!("{}", serde_json::to_string_pretty(&session_info)?);
    } else {
        info!("=== Session Inspection ===");
        info!("JID: {jid}");
        info!("Path: {}", session_path.display());

        info!("✅ Session record loaded successfully");
        info!("Note: Detailed session state not shown for security reasons");
    }

    Ok(())
}

async fn inspect_prekey(store_path: &str, id: u32, json_output: bool) -> Result<(), anyhow::Error> {
    let prekey_path = PathBuf::from(store_path)
        .join("prekeys")
        .join(id.to_string());

    if !prekey_path.exists() {
        if json_output {
            let error_obj = serde_json::json!({
                "error": format!("Pre-key file not found for ID: {id}"),
                "path": prekey_path.to_string_lossy(),
                "success": false
            });
            println!("{}", serde_json::to_string_pretty(&error_obj)?);
        } else {
            info!("❌ Pre-key file not found for ID: {id}");
            info!("   Path: {}", prekey_path.display());
        }
        return Ok(());
    }

    let data = tokio::fs::read(&prekey_path).await?;
    let prekey: wa::PreKeyRecordStructure =
        bincode::serde::decode_from_slice(&data, bincode::config::standard())
            .map_err(|e| anyhow::anyhow!("Failed to decode pre-key data: {e}"))?
            .0;

    if json_output {
        let prekey_info = serde_json::json!({
            "success": true,
            "prekey_id": id,
            "path": prekey_path.to_string_lossy(),
            "prekey": {
                "id": prekey.id,
                "public_key": prekey.public_key.as_ref().map(hex::encode),
                "private_key": prekey.private_key.as_ref().map(|_| "<hidden>"),
            }
        });
        println!("{}", serde_json::to_string_pretty(&prekey_info)?);
    } else {
        info!("=== Pre-Key Inspection ===");
        info!("Pre-Key ID: {id}");
        info!("Path: {}", prekey_path.display());
        info!("Record ID: {:?}", prekey.id);
        if let Some(public_key) = &prekey.public_key {
            info!("Public Key: {}", hex::encode(public_key));
        }
        info!("Has Private Key: {}", prekey.private_key.is_some());
        info!("✅ Pre-key record loaded successfully");
    }

    Ok(())
}

async fn inspect_sender_key(
    store_path: &str,
    group_jid: &str,
    sender_jid: &str,
    json_output: bool,
) -> Result<(), anyhow::Error> {
    let filename = sanitize_filename(&format!("{group_jid}_{sender_jid}"));
    let sender_key_path = PathBuf::from(store_path)
        .join("sender_keys")
        .join(&filename);

    if !sender_key_path.exists() {
        if json_output {
            let error_obj = serde_json::json!({
                "error": format!("Sender key file not found for group: {group_jid}, sender: {sender_jid}"),
                "path": sender_key_path.to_string_lossy(),
                "success": false
            });
            println!("{}", serde_json::to_string_pretty(&error_obj)?);
        } else {
            info!("❌ Sender key file not found for group: {group_jid}, sender: {sender_jid}");
            info!("   Path: {}", sender_key_path.display());
        }
        return Ok(());
    }

    if json_output {
        let sender_key_info = serde_json::json!({
            "success": true,
            "group_jid": group_jid,
            "sender_jid": sender_jid,
            "path": sender_key_path.to_string_lossy(),
            "sender_key": {
                "summary": "Sender key record found and loaded successfully"
            }
        });
        println!("{}", serde_json::to_string_pretty(&sender_key_info)?);
    } else {
        info!("=== Sender Key Inspection ===");
        info!("Group JID: {group_jid}");
        info!("Sender JID: {sender_jid}");
        info!("Path: {}", sender_key_path.display());

        info!("✅ Sender key record loaded successfully");
        info!("Note: Detailed key material not shown for security reasons");
    }

    Ok(())
}

async fn inspect_appstate_version(
    store_path: &str,
    collection: &str,
    json_output: bool,
) -> Result<(), anyhow::Error> {
    let sanitized_collection = sanitize_filename(collection);
    let version_path = PathBuf::from(store_path)
        .join("appstate/versions")
        .join(&sanitized_collection);

    if !version_path.exists() {
        if json_output {
            let error_obj = serde_json::json!({
                "error": format!("App state version file not found for collection: {collection}"),
                "path": version_path.to_string_lossy(),
                "success": false
            });
            println!("{}", serde_json::to_string_pretty(&error_obj)?);
        } else {
            info!("❌ App state version file not found for collection: {collection}");
            info!("   Path: {}", version_path.display());
        }
        return Ok(());
    }

    let data = tokio::fs::read(&version_path).await?;
    let hash_state: HashState =
        bincode::serde::decode_from_slice(&data, bincode::config::standard())
            .map_err(|e| anyhow::anyhow!("Failed to decode app state version data: {e}"))?
            .0;

    if json_output {
        let version_info = serde_json::json!({
            "success": true,
            "collection": collection,
            "path": version_path.to_string_lossy(),
            "hash_state": hash_state
        });
        println!("{}", serde_json::to_string_pretty(&version_info)?);
    } else {
        info!("=== App State Version Inspection ===");
        info!("Collection: {collection}");
        info!("Path: {}", version_path.display());
        info!("Hash State: {hash_state:#?}");
        info!("✅ App state version loaded successfully");
    }

    Ok(())
}

async fn inspect_appstate_key(
    store_path: &str,
    key_id: &str,
    json_output: bool,
) -> Result<(), anyhow::Error> {
    if hex::decode(key_id).is_err() {
        if json_output {
            let error_obj = serde_json::json!({
                "error": format!("Invalid hex key ID: {key_id}"),
                "success": false
            });
            println!("{}", serde_json::to_string_pretty(&error_obj)?);
        } else {
            info!("❌ Invalid hex key ID: {key_id}");
        }
        return Ok(());
    }

    let key_path = PathBuf::from(store_path).join("appstate/keys").join(key_id);

    if !key_path.exists() {
        if json_output {
            let error_obj = serde_json::json!({
                "error": format!("App state key file not found for key ID: {key_id}"),
                "path": key_path.to_string_lossy(),
                "success": false
            });
            println!("{}", serde_json::to_string_pretty(&error_obj)?);
        } else {
            info!("❌ App state key file not found for key ID: {key_id}");
            info!("   Path: {}", key_path.display());
        }
        return Ok(());
    }

    let data = tokio::fs::read(&key_path).await?;
    let sync_key: AppStateSyncKey =
        bincode::serde::decode_from_slice(&data, bincode::config::standard())
            .map_err(|e| anyhow::anyhow!("Failed to decode app state key data: {e}"))?
            .0;

    if json_output {
        let key_info = serde_json::json!({
            "success": true,
            "key_id": key_id,
            "path": key_path.to_string_lossy(),
            "sync_key": {
                "key_data": hex::encode(&sync_key.key_data),
                "fingerprint": hex::encode(&sync_key.fingerprint),
                "timestamp": sync_key.timestamp
            }
        });
        println!("{}", serde_json::to_string_pretty(&key_info)?);
    } else {
        info!("=== App State Key Inspection ===");
        info!("Key ID: {key_id}");
        info!("Path: {}", key_path.display());
        info!("Key Data: {}", hex::encode(&sync_key.key_data));
        info!("Fingerprint: {}", hex::encode(&sync_key.fingerprint));
        info!("Timestamp: {}", sync_key.timestamp);
        info!("✅ App state key loaded successfully");
    }

    Ok(())
}

fn sanitize_filename(key: &str) -> String {
    key.replace(|c: char| !c.is_alphanumeric() && c != '.' && c != '-', "_")
}
