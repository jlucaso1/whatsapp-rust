use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Mutex;

use wacore::signal::state::session_record::SessionRecord;
use wacore::signal::state::sender_key_record::SenderKeyRecord;
use wacore::signal::identity::IdentityKeyPair;

#[derive(Debug, Clone)]
pub struct CaptureManager {
    base_path: Arc<Mutex<Option<PathBuf>>>,
    enabled: Arc<AtomicBool>,
}

#[derive(Serialize, Deserialize)]
pub struct DirectMessageBundle {
    pub message_bin: Vec<u8>,
    pub sender_identity_key_bin: Vec<u8>,
    pub recipient_session: SessionRecord,
    pub recipient_identity_keys: IdentityKeyPair,
    pub recipient_prekey: Option<Vec<u8>>, // Serialized PreKeyRecordStructure
    pub recipient_signed_prekey: Option<Vec<u8>>, // Serialized SignedPreKeyRecordStructure
    pub expected_plaintext: String,
}

#[derive(Serialize, Deserialize)]
pub struct GroupMessageBundle {
    pub message_bin: Vec<u8>,
    pub sender_identity_key_bin: Vec<u8>,
    pub recipient_session: SessionRecord,
    pub recipient_sender_key: SenderKeyRecord,
    pub expected_plaintext: String,
}

impl CaptureManager {
    pub fn new() -> Self {
        Self {
            base_path: Arc::new(Mutex::new(None)),
            enabled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn set_capture_path<P: AsRef<Path>>(&self, path: P) {
        let mut base_path = self.base_path.lock().await;
        *base_path = Some(path.as_ref().to_path_buf());
        self.enabled.store(true, Ordering::Relaxed);
    }

    pub fn disable_capture(&self) {
        self.enabled.store(false, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub async fn capture_direct_message_bundle(
        &self,
        message_id: &str,
        bundle: DirectMessageBundle,
    ) -> Result<(), anyhow::Error> {
        if !self.is_enabled() {
            return Ok(());
        }

        let base_path = self.base_path.lock().await;
        if let Some(ref path) = *base_path {
            let bundle_dir = path.join(message_id);
            fs::create_dir_all(&bundle_dir).await?;

            // Save binary files
            fs::write(bundle_dir.join("message.bin"), &bundle.message_bin).await?;
            fs::write(bundle_dir.join("sender_identity_key.bin"), &bundle.sender_identity_key_bin).await?;

            // Save JSON files
            let session_json = serde_json::to_string_pretty(&bundle.recipient_session)?;
            fs::write(bundle_dir.join("recipient_session.json"), session_json).await?;

            let identity_json = serde_json::to_string_pretty(&bundle.recipient_identity_keys)?;
            fs::write(bundle_dir.join("recipient_identity_keys.json"), identity_json).await?;

            if let Some(ref prekey) = bundle.recipient_prekey {
                fs::write(bundle_dir.join("recipient_prekey.json"), prekey).await?;
            }

            if let Some(ref signed_prekey) = bundle.recipient_signed_prekey {
                fs::write(bundle_dir.join("recipient_signed_prekey.json"), signed_prekey).await?;
            }

            fs::write(bundle_dir.join("expected_plaintext.txt"), &bundle.expected_plaintext).await?;

            log::info!("Captured direct message bundle: {}", message_id);
        }

        Ok(())
    }

    pub async fn capture_group_message_bundle(
        &self,
        message_id: &str,
        bundle: GroupMessageBundle,
    ) -> Result<(), anyhow::Error> {
        if !self.is_enabled() {
            return Ok(());
        }

        let base_path = self.base_path.lock().await;
        if let Some(ref path) = *base_path {
            let bundle_dir = path.join(message_id);
            fs::create_dir_all(&bundle_dir).await?;

            // Save binary files
            fs::write(bundle_dir.join("message.bin"), &bundle.message_bin).await?;
            fs::write(bundle_dir.join("sender_identity_key.bin"), &bundle.sender_identity_key_bin).await?;

            // Save JSON files
            let session_json = serde_json::to_string_pretty(&bundle.recipient_session)?;
            fs::write(bundle_dir.join("recipient_session.json"), session_json).await?;

            let sender_key_json = serde_json::to_string_pretty(&bundle.recipient_sender_key)?;
            fs::write(bundle_dir.join("recipient_sender_key.json"), sender_key_json).await?;

            fs::write(bundle_dir.join("expected_plaintext.txt"), &bundle.expected_plaintext).await?;

            log::info!("Captured group message bundle: {}", message_id);
        }

        Ok(())
    }
}

impl Default for CaptureManager {
    fn default() -> Self {
        Self::new()
    }
}