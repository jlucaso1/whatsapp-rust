use crate::store::traits::*;
use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use std::io;
use std::path::{Path, PathBuf};
use tokio::fs;
use wacore::appstate::hash::HashState;
use wacore::signal;
use wacore::signal::state::sender_key_record::SenderKeyRecord;
use wacore::store::error::{Result, StoreError};
use waproto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

use super::SerializableDevice;

pub struct FileStore {
    base_path: PathBuf,
}

impl FileStore {
    pub async fn new(path: impl Into<PathBuf>) -> io::Result<Self> {
        let base_path = path.into();
        let store = Self { base_path };

        fs::create_dir_all(store.path_for("sessions")).await?;
        fs::create_dir_all(store.path_for("identities")).await?;
        fs::create_dir_all(store.path_for("prekeys")).await?;
        fs::create_dir_all(store.path_for("sender_keys")).await?;
        fs::create_dir_all(store.path_for("appstate/keys")).await?;
        fs::create_dir_all(store.path_for("appstate/versions")).await?;

        Ok(store)
    }

    fn path_for(&self, sub: &str) -> PathBuf {
        self.base_path.join(sub)
    }

    fn sanitize_filename(key: &str) -> String {
        key.replace(|c: char| !c.is_alphanumeric() && c != '.' && c != '-', "_")
    }

    async fn read_bincode<T: DeserializeOwned>(&self, path: &Path) -> Result<Option<T>> {
        match fs::read(path).await {
            Ok(data) => bincode::serde::decode_from_slice(&data, bincode::config::standard())
                .map(|(value, _)| Some(value))
                .map_err(|e| StoreError::Serialization(e.to_string())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    async fn write_bincode<T: Serialize>(&self, path: &Path, value: &T) -> Result<()> {
        let data = bincode::serde::encode_to_vec(value, bincode::config::standard())
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        fs::write(path, data).await.map_err(StoreError::Io)
    }

    fn device_path(&self) -> PathBuf {
        self.base_path.join("device.bin")
    }

    pub async fn save_device_data(&self, device_data: &SerializableDevice) -> Result<()> {
        self.write_bincode(&self.device_path(), device_data).await
    }

    pub async fn load_device_data(&self) -> Result<Option<SerializableDevice>> {
        log::info!(
            "FileStore: Attempting to load device data from {:?}",
            self.device_path()
        );
        

        self
            .read_bincode::<SerializableDevice>(&self.device_path())
            .await
    }
}

#[async_trait]
impl IdentityStore for FileStore {
    async fn put_identity(&self, address: &str, key: [u8; 32]) -> Result<()> {
        let path = self
            .path_for("identities")
            .join(Self::sanitize_filename(address));
        fs::write(path, key).await.map_err(StoreError::from)
    }

    async fn delete_identity(&self, address: &str) -> Result<()> {
        let path = self
            .path_for("identities")
            .join(Self::sanitize_filename(address));
        fs::remove_file(path)
            .await
            .or_else(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .map_err(StoreError::from)
    }

    async fn is_trusted_identity(&self, address: &str, key: &[u8; 32]) -> Result<bool> {
        let path = self
            .path_for("identities")
            .join(Self::sanitize_filename(address));
        match fs::read(path).await {
            Ok(data) => Ok(data == key),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StoreError::Io(e)),
        }
    }
}

#[async_trait]
impl SessionStore for FileStore {
    async fn get_session(&self, address: &str) -> Result<Option<Vec<u8>>> {
        let path = self
            .path_for("sessions")
            .join(Self::sanitize_filename(address));
        match fs::read(path).await {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    async fn put_session(&self, address: &str, session: &[u8]) -> Result<()> {
        let path = self
            .path_for("sessions")
            .join(Self::sanitize_filename(address));
        fs::write(path, session).await.map_err(StoreError::Io)
    }

    async fn delete_session(&self, address: &str) -> Result<()> {
        let path = self
            .path_for("sessions")
            .join(Self::sanitize_filename(address));
        fs::remove_file(path)
            .await
            .or_else(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .map_err(StoreError::Io)
    }

    async fn has_session(&self, address: &str) -> Result<bool> {
        let path = self
            .path_for("sessions")
            .join(Self::sanitize_filename(address));
        Ok(path.exists())
    }
}

type SignalStoreError = Box<dyn std::error::Error + Send + Sync>;

#[async_trait]
impl signal::store::PreKeyStore for FileStore {
    async fn load_prekey(
        &self,
        prekey_id: u32,
    ) -> std::result::Result<Option<PreKeyRecordStructure>, SignalStoreError> {
        let path = self.path_for("prekeys").join(prekey_id.to_string());
        Ok(self.read_bincode(&path).await?)
    }

    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecordStructure,
    ) -> std::result::Result<(), SignalStoreError> {
        let path = self.path_for("prekeys").join(prekey_id.to_string());
        Ok(self.write_bincode(&path, &record).await?)
    }

    async fn contains_prekey(&self, prekey_id: u32) -> std::result::Result<bool, SignalStoreError> {
        Ok(self
            .path_for("prekeys")
            .join(prekey_id.to_string())
            .exists())
    }

    async fn remove_prekey(&self, prekey_id: u32) -> std::result::Result<(), SignalStoreError> {
        let path = self.path_for("prekeys").join(prekey_id.to_string());
        fs::remove_file(path).await?;
        Ok(())
    }
}

#[async_trait]
impl signal::store::SenderKeyStore for FileStore {
    async fn store_sender_key(
        &self,
        sender_key_name: &signal::sender_key_name::SenderKeyName,
        record: SenderKeyRecord,
    ) -> std::result::Result<(), SignalStoreError> {
        let filename = Self::sanitize_filename(&format!(
            "{}_{}",
            sender_key_name.group_id(),
            sender_key_name.sender_id()
        ));
        let path = self.path_for("sender_keys").join(filename);
        Ok(self.write_bincode(&path, &record).await?)
    }

    async fn load_sender_key(
        &self,
        sender_key_name: &signal::sender_key_name::SenderKeyName,
    ) -> std::result::Result<SenderKeyRecord, SignalStoreError> {
        let filename = Self::sanitize_filename(&format!(
            "{}_{}",
            sender_key_name.group_id(),
            sender_key_name.sender_id()
        ));
        let path = self.path_for("sender_keys").join(filename);
        Ok(self.read_bincode(&path).await?.unwrap_or_default())
    }

    async fn delete_sender_key(
        &self,
        sender_key_name: &signal::sender_key_name::SenderKeyName,
    ) -> std::result::Result<(), SignalStoreError> {
        let filename = Self::sanitize_filename(&format!(
            "{}_{}",
            sender_key_name.group_id(),
            sender_key_name.sender_id()
        ));
        let path = self.path_for("sender_keys").join(filename);
        fs::remove_file(path).await.or_else(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e)
            }
        })?;
        Ok(())
    }
}

#[async_trait]
impl signal::store::SignedPreKeyStore for FileStore {
    async fn load_signed_prekey(
        &self,
        _signed_prekey_id: u32,
    ) -> std::result::Result<Option<SignedPreKeyRecordStructure>, SignalStoreError> {
        Ok(None)
    }

    async fn load_signed_prekeys(
        &self,
    ) -> std::result::Result<Vec<SignedPreKeyRecordStructure>, SignalStoreError> {
        Ok(Vec::new())
    }

    async fn store_signed_prekey(
        &self,
        _signed_prekey_id: u32,
        _record: SignedPreKeyRecordStructure,
    ) -> std::result::Result<(), SignalStoreError> {
        Ok(())
    }

    async fn contains_signed_prekey(
        &self,
        _signed_prekey_id: u32,
    ) -> std::result::Result<bool, SignalStoreError> {
        Ok(false)
    }

    async fn remove_signed_prekey(
        &self,
        _signed_prekey_id: u32,
    ) -> std::result::Result<(), SignalStoreError> {
        Ok(())
    }
}

#[async_trait]
impl AppStateKeyStore for FileStore {
    async fn get_app_state_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>> {
        let path = self.path_for("appstate/keys").join(hex::encode(key_id));
        self.read_bincode(&path).await
    }

    async fn set_app_state_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()> {
        let path = self.path_for("appstate/keys").join(hex::encode(key_id));
        self.write_bincode(&path, &key).await
    }
}

#[async_trait]
impl AppStateStore for FileStore {
    async fn get_app_state_version(&self, name: &str) -> Result<HashState> {
        let path = self
            .path_for("appstate/versions")
            .join(Self::sanitize_filename(name));
        Ok(self.read_bincode(&path).await?.unwrap_or_default())
    }

    async fn set_app_state_version(&self, name: &str, state: HashState) -> Result<()> {
        let path = self
            .path_for("appstate/versions")
            .join(Self::sanitize_filename(name));
        self.write_bincode(&path, &state).await
    }
}
